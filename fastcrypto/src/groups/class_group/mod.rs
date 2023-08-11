// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.
//!
//! Serialization is compatible with the chiavdf library (https://github.com/Chia-Network/chiavdf).

use crate::error::FastCryptoError::{InputTooLong, InvalidInput};
use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::{ParameterizedGroupElement, UnknownOrderGroupElement};
use curv::arithmetic::{BasicOps, BitManipulation, Integer, Modulo, One, Roots, Zero};
use curv::BigInt;
use std::cmp::Ordering;
use std::ops::{Add, Neg};

mod compressed;

/// The maximal size in bits we allow a discriminant to have.
pub const MAX_DISCRIMINANT_SIZE_IN_BITS: usize = 1024;

/// The size of a compressed quadratic form in bytes. We force all forms to have the same size,
/// namely 100 bytes.
pub const QUADRATIC_FORM_SIZE_IN_BYTES: usize = (MAX_DISCRIMINANT_SIZE_IN_BITS + 31) / 32 * 3 + 4;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
///
/// The `partial_gcd_limit` variable is equal to `|discriminant|^{1/4}` and is used to speed up
/// the composition algorithm.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QuadraticForm {
    a: BigInt,
    b: BigInt,
    c: BigInt,
    partial_gcd_limit: BigInt,
}

impl Neg for QuadraticForm {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            a: self.a,
            b: self.b.neg(),
            c: self.c,
            partial_gcd_limit: self.partial_gcd_limit,
        }
    }
}

impl Add<&QuadraticForm> for QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: &QuadraticForm) -> Self::Output {
        // Slightly optimised version of Algorithm 1 from Jacobson, Jr, Michael & Poorten, Alfred
        // (2002). "Computational aspects of NUCOMP", Lecture Notes in Computer Science.
        // (https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP)
        // The paragraph numbers and variable names follow the paper.

        let u1 = &self.a;
        let v1 = &self.b;
        let w1 = &self.c;
        let u2 = &rhs.a;
        let v2 = &rhs.b;
        let w2 = &rhs.c;

        // 1.
        if w1 < w2 {
            return rhs.clone() + &self;
        }
        let s = (v1 + v2) >> 1;
        let m = v2 - &s;

        // 2.
        let xgcd = BigInt::extended_gcd(u2, u1);
        let f = xgcd.gcd;
        let b = xgcd.x;
        let c = xgcd.y;

        let g: BigInt;
        let capital_bx: BigInt;
        let capital_by: BigInt;
        let capital_cy: BigInt;
        let capital_dy: BigInt;

        if s.is_multiple_of(&f) {
            g = f;
            capital_bx = &m * &b;
            capital_by = u1 / &g;
            capital_cy = u2 / &g;
            capital_dy = &s / &g;
        } else {
            // 3.
            let xgcd = BigInt::extended_gcd(&f, &s);
            g = xgcd.gcd;
            let y = xgcd.y;
            let h = &f / &g;
            capital_by = u1 / &g;
            capital_cy = u2 / &g;
            capital_dy = &s / &g;

            // 4.
            let l = (&y * (&b * (w1.modulus(&h)) + &c * (w2.modulus(&h)))).modulus(&h);
            capital_bx = &b * (&m / &h) + &l * (&capital_by / &h);
        }

        // 3. (partial xgcd)
        let PartialEuclideanAlgorithmOutput {
            a: bx,
            b: by,
            x,
            y,
            did_iterate: z,
        } = partial_euclidean_algorithm(
            capital_bx.modulus(&capital_by),
            capital_by.clone(),
            &self.partial_gcd_limit,
        );

        let (ax, ay) = if g.is_one() {
            (x.clone(), y.clone())
        } else {
            (&g * &x, &g * &y)
        };

        let u3: BigInt;
        let w3: BigInt;
        let v3: BigInt;

        if !z {
            let q = &capital_cy * &bx;
            let cx = (&q - &m) / &capital_by;
            let dx = (&bx * &capital_dy - w2) / &capital_by;
            u3 = &by * &capital_cy;
            w3 = &bx * &cx - &g * &dx;
            v3 = v2 - (&q << 1);
        } else {
            let cx = (&capital_cy * &bx - &m * &x) / &capital_by;
            let q1 = &by * &cx;
            let q2 = &q1 + &m;
            let dx = (&capital_dy * &bx - w2 * &x) / &capital_by;
            let q3 = &y * &dx;
            let q4 = &q3 + &capital_dy;
            let dy = &q4 / &x;
            let cy = if !b.is_zero() {
                &q2 / &bx
            } else {
                (&cx * &dy - w1) / &dx
            };
            u3 = &by * &cy - &ay * &dy;
            w3 = &bx * &cx - &ax * &dx;
            v3 = &g * (&q3 + &q4) - &q1 - &q2;
        }

        Self {
            a: u3,
            b: v3,
            c: w3,
            partial_gcd_limit: self.partial_gcd_limit,
        }
        .reduce()
    }
}

impl QuadraticForm {
    /// Create a new quadratic form given only the a and b coefficients and the discriminant.
    pub fn from_a_b_discriminant(a: BigInt, b: BigInt, discriminant: &Discriminant) -> Self {
        let c = ((&b * &b) - &discriminant.0) / (BigInt::from(4) * &a);
        Self {
            a,
            b,
            c,
            // This limit is used for the partial_xgcd algorithm in the add method.
            partial_gcd_limit: discriminant.0.abs().sqrt().sqrt(),
        }
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class
    /// group with a given discriminant. We use the element `(2, 1, x)` where `x` is determined from
    /// the discriminant.
    pub fn generator(discriminant: &Discriminant) -> Self {
        Self::from_a_b_discriminant(BigInt::from(2), BigInt::one(), discriminant)
    }

    /// Compute the discriminant `b^2 - 4ac` for this quadratic form.
    pub fn discriminant(&self) -> Discriminant {
        Discriminant::try_from(self.b.pow(2) - (BigInt::from(4) * &self.a * &self.c))
            .expect("The discriminant is checked in the constructors")
    }

    /// Return true if this form is in normal form: -a < b <= a.
    fn is_normal(&self) -> bool {
        self.b <= self.a && self.b > -(&self.a)
    }

    /// Return a normalized form equivalent to this quadratic form.
    fn normalize(self) -> Self {
        if self.is_normal() {
            return self;
        }
        let r = (&self.a - &self.b).div_floor(&(&self.a * 2));
        let ra = &r * &self.a;
        let c = self.c + (&ra + &self.b) * &r;
        let b = self.b + &ra * 2;
        Self {
            a: self.a,
            b,
            c,
            partial_gcd_limit: self.partial_gcd_limit,
        }
    }

    /// Return true if this form is reduced: A form is reduced if it is normal (see [`is_normal`])
    /// and  a <= c and if a == c then b >= 0.
    fn is_reduced(&self) -> bool {
        if !self.is_normal() {
            return false;
        }

        match self.a.cmp(&self.c) {
            Ordering::Less => true,
            Ordering::Equal => self.b >= BigInt::zero(),
            Ordering::Greater => false,
        }
    }

    /// Return a reduced form (see [is_reduced]) equivalent to this quadratic form.
    fn reduce(self) -> Self {
        let mut form = self.normalize();
        while !form.is_reduced() {
            let s = (&form.b + &form.c).div_floor(&(&form.c * 2));
            let old_a = form.a.clone();
            let old_b = form.b.clone();
            form.a = form.c.clone();
            form.b = -&form.b + &s * &form.c * 2;
            form.c = (&form.c * &s - &old_b) * &s + &old_a;
        }
        form
    }
}

impl ParameterizedGroupElement for QuadraticForm {
    /// Type of the discriminant.
    type ParameterType = Discriminant;

    type ScalarType = BigInt;

    fn zero(discriminant: &Self::ParameterType) -> Self {
        Self::from_a_b_discriminant(BigInt::one(), BigInt::one(), discriminant)
    }

    fn mul(&self, scale: &BigInt) -> Self {
        if scale.is_zero() {
            return Self::zero(&self.discriminant());
        } else if scale.is_even() {
            return self.double().mul(&(scale >> 1));
        }
        (self.double()).mul(&((scale - BigInt::one()) >> 1)) + self
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn has_group_parameter(&self, parameter: &Self::ParameterType) -> bool {
        self.discriminant() == *parameter
    }
}

impl UnknownOrderGroupElement for QuadraticForm {}

/// A discriminant for an imaginary class group. The discriminant is a negative integer which is
/// equal to 1 mod 4.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Discriminant(BigInt);

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        if value >= BigInt::zero() || value.modulus(&BigInt::from(4)) != BigInt::from(1) {
            return Err(InvalidInput);
        }

        if value.bit_length() > MAX_DISCRIMINANT_SIZE_IN_BITS {
            return Err(InputTooLong(value.bit_length()));
        }

        Ok(Self(value))
    }
}

/// The output of [`partial_euclidean_algorithm`].
struct PartialEuclideanAlgorithmOutput {
    a: BigInt,
    b: BigInt,
    x: BigInt,
    y: BigInt,
    did_iterate: bool,
}

/// Compute the extended Euclidean algorithm for two integers `a` and `b` but quit early if the
/// Bezout parameters are smaller than `limit`.
fn partial_euclidean_algorithm(
    a: BigInt,
    b: BigInt,
    limit: &BigInt,
) -> PartialEuclideanAlgorithmOutput {
    let mut x = BigInt::one();
    let mut y = BigInt::zero();
    let mut z = 0u32;

    let mut bx = a;
    let mut by = b;

    while &by.abs() > limit && !bx.is_zero() {
        let (q, t) = by.div_rem(&bx);
        by = bx;
        bx = t;
        let tmp = &y - &q * &x;
        y = x;
        x = tmp;
        z += 1;
    }

    if z.is_odd() {
        by = -by;
        y = -y;
    }

    PartialEuclideanAlgorithmOutput {
        a: bx,
        b: by,
        x,
        y,
        did_iterate: z > 0,
    }
}

#[test]
fn test_multiplication() {
    let discriminant = Discriminant::try_from(BigInt::from(-7)).unwrap();
    let generator = QuadraticForm::generator(&discriminant);
    let mut current = QuadraticForm::zero(&discriminant);
    for i in 0..100 {
        assert_eq!(current, generator.mul(&BigInt::from(i)));
        current = current + &generator;
    }
}

#[test]
fn test_normalization_and_reduction() {
    let discriminant = Discriminant::try_from(BigInt::from(-19)).unwrap();
    let mut quadratic_form =
        QuadraticForm::from_a_b_discriminant(BigInt::from(11), BigInt::from(49), &discriminant);
    assert_eq!(quadratic_form.c, BigInt::from(55));

    quadratic_form = quadratic_form.normalize();

    // Test vector from https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf
    assert_eq!(quadratic_form.a, BigInt::from(11));
    assert_eq!(quadratic_form.b, BigInt::from(5));
    assert_eq!(quadratic_form.c, BigInt::from(1));

    quadratic_form = quadratic_form.reduce();

    // Test vector from https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf
    assert_eq!(quadratic_form.a, BigInt::from(1));
    assert_eq!(quadratic_form.b, BigInt::from(1));
    assert_eq!(quadratic_form.c, BigInt::from(5));
}

#[test]
fn test_composition() {
    // Test vector computed with PARI/GP

    let discriminant = Discriminant::try_from(BigInt::from(-47)).unwrap();
    let g = QuadraticForm::generator(&discriminant);
    let b = QuadraticForm::from_a_b_discriminant(BigInt::from(3), BigInt::from(-1), &discriminant);
    let a1 = g.clone();

    let a2 = a1 + &g;
    assert_eq!(a2, b);

    let a3 = a2 + &g;
    assert_eq!(a3, b.neg());

    let a4 = a3 + &g;
    assert_eq!(a4, g.clone().neg());

    let a5 = a4 + &g;
    assert_eq!(a5, QuadraticForm::zero(&discriminant));

    let a6 = a5 + &g;
    assert_eq!(a6, g);
}
