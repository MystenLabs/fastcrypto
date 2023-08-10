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
use std::ops::Add;

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

impl Add<QuadraticForm> for QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: QuadraticForm) -> Self::Output {
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
            return rhs + self;
        }
        let s = (v1 + v2) >> 1;
        let m = v2 - &s;

        // 2.
        let xgcd = BigInt::extended_gcd(&u2, &u1);
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
        } = partial_euclidan_algorithm(
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

        let mut out = Self {
            a: u3,
            b: v3,
            c: w3,
            partial_gcd_limit: self.partial_gcd_limit,
        };
        out.reduce();
        out
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
            // This limit is used for the partial_xgcd algorithm
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

    fn is_normal(&self) -> bool {
        self.b <= self.a && self.b > -(&self.a)
    }

    fn normalize(&mut self) {
        if self.is_normal() {
            return;
        }
        let r = (&self.a - &self.b).div_floor(&(&self.a * 2));
        let ra = &r * &self.a;
        self.c += (&ra + &self.b) * &r;
        self.b += &ra * 2;
    }

    pub fn is_reduced(&self) -> bool {
        self.is_normal() && self.a <= self.c && !(self.a == self.c && self.b < BigInt::zero())
    }

    fn reduce(&mut self) {
        self.normalize();
        while !self.is_reduced() {
            let s = (&self.b + &self.c).div_floor(&(&self.c * 2));
            let old_a = self.a.clone();
            let old_b = self.b.clone();
            self.a = self.c.clone();
            self.b = -&self.b + &s * &self.c * 2;
            self.c = (&self.c * &s - &old_b) * &s + &old_a;
        }
    }
}

impl ParameterizedGroupElement for QuadraticForm {
    /// Type of the discriminant.
    type ParameterType = Discriminant;

    type ScalarType = BigInt;

    fn zero(discriminant: &Self::ParameterType) -> Self {
        Self::from_a_b_discriminant(BigInt::one(), BigInt::one(), discriminant)
    }

    // TODO: Coefficients explode
    // fn double(&self) -> Self {
    //     // Slightly optimised version of Algorithm 2 from Jacobson, Jr, Michael & Poorten, Alfred
    //     // (2002). "Computational aspects of NUCOMP", Lecture Notes in Computer Science.
    //     // (https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP)
    //     // The paragraph numbers and variable names follow the paper.
    //
    //     let Self { a: u, b: v, c: w, partial_gcd_limit: _ } = &self;
    //
    //     // 1.
    //     let xgcd = BigInt::extended_gcd(&u, &v);
    //     let g = xgcd.gcd;
    //     //let y = xgcd.y;
    //     let (capital_by, capital_dy) = (u / &g, v / &g);
    //
    //     // 2.
    //     let capital_bx = (w * &xgcd.y).modulus(&capital_by);
    //
    //     // 3. (partial xgcd)
    //     let PartialEuclideanAlgorithmOutput {
    //         a: bx,
    //         b: by,
    //         mut x,
    //         mut y,
    //         did_iterate: z,
    //     } = partial_euclidan_algorithm(capital_bx, capital_by.clone(), &self.partial_gcd_limit);
    //
    //     // 4. / 5.
    //     let mut u3 = by.pow(2);
    //     let mut w3 = bx.pow(2);
    //     let mut v3 = -(&bx * &by).shl(1);
    //
    //     if !z {
    //         // 4.
    //         let mut dx = (&bx * &capital_dy - w) / &capital_by;
    //         v3 += v;
    //         if !g.is_one() {
    //             dx *= &g;
    //         }
    //         w3 -= &dx;
    //     } else {
    //         // 5.
    //         let dx = (&bx * &capital_dy - w * &x) / &capital_by;
    //         let q1 = &dx * &y;
    //         let dy = (&q1 + &capital_dy) / &x;
    //         v3 += &g * (&dy + &q1);
    //
    //         if !g.is_one() {
    //             x *= &g;
    //             y *= &g;
    //         }
    //         u3 -= &y * &dy;
    //         w3 -= &x * &dx;
    //     }
    //
    //     let mut out = Self {
    //             a: u3,
    //             b: v3,
    //             c: w3,
    //         partial_gcd_limit: self.partial_gcd_limit.clone(),
    //     };
    //     out.reduce();
    //     out
    // }

    fn mul(&self, scale: &BigInt) -> Self {
        // TODO: Use double method once implemented
        if scale.is_zero() {
            return Self::zero(&self.discriminant());
        } else if scale.is_even() {
            return (self.clone() + self.clone()).mul(&(scale >> 1));
        }
        return self.clone() + (self.clone() + self.clone()).mul(&((scale - BigInt::one()) >> 1));
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn get_group_parameter(&self) -> Self::ParameterType {
        self.discriminant()
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

struct PartialEuclideanAlgorithmOutput {
    a: BigInt,
    b: BigInt,
    x: BigInt,
    y: BigInt,
    did_iterate: bool,
}

fn partial_euclidan_algorithm(
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
