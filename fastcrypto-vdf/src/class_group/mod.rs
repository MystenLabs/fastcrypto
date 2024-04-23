// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.

use crate::math::extended_gcd::{extended_euclidean_algorithm, EuclideanAlgorithmOutput};
use crate::{ParameterizedGroupElement, UnknownOrderGroupElement};
use core::cell::OnceCell;
use discriminant::Discriminant;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Doubling;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::mem::swap;
use std::ops::{Add, Mul, Neg};

#[cfg(test)]
mod tests;

/// This module implements a hash function for imaginary class groups whichtakes an arbitrary binary input and returns
/// an element in the class group. The output of the hash function is uniformly random on a large subset of the class
/// group but not the entire class group.
pub(crate) mod hash;

/// Two quadratic forms may represent the same element in the class group, but each equivalence class contains exactly
/// one reduced form. This module contains methods to reduce quadratic forms, which besides uniqness also ensures that
/// the coefficients does not become too large.
pub(crate) mod reduction;

/// Discriminants of quadratic forms are negative primes which is 1 mod 8. This module contains a type to represent
/// discriminants and methods to create them.
pub mod discriminant;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
#[derive(Eq, Debug, Clone, Serialize, Deserialize)]
pub struct QuadraticForm {
    pub a: BigInt,
    pub b: BigInt,
    pub c: BigInt,
    #[serde(skip)]
    partial_gcd_limit: OnceCell<BigInt>,
}

impl QuadraticForm {
    /// Create a new quadratic form given only the a and b coefficients and the discriminant.
    pub fn from_a_b_and_discriminant(
        a: BigInt,
        b: BigInt,
        discriminant: &Discriminant,
    ) -> FastCryptoResult<Self> {
        if !a.is_positive() {
            return Err(InvalidInput);
        }

        let numerator = b.pow(2) - discriminant.as_bigint();
        let denominator = &a << 2;
        if !numerator.is_multiple_of(&denominator) {
            return Err(InvalidInput);
        }

        let c = numerator / denominator;
        Ok(Self {
            a,
            b,
            c,
            partial_gcd_limit: OnceCell::new(),
        })
    }

    /// The GCD computation in composition may when coefficients are below this limit which is set
    /// to `|discriminant|^{1/4}`.
    fn partial_gcd_limit(&self) -> &BigInt {
        self.partial_gcd_limit
            .get_or_init(|| self.discriminant().as_bigint().abs().nth_root(4))
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class group with a given
    /// discriminant which is 1 mod 8. We use the element `(2, 1, c)` where `c` is determined from the discriminant.
    pub fn generator(discriminant: &Discriminant) -> Self {
        Self::from_a_b_and_discriminant(BigInt::from(2), BigInt::one(), discriminant)
            .expect("Always succeeds when the discriminant is 1 mod 8")
    }

    /// Compute the discriminant `b^2 - 4ac` for this quadratic form.
    pub fn discriminant(&self) -> Discriminant {
        Discriminant::try_from(self.b.pow(2) - ((&self.a * &self.c) << 2))
            .expect("The discriminant is checked in the constructors")
    }

    /// Compute the composition of this quadratic form with another quadratic form.
    pub fn compose(&self, rhs: &QuadraticForm) -> QuadraticForm {
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
            swap(&mut (u1, v1, w1), &mut (u2, v2, w2));
        }
        let s: BigInt = (v1 + v2) >> 1;
        let m = v2 - &s;

        // 2.
        let EuclideanAlgorithmOutput {
            gcd: f,
            x: b,
            y: c,
            a_divided_by_gcd: mut capital_cy,
            b_divided_by_gcd: mut capital_by,
        } = extended_euclidean_algorithm(u2, u1);

        let (q, r) = s.div_rem(&f);
        let (g, capital_bx, capital_dy) = if r.is_zero() {
            (f, &m * &b, q)
        } else {
            // 3.
            let EuclideanAlgorithmOutput {
                gcd: g,
                x: _,
                y,
                a_divided_by_gcd: h,
                b_divided_by_gcd,
            } = extended_euclidean_algorithm(&f, &s);
            capital_by *= &h;
            capital_cy *= &h;

            // 4.
            let l = (&y * (&b * (w1.mod_floor(&h)) + &c * (w2.mod_floor(&h)))).mod_floor(&h);
            (
                g,
                &b * (&m / &h) + &l * (&capital_by / &h),
                b_divided_by_gcd,
            )
        };

        // 5. (partial xgcd)
        let mut bx = capital_bx.mod_floor(&capital_by);
        let mut by = capital_by.clone();

        let mut x = BigInt::one();
        let mut y = BigInt::zero();
        let mut z = 0u32;

        while by.abs() > *self.partial_gcd_limit() && !bx.is_zero() {
            let (q, t) = by.div_rem(&bx);
            by = bx;
            bx = t;
            swap(&mut x, &mut y);
            x -= &q * &y;
            z += 1;
        }

        if z.is_odd() {
            by = -by;
            y = -y;
        }

        let u3: BigInt;
        let w3: BigInt;
        let v3: BigInt;

        if z == 0 {
            // 6.
            let q = &capital_cy * &bx;
            let cx = (&q - &m) / &capital_by;
            let dx = (&bx * &capital_dy - w2) / &capital_by;
            u3 = &by * &capital_cy;
            w3 = &bx * &cx - &g * &dx;
            v3 = v2 - (&q << 1);
        } else {
            // 7.
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

            u3 = &by * &cy - &g * &y * &dy;
            w3 = &bx * &cx - &g * &x * &dx;
            v3 = &g * (&q3 + &q4) - &q1 - &q2;
        }

        let mut form = QuadraticForm {
            a: u3,
            b: v3,
            c: w3,
            partial_gcd_limit: self.partial_gcd_limit.clone(),
        };
        form.reduce();
        form
    }
}

impl Doubling for QuadraticForm {
    fn double(&self) -> Self {
        // Slightly optimised version of Algorithm 2 from Jacobson, Jr, Michael & Poorten, Alfred
        // (2002). "Computational aspects of NUCOMP", Lecture Notes in Computer Science.
        // (https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP)
        // The paragraph numbers and variable names follow the paper.

        let u = &self.a;
        let v = &self.b;
        let w = &self.c;

        let EuclideanAlgorithmOutput {
            gcd: g,
            x: _,
            y,
            a_divided_by_gcd: capital_by,
            b_divided_by_gcd: capital_dy,
        } = extended_euclidean_algorithm(u, v);

        let mut bx = (&y * w).mod_floor(&capital_by);
        let mut by = capital_by.clone();

        let mut x = BigInt::one();
        let mut y = BigInt::zero();
        let mut z = 0u32;

        while by.abs() > *self.partial_gcd_limit() && !bx.is_zero() {
            let (q, t) = by.div_rem(&bx);
            by = bx;
            bx = t;
            swap(&mut x, &mut y);
            x -= &q * &y;
            z += 1;
        }

        if z.is_odd() {
            by = -by;
            y = -y;
        }

        let mut u3: BigInt;
        let mut w3: BigInt;
        let mut v3: BigInt;

        if z == 0 {
            let dx = (&bx * &capital_dy - w) / &capital_by;
            u3 = &by * &by;
            w3 = &bx * &bx;
            let s = &bx + &by;
            v3 = v - &s * &s + &u3 + &w3;
            w3 = &w3 - &g * &dx;
        } else {
            let dx = (&bx * &capital_dy - w * &x) / &capital_by;
            let q1 = &dx * &y;
            let mut dy = &q1 + &capital_dy;
            v3 = &g * (&dy + &q1);
            dy = &dy / &x;
            u3 = &by * &by;
            w3 = &bx * &bx;
            v3 = &v3 - (&bx + &by).pow(2) + &u3 + &w3;

            u3 = &u3 - &g * &y * &dy;
            w3 = &w3 - &g * &x * &dx;
        }

        let mut form = QuadraticForm {
            a: u3,
            b: v3,
            c: w3,
            partial_gcd_limit: self.partial_gcd_limit.clone(),
        };
        form.reduce();
        form
    }
}

impl<'a> Mul<&'a BigInt> for QuadraticForm {
    type Output = Self;

    fn mul(self, rhs: &'a BigInt) -> Self::Output {
        self.borrow().mul(rhs)
    }
}

impl ParameterizedGroupElement for QuadraticForm {
    /// The discriminant of a quadratic form defines the class group.
    type ParameterType = Discriminant;

    type ScalarType = BigInt;

    fn zero(discriminant: &Self::ParameterType) -> Self {
        Self::from_a_b_and_discriminant(BigInt::one(), BigInt::one(), discriminant)
            .expect("Doesn't fail")
    }

    fn mul(&self, scale: &BigInt) -> Self {
        if scale.is_zero() {
            return Self::zero(&self.discriminant());
        }

        let mut result = self.clone();
        for i in (0..scale.bits() - 1).rev() {
            result = result.double();
            if scale.bit(i) {
                result = result + self;
            }
        }
        result
    }

    fn same_group(&self, other: &Self) -> bool {
        self.discriminant() == other.discriminant()
    }
}

impl Add<&QuadraticForm> for QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: &QuadraticForm) -> Self::Output {
        self.compose(rhs)
    }
}

impl Add<QuadraticForm> for QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: QuadraticForm) -> Self::Output {
        self.compose(&rhs)
    }
}

impl Add<&QuadraticForm> for &QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: &QuadraticForm) -> Self::Output {
        self.compose(rhs)
    }
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

impl UnknownOrderGroupElement for QuadraticForm {}

impl PartialEq for QuadraticForm {
    fn eq(&self, other: &Self) -> bool {
        // Ignore the partial_gcd_limit field
        self.a == other.a && self.b == other.b && self.c == other.c
    }
}
