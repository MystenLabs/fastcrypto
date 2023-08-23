// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.
//!
//! Serialization is compatible with the chiavdf library (https://github.com/Chia-Network/chiavdf).

use crate::error::FastCryptoError::{InputTooLong, InvalidInput};
use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::class_group::bigint_utils::extended_euclidean_algorithm;
use crate::groups::{ParameterizedGroupElement, UnknownOrderGroupElement};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::cmp::Ordering;
use std::mem::swap;
use std::ops::{Add, Neg};

mod bigint_utils;
mod compressed;

/// The maximal size in bits we allow a discriminant to have.
pub const MAX_DISCRIMINANT_SIZE_IN_BITS: u64 = 1024;

/// The size of a compressed quadratic form in bytes. We force all forms to have the same size,
/// namely 100 bytes.
pub const QUADRATIC_FORM_SIZE_IN_BYTES: usize = (
    // The number of 32 bit words needed to represent the discriminant rounded up,
    (MAX_DISCRIMINANT_SIZE_IN_BITS + 31) / 32
        * 3 // a' is two words and t' is one word. Both is divided by g, so the length of g is subtracted from both.
        + 1 // Flags for special forms (identity or generator) and the sign of b and t'.
        + 1 // The size of g - 1 = g_size.
        // Two extra bytes for g and b0 (which has the same length). Note that 2 * g_size was already counted.
        + 2
) as usize;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
///
/// The `partial_gcd_limit` variable must be equal to `|discriminant|^{1/4}` and is used to speed up
/// the composition algorithm.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QuadraticForm {
    a: BigInt,
    b: BigInt,
    c: BigInt,
    partial_gcd_limit: BigInt,
}

impl QuadraticForm {
    /// Create a new quadratic form given only the a and b coefficients and the discriminant.
    pub fn from_a_b_discriminant(a: BigInt, b: BigInt, discriminant: &Discriminant) -> Self {
        let c = ((&b * &b) - &discriminant.0) / (BigInt::from(4) * &a);
        Self {
            a,
            b,
            c,
            // This limit is used by `partial_euclidean_algorithm` in the add method.
            partial_gcd_limit: discriminant.0.abs().sqrt().sqrt(),
        }
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class
    /// group with a given discriminant. We use the element `(2, 1, c)` where `c` is determined from
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
        match self.b.magnitude().cmp(self.a.magnitude()) {
            Ordering::Less => true,
            Ordering::Equal => !self.b.is_negative(),
            Ordering::Greater => false,
        }
    }

    /// Return a normalized form equivalent to this quadratic form. See [`QuadraticForm::is_normal`].
    fn normalize(self) -> Self {
        // See section 5 in https://github.com/Chia-Network/chiavdf/blob/main/classgroups.pdf.
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

    /// Return true if this form is reduced: A form is reduced if it is normal (see
    /// [`QuadraticForm::is_normal`]) and a <= c and if a == c then b >= 0.
    fn is_reduced(&self) -> bool {
        match self.a.cmp(&self.c) {
            Ordering::Less => true,
            Ordering::Equal => !self.b.is_negative(),
            Ordering::Greater => false,
        }
    }

    /// Return a reduced form (see [`QuadraticForm::is_reduced`]) equivalent to this quadratic form.
    fn reduce(self) -> Self {
        // See section 5 in https://github.com/Chia-Network/chiavdf/blob/main/classgroups.pdf.
        let mut form = self.normalize();
        while !form.is_reduced() {
            let s = (&form.b + &form.c).div_floor(&(&form.c * 2));
            let cs = &form.c * &s;
            let old_a = form.a.clone();
            let old_b = form.b.clone();
            form.a = form.c.clone();
            form.c = (&cs - &old_b) * &s + &old_a;
            form.b = &cs * 2 - &form.b;
        }
        form
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
        let xgcd = extended_euclidean_algorithm(u2, u1);
        let f = xgcd.gcd;
        let b = xgcd.x;
        let c = xgcd.y;

        let g: BigInt;
        let capital_bx: BigInt;
        let capital_by: BigInt;
        let capital_cy: BigInt;
        let capital_dy: BigInt;

        let (q, r) = s.div_rem(&f);
        if r.is_zero() {
            g = f;
            capital_bx = &m * &b;
            capital_by = xgcd.b_divided_by_gcd;
            capital_cy = xgcd.a_divided_by_gcd;
            capital_dy = q;
        } else {
            // 3.
            let xgcd_prime = extended_euclidean_algorithm(&f, &s);
            g = xgcd_prime.gcd;
            let y = xgcd_prime.y;
            capital_by = &xgcd.b_divided_by_gcd * &xgcd_prime.a_divided_by_gcd;
            capital_cy = &xgcd.a_divided_by_gcd * &xgcd_prime.a_divided_by_gcd;
            capital_dy = xgcd_prime.b_divided_by_gcd;
            let h = xgcd_prime.a_divided_by_gcd;

            // 4.
            let l = (&y * (&b * (w1.mod_floor(&h)) + &c * (w2.mod_floor(&h)))).mod_floor(&h);
            capital_bx = &b * (&m / &h) + &l * (&capital_by / &h);
        }

        // 5. (partial xgcd)
        // TODO: capital_bx is not used later, so the modular reduction may be done earlier.
        let mut bx = capital_bx.mod_floor(&capital_by);
        let mut by = capital_by.clone();

        let mut x = BigInt::one();
        let mut y = BigInt::zero();
        let mut z = 0u32;

        while by.abs() > self.partial_gcd_limit && !bx.is_zero() {
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

        let (ax, ay) = if g.is_one() {
            (x.clone(), y.clone())
        } else {
            (&g * &x, &g * &y)
        };

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
            u3 = &by * &cy - &ay * &dy;
            w3 = &bx * &cx - &ax * &dx;
            v3 = &g * (&q3 + &q4) - &q1 - &q2;
        }

        QuadraticForm {
            a: u3,
            b: v3,
            c: w3,
            partial_gcd_limit: self.partial_gcd_limit.clone(),
        }
        .reduce()
    }

    fn double(&self) -> Self {
        // Slightly optimised version of Algorithm 2 from Jacobson, Jr, Michael & Poorten, Alfred
        // (2002). "Computational aspects of NUCOMP", Lecture Notes in Computer Science.
        // (https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP)
        // The paragraph numbers and variable names follow the paper.

        let u = &self.a;
        let v = &self.b;
        let w = &self.c;

        let xgcd = extended_euclidean_algorithm(u, v);
        let g = xgcd.gcd;
        let y = xgcd.y;

        let capital_by = xgcd.a_divided_by_gcd;
        let capital_dy = xgcd.b_divided_by_gcd;
        let mut bx = (&y * w).mod_floor(&capital_by);
        let mut by = capital_by.clone();

        let mut x = BigInt::one();
        let mut y = BigInt::zero();
        let mut z = 0u32;

        while by.abs() > self.partial_gcd_limit && !bx.is_zero() {
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

        let (ax, ay) = if g.is_one() {
            (x.clone(), y.clone())
        } else {
            (&g * &x, &g * &y)
        };

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
            let s = &bx + &by;
            v3 = &v3 - &s * &s + &u3 + &w3;
            u3 = &u3 - &ay * &dy;
            w3 = &w3 - &ax * &dx;
        }

        QuadraticForm {
            a: u3,
            b: v3,
            c: w3,
            partial_gcd_limit: self.partial_gcd_limit.clone(),
        }
        .reduce()
    }
}

impl ParameterizedGroupElement for QuadraticForm {
    /// The discriminant of a quadratic form defines the class group.
    type ParameterType = Discriminant;

    type ScalarType = BigInt;

    fn zero(discriminant: &Self::ParameterType) -> Self {
        Self::from_a_b_discriminant(BigInt::one(), BigInt::one(), discriminant)
    }

    fn double(&self) -> Self {
        self.compose(self)
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

    fn as_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
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

/// A discriminant for an imaginary class group. The discriminant is a negative integer which is
/// equal to 1 mod 4.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Discriminant(BigInt);

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        if !value.is_negative() || value.mod_floor(&BigInt::from(4)) != BigInt::from(1) {
            return Err(InvalidInput);
        }

        if value.bits() > MAX_DISCRIMINANT_SIZE_IN_BITS {
            return Err(InputTooLong(value.bits() as usize));
        }

        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use crate::groups::class_group::{Discriminant, QuadraticForm};
    use crate::groups::ParameterizedGroupElement;
    use num_bigint::BigInt;

    #[test]
    fn test_multiplication() {
        let discriminant = Discriminant::try_from(BigInt::from(-47)).unwrap();
        let generator = QuadraticForm::generator(&discriminant);
        let mut current = QuadraticForm::zero(&discriminant);
        for i in 0..10000 {
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
        // The order of the class group (the class number) for -223 is 7 (see https://mathworld.wolfram.com/ClassNumber.html).
        let discriminant = Discriminant::try_from(BigInt::from(-223)).unwrap();
        let g = QuadraticForm::generator(&discriminant);

        for i in 1..=6 {
            assert_ne!(QuadraticForm::zero(&discriminant), g.mul(&BigInt::from(i)));
        }
        assert_eq!(QuadraticForm::zero(&discriminant), g.mul(&BigInt::from(7)));
    }
}
