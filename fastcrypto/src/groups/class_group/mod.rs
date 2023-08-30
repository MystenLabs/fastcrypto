// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.
//!
//! Serialization is compatible with the chiavdf library (https://github.com/Chia-Network/chiavdf).

use crate::error::FastCryptoError::InvalidInput;
use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::class_group::bigint_utils::extended_euclidean_algorithm;
use crate::groups::{ParameterizedGroupElement, UnknownOrderGroupElement};
use rug::integer::Order;
use rug::ops::{DivRoundingAssign, NegAssign, RemRoundingAssign};
use rug::{Assign, Complete, Integer};
use std::cmp::Ordering;
use std::mem::swap;
use std::ops::{Add, AddAssign, MulAssign, Neg, SubAssign};
use num_integer::Integer as IntegerTrait;

pub mod bigint_utils;
mod compressed;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
///
/// The `partial_gcd_limit` variable must be equal to `|discriminant|^{1/4}` and is used to speed up
/// the composition algorithm.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QuadraticForm {
    a: Integer,
    b: Integer,
    c: Integer,
    partial_gcd_limit: Integer,
}

impl QuadraticForm {
    /// Create a new quadratic form given only the a and b coefficients and the discriminant.
    pub fn from_a_b_discriminant(a: Integer, b: Integer, discriminant: &Discriminant) -> Self {
        let c = ((&b * &b) - &discriminant.0).complete() / (Integer::from(4) * &a);
        Self {
            a,
            b,
            c,
            // This limit is used by `partial_euclidean_algorithm` in the add method.
            partial_gcd_limit: discriminant.0.abs_ref().complete().root_ref(4).complete(),
        }
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class
    /// group with a given discriminant. We use the element `(2, 1, c)` where `c` is determined from
    /// the discriminant.
    pub fn generator(discriminant: &Discriminant) -> Self {
        Self::from_a_b_discriminant(Integer::from(2), Integer::from(1), discriminant)
    }

    /// Compute the discriminant `b^2 - 4ac` for this quadratic form.
    pub fn discriminant(&self) -> Discriminant {
        Discriminant::try_from(
            Integer::from(&self.b * &self.b) - (Integer::from(4) * &self.a * &self.c),
        )
        .expect("The discriminant is checked in the constructors")
    }

    /// Return true if this form is in normal form: -a < b <= a.
    #[inline]
    fn is_normal(&self) -> bool {
        match self.b.cmp_abs(&self.a) {
            Ordering::Less => true,
            Ordering::Equal => !self.b.is_negative(),
            Ordering::Greater => false,
        }
    }

    /// Return a normalized form equivalent to this quadratic form. See [`QuadraticForm::is_normal`].
    fn normalize(&mut self) {
        // See section 5 in https://github.com/Chia-Network/chiavdf/blob/main/classgroups.pdf.
        if self.is_normal() {
            return;
        }
        let mut r = (&self.a - &self.b).complete();
        r.div_floor_assign(Integer::from(&self.a + &self.a));
        let ra = Integer::from(&r * &self.a);
        self.b.add_assign(&ra);
        self.c.add_assign(&self.b * &r);
        self.b.add_assign(&ra);
    }

    /// Return true if this form is reduced: A form is reduced if it is normal (see
    /// [`QuadraticForm::is_normal`]) and a <= c and if a == c then b >= 0.
    #[inline]
    fn is_reduced(&self) -> bool {
        match self.a.cmp(&self.c) {
            Ordering::Less => true,
            Ordering::Equal => !self.b.is_negative(),
            Ordering::Greater => false,
        }
    }

    /// Return a reduced form (see [`QuadraticForm::is_reduced`]) equivalent to this quadratic form.
    fn reduce(mut self) -> Self {
        // See section 5 in https://github.com/Chia-Network/chiavdf/blob/main/classgroups.pdf.
        self.normalize();

        let mut s = Integer::new();
        let mut cs = Integer::new();

        while !self.is_reduced() {
            s.assign(&self.b + &self.c);
            s.div_floor_assign(Integer::from(&self.c + &self.c));
            cs.assign(&self.c * &s);
            swap(&mut self.a, &mut self.c);
            self.b.neg_assign();
            self.b.add_assign(&cs);
            s.mul_assign(&self.b);
            self.c.add_assign(&s);
            self.b.add_assign(&cs);
        }
        self
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
        let s: Integer = Integer::from(v1 + v2) >> 1;
        let m = Integer::from(v2 - &s);

        // 2.
        let xgcd = extended_euclidean_algorithm(u2, u1);
        let f = xgcd.gcd;
        let b = xgcd.x;
        let c = xgcd.y;

        let g: Integer;
        let capital_bx: Integer;
        let capital_by: Integer;
        let capital_cy: Integer;
        let capital_dy: Integer;

        let (q, r) = s.div_rem_ref(&f).complete();
        if r.is_zero() {
            g = f;
            capital_bx = Integer::from(&m * &b);
            capital_by = xgcd.b_divided_by_gcd;
            capital_cy = xgcd.a_divided_by_gcd;
            capital_dy = q;
        } else {
            // 3.
            let xgcd_prime = extended_euclidean_algorithm(&f, &s);
            g = xgcd_prime.gcd;
            let y = xgcd_prime.y;
            capital_by = Integer::from(&xgcd.b_divided_by_gcd * &xgcd_prime.a_divided_by_gcd);
            capital_cy = Integer::from(&xgcd.a_divided_by_gcd * &xgcd_prime.a_divided_by_gcd);
            capital_dy = xgcd_prime.b_divided_by_gcd;
            let h = xgcd_prime.a_divided_by_gcd;

            // 4.
            let l = (&y
                * (&b * (w1.modulo_ref(&h).complete()) + &c * (w2.modulo_ref(&h).complete())))
            .modulo(&h);
            capital_bx = Integer::from(&b * (&m / &h).complete())
                + Integer::from(&l * (&capital_by / &h).complete());
        }

        // 5. (partial xgcd)
        // TODO: capital_bx is not used later, so the modular reduction may be done earlier.
        let mut bx = capital_bx.modulo(&capital_by);
        let mut by = capital_by.clone();

        let mut x = Integer::from(1);
        let mut y = Integer::new();
        let mut z = 0u32;

        while by.abs_ref().complete() > self.partial_gcd_limit && !bx.is_zero() {
            let (q, t) = by.div_rem_ref(&bx).complete();
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

        let u3: Integer;
        let w3: Integer;
        let v3: Integer;

        if z == 0 {
            // 6.
            let q = Integer::from(&capital_cy * &bx);
            let cx = Integer::from(&q - &m) / &capital_by;
            let dx = (Integer::from(&bx * &capital_dy) - w2) / &capital_by;
            u3 = Integer::from(&by * &capital_cy);
            w3 = Integer::from(&bx * &cx) - &g * &dx;
            v3 = Integer::from(v2 - Integer::from(&q << 1));
        } else {
            // 7.
            let cx = (Integer::from(&capital_cy * &bx) - &m * &x) / &capital_by;
            let q1 = Integer::from(&by * &cx);
            let q2 = Integer::from(&q1 + &m);
            let dx = (Integer::from(&capital_dy * &bx) - w2 * &x) / &capital_by;
            let q3 = Integer::from(&y * &dx);
            let q4 = Integer::from(&q3 + &capital_dy);
            let dy = Integer::from(&q4 / &x);
            let cy = if !b.is_zero() {
                Integer::from(&q2 / &bx)
            } else {
                (Integer::from(&cx * &dy) - w1) / &dx
            };

            let (ax_dx, ay_dy) = (Integer::from(&g * &x) * &dx, Integer::from(&g * &y) * &dy);

            u3 = Integer::from(&by * &cy) - &ay_dy;
            w3 = Integer::from(&bx * &cx) - &ax_dx;
            v3 = &g * Integer::from(&q3 + &q4) - &q1 - &q2;
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

    type ScalarType = Integer;

    fn zero(discriminant: &Self::ParameterType) -> Self {
        Self::from_a_b_discriminant(Integer::from(1), Integer::from(1), discriminant)
    }

    fn double(mut self) -> Self {
        // Slightly optimised version of Algorithm 2 from Jacobson, Jr, Michael & Poorten, Alfred
        // (2002). "Computational aspects of NUCOMP", Lecture Notes in Computer Science.
        // (https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP)
        // The paragraph numbers and variable names follow the paper.

        let xgcd = extended_euclidean_algorithm(&self.b, &self.a);
        let g = xgcd.gcd;

        let mut capital_by = xgcd.b_divided_by_gcd;
        let mut capital_dy = xgcd.a_divided_by_gcd;

        let mut bx = xgcd.x;
        bx.mul_assign(&self.c);
        bx.rem_floor_assign(&capital_by);

        let mut by = Integer::from(&capital_by);

        let mut x = Integer::ONE.to_owned();
        let mut y = Integer::ZERO;
        let mut z = 0u32;

        let (mut q, mut t) = (Integer::new(), Integer::new());

        while by.cmp_abs(&self.partial_gcd_limit) == Ordering::Greater && !bx.is_zero() {
            (&mut q, &mut t).assign(by.div_rem_euc_ref(&bx));
            by.assign(&bx);
            bx.assign(&t);
            swap(&mut x, &mut y);
            x.sub_assign(&q * &y);
            z += 1;
        }

        if z.is_odd() {
            by.neg_assign();
            y.neg_assign();
        }

        if z == 0 {
            self.c.neg_assign();
            self.c.add_assign(&bx * &capital_dy);
            capital_by.div_exact_from(&self.c);
            self.a.assign(by.square_ref());
            self.c.assign(bx.square_ref());
            self.b.add_assign(&self.a);
            self.b.add_assign(&self.c);
            self.b.sub_assign(Integer::from(&bx + &by).square_ref());
            self.c.sub_assign(&g * &capital_by);
        } else {
            self.c.mul_assign(&x);
            self.c.neg_assign();
            self.c.add_assign(&bx * &capital_dy);
            // dx in paper
            capital_by.div_exact_from(&self.c);

            let q1 = Integer::from(&capital_by * &y);

            capital_dy.add_assign(&q1);

            self.b.assign(&capital_dy);
            self.b.add_assign(&q1);
            self.b.mul_assign(&g);
            capital_dy.div_exact_mut(&x);
            self.a.assign(by.square_ref());
            self.c.assign(bx.square_ref());

            // s in paper
            bx.add_assign(&by);
            bx.square_mut();

            self.b.sub_assign(&bx);
            self.b.add_assign(&self.a);
            self.b.add_assign(&self.c);

            capital_by.mul_assign(&g);
            capital_by.mul_assign(&x);

            capital_dy.mul_assign(&g);
            capital_dy.mul_assign(&y);

            self.a.sub_assign(&capital_dy);
            self.c.sub_assign(&capital_by);
        }

        self.reduce()
    }

    fn mul(&self, scale: &Integer) -> Self {
        if scale.is_zero() {
            return Self::zero(&self.discriminant());
        }

        let mut result = self.clone();
        for i in (0..scale.significant_bits() - 1).rev() {
            result = result.double();
            if scale.get_bit(i) {
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
pub struct Discriminant(Integer);

impl TryFrom<Integer> for Discriminant {
    type Error = FastCryptoError;

    fn try_from(value: Integer) -> FastCryptoResult<Self> {
        if !value.is_negative()
            || value.modulo_ref(&Integer::from(4)).complete() != Integer::from(1)
        {
            return Err(InvalidInput);
        }
        Ok(Self(value))
    }
}

impl Discriminant {
    /// Return the number of bits needed to represent this discriminant, not including the sign bit.
    pub fn bits(&self) -> usize {
        self.0.significant_bits() as usize
    }

    /// Returns the big-endian byte representation of the absolute value of this discriminant.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_digits(Order::Msf)
    }
}

#[cfg(test)]
mod tests {
    use crate::groups::class_group::{Discriminant, QuadraticForm};
    use crate::groups::ParameterizedGroupElement;
    use rug::Integer;

    #[test]
    fn test_multiplication() {
        let discriminant = Discriminant::try_from(Integer::from(-47)).unwrap();
        let generator = QuadraticForm::generator(&discriminant);
        let mut current = QuadraticForm::zero(&discriminant);
        for i in 0..100000 {
            assert_eq!(current, generator.mul(&Integer::from(i)));
            current = current + &generator;
        }
    }

    #[test]
    fn test_normalization_and_reduction() {
        let discriminant = Discriminant::try_from(Integer::from(-19)).unwrap();
        let mut quadratic_form = QuadraticForm::from_a_b_discriminant(
            Integer::from(11),
            Integer::from(49),
            &discriminant,
        );
        assert_eq!(quadratic_form.c, Integer::from(55));

        quadratic_form.normalize();

        // Test vector from https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf
        assert_eq!(quadratic_form.a, Integer::from(11));
        assert_eq!(quadratic_form.b, Integer::from(5));
        assert_eq!(quadratic_form.c, Integer::from(1));

        quadratic_form = quadratic_form.reduce();

        // Test vector from https://github.com/Chia-Network/vdf-competition/blob/main/classgroups.pdf
        assert_eq!(quadratic_form.a, Integer::from(1));
        assert_eq!(quadratic_form.b, Integer::from(1));
        assert_eq!(quadratic_form.c, Integer::from(5));
    }

    #[test]
    fn test_composition() {
        // The order of the class group (the class number) for -223 is 7 (see https://mathworld.wolfram.com/ClassNumber.html).
        let discriminant = Discriminant::try_from(Integer::from(-223)).unwrap();
        let g = QuadraticForm::generator(&discriminant);

        for i in 1..=6 {
            assert_ne!(QuadraticForm::zero(&discriminant), g.mul(&Integer::from(i)));
        }
        assert_eq!(QuadraticForm::zero(&discriminant), g.mul(&Integer::from(7)));
    }
}
