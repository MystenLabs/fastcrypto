// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{ParameterizedGroupElement, UnknownOrderGroupElement};
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use num_bigint::BigInt;
use num_integer::Integer as IntegerTrait;
use num_traits::{Signed, Zero};
use rug::integer::Order;
use rug::ops::{DivRoundingAssign, NegAssign, RemRoundingAssign, SubFrom};
use rug::{Assign, Complete, Integer};
use std::cmp::Ordering;
use std::mem::swap;
use std::ops::{Add, AddAssign, MulAssign, Neg, SubAssign};

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
        Self::from_a_b_discriminant(Integer::from(2), Integer::ONE.to_owned(), discriminant)
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
        r.mul_assign(&self.b);
        self.c.add_assign(&r);
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

        let mut s: Integer = Integer::from(v1 + v2) >> 1;
        let m = Integer::from(v2 - &s);

        // 2.
        let (f, b, c) = Integer::extended_gcd_ref(u2, u1).complete();

        let mut capital_by = u1.div_exact_ref(&f).complete();
        let mut capital_cy = u2.div_exact_ref(&f).complete();

        let (q, r) = s.div_rem_ref(&f).complete();

        let (g, capital_bx, capital_dy) = if r.is_zero() {
            (f, Integer::from(&b * &m), q)
        } else {
            // 3.
            // Using (q,r) = div_rem(s,f) computed above, we may skip the first iteration of the
            // Euclidean algorithm of (f,s):
            let (g, _, y) = Integer::extended_gcd_ref(&f, &r).complete();

            let h = f.div_exact(&g);

            capital_by.mul_assign(&h);
            capital_cy.mul_assign(&h);

            // 4.
            let mut l = (&y
                * (&b * (w1.modulo_ref(&h).complete()) + &c * (w2.modulo_ref(&h).complete())))
            .modulo(&h);

            l.mul_assign(capital_by.div_exact_ref(&h).complete());
            l.add_assign(&b * (&m / &h).complete());

            s.div_exact_mut(&g);
            (g, l, s)
        };

        // 5. (partial xgcd)
        let mut bx = capital_bx.modulo(&capital_by);
        let mut by = capital_by.clone();

        let mut x = Integer::ONE.to_owned();
        let mut y = Integer::ZERO;
        let mut z = 0u32;

        let mut q = Integer::new();

        while by.cmp_abs(&self.partial_gcd_limit) == Ordering::Greater && !bx.is_zero() {
            q.assign(&by / &bx);

            swap(&mut by, &mut bx);
            bx.sub_assign(&q * &by);

            swap(&mut x, &mut y);
            x.sub_assign(&q * &y);
            z += 1;
        }

        if z.is_odd() {
            by.neg_assign();
            y.neg_assign();
        }

        let mut u3: Integer;
        let mut w3: Integer;
        let mut v3: Integer;

        if z == 0 {
            // 6.
            let mut q = Integer::from(&capital_cy);
            q.mul_assign(&bx);

            let mut cx = m;
            cx.sub_from(&q);
            cx.div_exact_mut(&capital_by);

            let mut dx = Integer::from(&capital_dy);
            dx.mul_assign(&bx);
            dx.sub_assign(w2);
            dx.div_exact_mut(&capital_by);

            u3 = by;
            u3.mul_assign(&capital_cy);

            w3 = bx;
            w3.mul_assign(&cx);
            w3.sub_assign(&g * &dx);

            v3 = q;
            v3.mul_assign(2);
            v3.sub_from(v2);
        } else {
            // 7.
            let mut cx = capital_cy;
            cx.mul_assign(&bx);
            cx.sub_assign(&m * &x);
            cx.div_exact_mut(&capital_by);

            let mut q1 = Integer::new();
            q1.assign(&by * &cx);

            let mut q2 = m;
            q2.add_assign(&q1);

            let mut dx = c; // Re-use value
            dx.assign(&capital_dy * &bx);
            dx.sub_assign(w2 * &x);
            dx.div_exact_mut(&capital_by);

            let q3 = Integer::from(&y * &dx);

            let mut q4 = capital_dy;
            q4.add_assign(&q3);

            let mut dy = Integer::from(&q4);
            dy.div_exact_mut(&x);

            let cy = if !b.is_zero() {
                q2.div_exact_ref(&bx).complete()
            } else {
                (Integer::from(&cx * &dy) - w1).div_exact(&dx)
            };

            w3 = dx;
            w3.mul_assign(&g);
            w3.mul_assign(&x);
            w3.sub_from(&bx * &cx);

            u3 = dy;
            u3.mul_assign(&g);
            u3.mul_assign(&y);
            u3.sub_from(&by * &cy);

            v3 = q3;
            v3.add_assign(q4);
            v3.mul_assign(&g);
            v3.sub_assign(&q1);
            v3.sub_assign(&q2);
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
        Self::from_a_b_discriminant(
            Integer::ONE.to_owned(),
            Integer::ONE.to_owned(),
            discriminant,
        )
    }

    fn double(mut self) -> Self {
        // Slightly optimised version of Algorithm 2 from Jacobson, Jr, Michael & Poorten, Alfred
        // (2002). "Computational aspects of NUCOMP", Lecture Notes in Computer Science.
        // (https://www.researchgate.net/publication/221451638_Computational_aspects_of_NUCOMP)
        // The paragraph numbers and variable names follow the paper.

        let (g, mut bx, _) = Integer::extended_gcd_ref(&self.b, &self.a).complete();
        self.a.div_exact_mut(&g);

        bx.mul_assign(&self.c);
        bx.rem_floor_assign(&self.a);

        let mut by = Integer::from(&self.a);

        let mut first = true;
        let mut x = Integer::new();
        let mut y = Integer::new();
        let mut z = 0u32;

        let mut q = Integer::new();

        while by.cmp_abs(&self.partial_gcd_limit) == Ordering::Greater && !bx.is_zero() {
            q.assign(&by / &bx);

            swap(&mut by, &mut bx);
            bx.sub_assign(&q * &by);

            if first {
                y.assign(Integer::ONE);
                x.assign(-&q);
                first = false;
            } else {
                swap(&mut x, &mut y);
                x.sub_assign(&q * &y);
            }
            z += 1;
        }

        if z.is_odd() {
            by.neg_assign();
            y.neg_assign();
        }

        if z == 0 {
            self.c.mul_assign(&g);
            self.c.sub_from(&bx * &self.b);
            self.c.div_exact_mut(&self.a);
            self.c.sub_from(bx.square_ref());

            self.a.mul_assign(&by);

            bx.mul_assign(&by);
            self.b.sub_assign(&bx);
            self.b.sub_assign(&bx);
        } else {
            self.c.mul_assign(&x);
            self.c.mul_assign(&g);
            self.c.sub_from(&bx * &self.b);
            self.c.div_exact_mut(&self.a);

            self.a.assign(&y * &self.c);
            q.assign(&self.a);

            self.a.add_assign(&self.b);
            self.a.div_exact_mut(&x);
            self.a.mul_assign(&y);
            self.a.sub_from(by.square_ref());

            self.c.mul_assign(&x);
            self.c.sub_from(bx.square_ref());

            // s in paper
            bx.mul_assign(by);
            bx.sub_assign(&q);
            self.b.sub_assign(&bx);
            self.b.sub_assign(bx);
        }

        self.reduce()
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
        if !value.is_negative() || &value.modulo_ref(&Integer::from(4)).complete() != Integer::ONE {
            return Err(InvalidInput);
        }
        Ok(Self(value))
    }
}

impl TryFrom<BigInt> for Discriminant {
    type Error = FastCryptoError;

    fn try_from(value: BigInt) -> FastCryptoResult<Self> {
        if !value.is_negative() {
            return Err(InvalidInput);
        }
        Self::try_from(-Integer::from_digits(&value.to_bytes_be().1, Order::Msf))
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
    use crate::class_group::gmp::{Discriminant, QuadraticForm};
    use crate::ParameterizedGroupElement;
    use num_bigint::BigInt;
    use rug::Integer;

    #[test]
    fn test_multiplication() {
        let discriminant = Discriminant::try_from(Integer::from(-47)).unwrap();
        let generator = QuadraticForm::generator(&discriminant);
        let mut current = QuadraticForm::zero(&discriminant);
        for i in 0..100000 {
            assert_eq!(current, generator.mul(&BigInt::from(i)));
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
            assert_ne!(QuadraticForm::zero(&discriminant), g.mul(&BigInt::from(i)));
        }
        assert_eq!(QuadraticForm::zero(&discriminant), g.mul(&BigInt::from(7)));
    }
}
