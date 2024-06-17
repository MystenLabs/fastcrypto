// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::QuadraticForm;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed};
use std::cmp::Ordering;
use std::mem::swap;
use std::ops::ShrAssign;

impl QuadraticForm {
    /// Return true if this form is in normal form: -a < b <= a.
    #[inline]
    fn is_normal(&self) -> bool {
        match self.b.magnitude().cmp(self.a.magnitude()) {
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
        let r = -increment_and_shift_right(self.b.div_floor(&self.a));
        let ra: BigInt = &r * &self.a;
        self.b += &ra;
        self.c += &self.b * &r;
        self.b += &ra;
    }

    /// Return true if this form is reduced: A form is reduced if it is normal (see
    /// [`QuadraticForm::is_normal`]) and a <= c and if a == c then b >= 0.
    #[inline]
    pub(crate) fn is_reduced_assuming_normal(&self) -> bool {
        match self.a.cmp(&self.c) {
            Ordering::Less => true,
            Ordering::Equal => !self.b.is_negative(),
            Ordering::Greater => false,
        }
    }

    /// Return a reduced form (see [`QuadraticForm::is_reduced_assuming_normal`]) equivalent to this quadratic form.
    pub(crate) fn reduce(mut self) -> Self {
        // See section 5 in https://github.com/Chia-Network/chiavdf/blob/main/classgroups.pdf.
        self.normalize();
        while !self.is_reduced_assuming_normal() {
            let s = increment_and_shift_right(self.b.div_floor(&self.c));
            let cs: BigInt = &self.c * &s;
            swap(&mut self.a, &mut self.c);
            self.b = -self.b;
            self.b += &cs;
            self.c += &self.b * &s;
            self.b += &cs;
        }
        self
    }
}

/// Compute (x + 1) >> 1.
#[inline]
fn increment_and_shift_right(mut x: BigInt) -> BigInt {
    if x.is_odd() {
        // If x is even, there's no carry on the first bit, so adding 1 will not change anything.
        x += BigInt::one();
    }
    x.shr_assign(1);
    x
}

#[cfg(test)]
mod tests {
    use crate::class_group::Discriminant;
    use crate::class_group::QuadraticForm;
    use num_bigint::BigInt;

    #[test]
    fn test_normalization_and_reduction() {
        let discriminant = Discriminant::from_trusted_bigint(BigInt::from(-223));
        let mut quadratic_form = QuadraticForm::from_a_b_and_discriminant(
            BigInt::from(41),
            BigInt::from(49),
            &discriminant,
        )
        .unwrap();
        assert_eq!(quadratic_form.c, BigInt::from(16));

        quadratic_form.normalize();
        assert!(quadratic_form.is_normal());
        assert_eq!(quadratic_form.a, BigInt::from(41));
        assert_eq!(quadratic_form.b, BigInt::from(-33));
        assert_eq!(quadratic_form.c, BigInt::from(8));

        quadratic_form = quadratic_form.reduce();
        assert!(quadratic_form.is_reduced_assuming_normal());
        assert_eq!(quadratic_form.a, BigInt::from(7));
        assert_eq!(quadratic_form.b, BigInt::from(-1));
        assert_eq!(quadratic_form.c, BigInt::from(8));
    }
}
