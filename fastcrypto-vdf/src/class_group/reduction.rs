// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::QuadraticForm;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::Signed;
use std::cmp::Ordering;
use std::mem::swap;
use std::ops::{AddAssign, Shl, Shr};

impl QuadraticForm {
    /// Return true if this form is in normal form: -a < b <= a.
    pub fn is_normal(&self) -> bool {
        match self.b.magnitude().cmp(self.a.magnitude()) {
            Ordering::Less => true,
            Ordering::Equal => !self.b.is_negative(),
            Ordering::Greater => false,
        }
    }

    /// Return a normalized form equivalent to this quadratic form. See [`QuadraticForm::is_normal`].
    pub fn normalize(&mut self) {
        // See section 5 in https://github.com/Chia-Network/chiavdf/blob/main/classgroups.pdf.
        if self.is_normal() {
            return;
        }
        let r = (&self.a - &self.b).div_floor(&self.a).shr(1);
        let ra: BigInt = &r * &self.a;
        self.c.add_assign((&ra + &self.b) * &r);
        self.b.add_assign(&ra.shl(1));
    }

    /// Return true if this form is reduced: A form is reduced if it is normal (see
    /// [`QuadraticForm::is_normal`]) and a <= c and if a == c then b >= 0.
    pub fn is_reduced(&self) -> bool {
        match self.a.cmp(&self.c) {
            Ordering::Less => true,
            Ordering::Equal => !self.b.is_negative(),
            Ordering::Greater => false,
        }
    }

    /// Return a reduced form (see [`QuadraticForm::is_reduced`]) equivalent to this quadratic form.
    pub fn reduce(&mut self) {
        // See section 5 in https://github.com/Chia-Network/chiavdf/blob/main/classgroups.pdf.
        self.normalize();
        while !self.is_reduced() {
            let s = (&self.b + &self.c).div_floor(&self.c).shr(1);
            let cs: BigInt = &self.c * &s;
            swap(&mut self.a, &mut self.c);
            self.c += (&cs - &self.b) * &s;
            self.b = cs.shl(1) - &self.b;
        }
    }
}
