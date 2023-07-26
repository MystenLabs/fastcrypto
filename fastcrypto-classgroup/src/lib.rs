// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Neg;
use std::process::Output;
use num_bigint::BigInt;
use num::{Integer, Signed, Zero};

struct BinaryQuadraticForm {
    pub a: BigInt,
    pub b: BigInt,
    pub c: BigInt,
}

// https://github.com/Chia-Network/vdftrack1results/blob/main/bulaiden/entry/vdf.cpp

impl BinaryQuadraticForm {

    fn generator(discriminant: &BigInt) -> Self {
        let a = BigInt::from(2);
        let b = BigInt::from(1);
        let mut c = &b * &b;
        c -= discriminant;
        let denom = &a * 4;
        c = c.div_floor(&denom);
        let mut result = Self {
            a,
            b,
            c,
        };
        result.reduce();
        result
    }

    fn is_normalized(&self) -> bool {
        &self.b <= &(&self.a).neg() && &self.b <= &self.a
    }

    fn discriminant(&self) -> BigInt {
        &self.b * &self.b - &self.a * &self.c * 4
    }

    fn normalize(&mut self) {
        if self.is_normalized() {
            return;
        }

        let r = (&self.a - &self.b).div_floor(&(&self.a * 2));
        let mut ra = &r * &self.a;

        self.c += &ra * &r;
        self.c += &r * &self.b;

        ra = &ra * 2;
        self.b = &self.b + ra;
    }

    fn is_reduced(&self) -> bool {
        if !self.is_normalized() {
            return false;
        }
        if &self.a == &self.c {
            return &self.b >= &BigInt::zero();
        }
        &self.a < &self.c
    }

    fn reduce(&mut self) {
        self.normalize();
        while &self.a > &self.c || (&self.a == &self.c && &self.b < &BigInt::zero()) {
            let s = (&self.b + &self.c).div_floor(&(&self.c * 2));
            let old_a = self.a.clone();
            let old_b = self.b.clone();
            self.a = self.c.clone();
            self.b = (&self.b).neg();
            let p = &s * &self.c * 2;
            self.b = &self.b + p;
            let p = &old_b * &s;
            let s = &s * &s;
            self.c = &self.c * s;
            self.c = &self.c - p;
            self.c = &self.c + old_a;
        }
        self.normalize();
    }

    fn double(&self) -> Self {
        let (g, y, _) = self.b.extended_gcd(&self.a);

        let by = &self.a / &g;
        let dy = &self.b / &g;
        let bx = (&y * &self.c).mod_floor(&by);


    }

}

#[test]
fn test_normalize() {
    let mut form = BinaryQuadraticForm {
        a: BigInt::from(11),
        b: BigInt::from(49),
        c: BigInt::from(55),
    };
    form.normalize();

    assert_eq!(form.a, BigInt::from(11));
    assert_eq!(form.b, BigInt::from(5));
    assert_eq!(form.c, BigInt::from(1));
}

#[test]
fn test_reduce() {
    let mut form = BinaryQuadraticForm {
        a: BigInt::from(11),
        b: BigInt::from(49),
        c: BigInt::from(55),
    };
    form.reduce();

    assert_eq!(form.a, BigInt::from(1));
    assert_eq!(form.b, BigInt::from(1));
    assert_eq!(form.c, BigInt::from(5));
}




