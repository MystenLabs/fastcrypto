// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_integer::Integer as IntegerTrait;
use num_traits::{One, Signed, Zero};
use rug::ops::NegAssign;
use rug::{Assign, Complete, Integer};
use std::mem;
use std::ops::{Neg, SubAssign};

pub struct EuclideanAlgorithmOutput {
    pub gcd: Integer,
    pub x: Integer,
    pub y: Integer,
    pub a_divided_by_gcd: Integer,
    pub b_divided_by_gcd: Integer,
}

impl EuclideanAlgorithmOutput {
    fn flip(self) -> Self {
        Self {
            gcd: self.gcd,
            x: self.y,
            y: self.x,
            a_divided_by_gcd: self.b_divided_by_gcd,
            b_divided_by_gcd: self.a_divided_by_gcd,
        }
    }
}

/// Compute the greatest common divisor gcd of a and b. The output also returns the Bezout coefficients
/// x and y such that ax + by = gcd and also the quotients a / gcd and b / gcd.
pub fn extended_euclidean_algorithm(a: &Integer, b: &Integer) -> EuclideanAlgorithmOutput {
    if b < a {
        return extended_euclidean_algorithm(b, a).flip();
    }

    let mut s = (Integer::new(), Integer::from(1));
    let mut t = (Integer::from(1), Integer::new());
    let mut r = (a.clone(), b.clone());

    let mut q = Integer::new();
    let mut r_prime = Integer::new();

    while !r.0.is_zero() {
        (&mut q, &mut r_prime).assign(r.1.div_rem_euc_ref(&r.0));
        r.1.assign(&r.0);
        r.0.assign(&r_prime);

        mem::swap(&mut s.0, &mut s.1);
        s.0.sub_assign(&q * &s.1);

        mem::swap(&mut t.0, &mut t.1);
        t.0.sub_assign(&q * &t.1);
    }

    // The last coefficients are equal to +/- a / gcd(a,b) and b / gcd(a,b) respectively.
    if a.is_negative() != s.0.is_negative() {
        s.0.neg_assign();
    }
    if b.is_negative() != t.0.is_negative() {
        t.0.neg_assign();
    }

    if r.1.is_negative() {
        r.1.neg_assign();
        t.1.neg_assign();
        s.1.neg_assign();
    }

    EuclideanAlgorithmOutput {
        gcd: r.1,
        x: t.1,
        y: s.1,
        a_divided_by_gcd: s.0,
        b_divided_by_gcd: t.0,
    }
}

#[test]
fn test_xgcd() {
    let a = Integer::from(240);
    let b = Integer::from(46);
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd_ref(&b).complete());
    assert_eq!((&output.x * &a).complete() + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, (&a / &output.gcd).complete());
    assert_eq!(output.b_divided_by_gcd, (&b / &output.gcd).complete());

    let a = Integer::from(240);
    let b = Integer::from(-46);
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd_ref(&b).complete());
    assert_eq!((&output.x * &a).complete() + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, (&a / &output.gcd).complete());
    assert_eq!(output.b_divided_by_gcd, (&b / &output.gcd).complete());

    let a = Integer::from(-240);
    let b = Integer::from(-46);
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd_ref(&b).complete());
    assert_eq!((&output.x * &a).complete() + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, (&a / &output.gcd).complete());
    assert_eq!(output.b_divided_by_gcd, (&b / &output.gcd).complete());
}

#[test]
fn test_large_gcd() {}
