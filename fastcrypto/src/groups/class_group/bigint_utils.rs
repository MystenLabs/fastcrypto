// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_integer::Integer as IntegerTrait;
use num_traits::{One, Signed, Zero};
use rug::{Complete, Integer};
use std::mem;
use std::ops::Neg;

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

    while !r.0.is_zero() {
        let (q, r_prime) = r.1.div_rem_euc_ref(&r.0).complete();
        r.1 = r.0;
        r.0 = r_prime;

        let f = |mut x: (Integer, Integer)| {
            mem::swap(&mut x.0, &mut x.1);
            x.0 -= &q * &x.1;
            x
        };
        s = f(s);
        t = f(t);
    }

    // The last coefficients are equal to +/- a / gcd(a,b) and b / gcd(a,b) respectively.
    let a_divided_by_gcd = if a.signum_ref().complete() != s.0.signum_ref().complete() {
        s.0.neg()
    } else {
        s.0
    };
    let b_divided_by_gcd = if b.signum_ref().complete() != t.0.signum_ref().complete() {
        t.0.neg()
    } else {
        t.0
    };

    if !r.1.is_negative() {
        EuclideanAlgorithmOutput {
            gcd: r.1,
            x: t.1,
            y: s.1,
            a_divided_by_gcd,
            b_divided_by_gcd,
        }
    } else {
        EuclideanAlgorithmOutput {
            gcd: r.1.neg(),
            x: t.1.neg(),
            y: s.1.neg(),
            a_divided_by_gcd,
            b_divided_by_gcd,
        }
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
