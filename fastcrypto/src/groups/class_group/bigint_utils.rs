// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Zero};
use std::mem;
use std::ops::Neg;

pub struct EuclideanAlgorithmOutput {
    pub gcd: BigInt,
    pub x: BigInt,
    pub y: BigInt,
    pub a_divided_by_gcd: BigInt,
    pub b_divided_by_gcd: BigInt,
}

/// Compute the greatest common divisor gcd of a and b. The output also returns the Bezout coefficients
/// x and y such that ax + by = gcd and also the quotients a / gcd and b / gcd.
pub fn extended_euclidean_algorithm(a: &BigInt, b: &BigInt) -> EuclideanAlgorithmOutput {
    let mut s = (BigInt::zero(), BigInt::one());
    let mut t = (BigInt::one(), BigInt::zero());
    let mut r = (a.clone(), b.clone());

    while !r.0.is_zero() {
        let q = &r.1 / &r.0;
        let f = |mut r: (BigInt, BigInt)| {
            mem::swap(&mut r.0, &mut r.1);
            r.0 = r.0 - &q * &r.1;
            r
        };
        r = f(r);
        s = f(s);
        t = f(t);
    }

    // The last coefficients are equal to +/- a / gcd(a,b) and b / gcd(a,b) respectively.
    let a_divided_by_gcd = if a.sign() != s.0.sign() { -s.0 } else { s.0 };
    let b_divided_by_gcd = if b.sign() != t.0.sign() { -t.0 } else { t.0 };

    if r.1 >= BigInt::zero() {
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
    let a = BigInt::from(240);
    let b = BigInt::from(46);
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd(&b));
    assert_eq!(&output.x * &a + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, &a / &output.gcd);
    assert_eq!(output.b_divided_by_gcd, &b / &output.gcd);

    let a = BigInt::from(240);
    let b = BigInt::from(-46);
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd(&b));
    assert_eq!(&output.x * &a + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, &a / &output.gcd);
    assert_eq!(output.b_divided_by_gcd, &b / &output.gcd);

    let a = BigInt::from(-240);
    let b = BigInt::from(-46);
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd(&b));
    assert_eq!(&output.x * &a + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, &a / &output.gcd);
    assert_eq!(output.b_divided_by_gcd, &b / &output.gcd);
}
