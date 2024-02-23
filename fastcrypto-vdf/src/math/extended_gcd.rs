// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the extended Euclidean algorithm for [BigInt]`s.
//! Besides the gcd and the Bezout coefficients, it also returns the quotients of the two inputs
//! divided by the GCD since these are often used, for example in the NUCOMP and NUDPL algorithms,
//! and come out for free while computing the Bezout coefficients.

use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::mem;
use std::ops::Neg;

/// The output of the extended Euclidean algorithm on inputs `a` and `b`: The Bezout coefficients `x`
/// and `y` such that `ax + by = gcd`. The quotients `a / gcd` and `b / gcd` are also returned.
pub struct EuclideanAlgorithmOutputPartial {
    pub gcd: BigInt,
    pub y: BigInt,
    pub a_divided_by_gcd: BigInt,
    pub b_divided_by_gcd: BigInt,
}

impl EuclideanAlgorithmOutputPartial {
    fn neg(self) -> Self {
        Self {
            gcd: -self.gcd,
            y: -self.y,
            a_divided_by_gcd: self.a_divided_by_gcd,
            b_divided_by_gcd: self.b_divided_by_gcd,
        }
    }
}

/// The output of the extended Euclidean algorithm on inputs `a` and `b`: The Bezout coefficients `x`
/// and `y` such that `ax + by = gcd`. The quotients `a / gcd` and `b / gcd` are also returned.
pub struct EuclideanAlgorithmOutput {
    pub gcd: BigInt,
    pub x: BigInt,
    pub y: BigInt,
    pub a_divided_by_gcd: BigInt,
    pub b_divided_by_gcd: BigInt,
}

impl EuclideanAlgorithmOutput {
    fn neg(self) -> Self {
        Self {
            gcd: -self.gcd,
            x: -self.x,
            y: -self.y,
            a_divided_by_gcd: self.a_divided_by_gcd,
            b_divided_by_gcd: self.b_divided_by_gcd,
        }
    }
}

/// Compute the greatest common divisor gcd of a and b. The output also returns the Bezout coefficients
/// x and y such that ax + by = gcd and also the quotients a / gcd and b / gcd.
pub fn extended_euclidean_algorithm(a: &BigInt, b: &BigInt) -> EuclideanAlgorithmOutput {
    let mut s = (BigInt::zero(), BigInt::one());
    let mut t = (BigInt::one(), BigInt::zero());
    let mut r = (a.clone(), b.clone());

    while !r.0.is_zero() {
        let (q, r_prime) = r.1.div_rem(&r.0);
        r.1 = r.0;
        r.0 = r_prime;

        mem::swap(&mut s.0, &mut s.1);
        s.0 -= &q * &s.1;

        mem::swap(&mut t.0, &mut t.1);
        t.0 -= &q * &t.1;
    }

    // The last coefficients are equal to +/- a / gcd(a,b) and b / gcd(a,b) respectively.
    let a_divided_by_gcd = if a.sign() != s.0.sign() {
        s.0.neg()
    } else {
        s.0
    };
    let b_divided_by_gcd = if b.sign() != t.0.sign() {
        t.0.neg()
    } else {
        t.0
    };

    let negate = r.1.is_negative();
    let result = EuclideanAlgorithmOutput {
        gcd: r.1,
        x: t.1,
        y: s.1,
        a_divided_by_gcd,
        b_divided_by_gcd,
    };
    if negate {
        result.neg()
    } else {
        result
    }
}

/// Compute the greatest common divisor gcd of a and b. The output also returns only the Bezout coefficients for b and
/// but also the quotients a / gcd and b / gcd.
pub fn extended_euclidean_algorithm_partial(
    a: &BigInt,
    b: &BigInt,
) -> EuclideanAlgorithmOutputPartial {
    let mut s = (BigInt::zero(), BigInt::one());
    let mut r = (a.clone(), b.clone());

    while !r.0.is_zero() {
        let (q, r_prime) = r.1.div_rem(&r.0);
        r.1 = r.0;
        r.0 = r_prime;

        mem::swap(&mut s.0, &mut s.1);
        s.0 -= &q * &s.1;
    }

    // The last coefficients are equal to +/- a / gcd(a,b) and b / gcd(a,b) respectively.
    let a_divided_by_gcd = if a.sign() != s.0.sign() { -s.0 } else { s.0 };
    let negate = r.1.is_negative();
    let b_divided_by_gcd = if negate { -b / &r.1 } else { b / &r.1 };
    let result = EuclideanAlgorithmOutputPartial {
        gcd: r.1,
        y: s.1,
        a_divided_by_gcd,
        b_divided_by_gcd,
    };
    if negate {
        result.neg()
    } else {
        result
    }
}

#[test]
fn test_xgcd() {
    test_xgcd_single(BigInt::from(240), BigInt::from(46));
    test_xgcd_single(BigInt::from(-240), BigInt::from(46));
    test_xgcd_single(BigInt::from(240), BigInt::from(-46));
    test_xgcd_single(BigInt::from(-240), BigInt::from(-46));
}

#[cfg(test)]
fn test_xgcd_single(a: BigInt, b: BigInt) {
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd(&b));
    assert_eq!(&output.x * &a + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, &a / &output.gcd);
    assert_eq!(output.b_divided_by_gcd, &b / &output.gcd);
}
