// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the extended Euclidean algorithm for [BigInt]`s.
//! Besides the gcd and the Bezout coefficients, it also returns the quotients of the two inputs
//! divided by the GCD since these are often used, for example in the NUCOMP and NUDPL algorithms,
//! and come out for free while computing the Bezout coefficients.

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use std::mem;

/// The output of the extended Euclidean algorithm on inputs `a` and `b`: The Bezout coefficients `x`
/// and `y` such that `ax + by = gcd`. The quotients `a / gcd` and `b / gcd` are also returned.
/// Note that `x` is optional and only computed in [extended_euclidean_algorithm] if `compute_x` is true.
pub struct EuclideanAlgorithmOutput {
    pub gcd: BigInt,
    pub x: Option<BigInt>,
    pub y: BigInt,
    pub a_divided_by_gcd: BigInt,
    pub b_divided_by_gcd: BigInt,
}

/// Compute the greatest common divisor gcd of a and b. The output also returns the Bezout coefficients
/// x and y such that ax + by = gcd and also the quotients a / gcd and b / gcd.
/// Note that `x` is only computed if `compute_x` is true.
pub(crate) fn extended_euclidean_algorithm(
    a: &BigInt,
    b: &BigInt,
    compute_x: bool,
) -> EuclideanAlgorithmOutput {
    let mut s = (BigInt::zero(), BigInt::one());
    let mut t = (BigInt::one(), BigInt::zero());
    let mut r = (a.clone(), b.clone());

    while !r.0.is_zero() {
        let (q, r_prime) = r.1.div_rem(&r.0);
        r.1 = mem::replace(&mut r.0, r_prime);

        mem::swap(&mut s.0, &mut s.1);
        s.0 -= &q * &s.1;

        if compute_x {
            mem::swap(&mut t.0, &mut t.1);
            t.0 -= &q * &t.1;
        }
    }

    // The last coefficients are equal to +/- a / gcd(a,b) and b / gcd(a,b) respectively.
    let a_divided_by_gcd = with_sign(s.0, a.sign());

    let negate = r.1.is_negative();
    let gcd = conditional_negate(negate, r.1);
    let y = conditional_negate(negate, s.1);

    let (x, b_divided_by_gcd) = if compute_x {
        (
            Some(conditional_negate(negate, t.1)),
            with_sign(t.0, b.sign()),
        )
    } else {
        // If the t coefficients have not been computed, we can compute b_divided_by_gcd directly.
        (None, b / &gcd)
    };

    EuclideanAlgorithmOutput {
        gcd,
        x,
        y,
        a_divided_by_gcd,
        b_divided_by_gcd,
    }
}

/// Return a number with the same magnitude as `value` but with the given sign.
#[inline]
fn with_sign(value: BigInt, sign: Sign) -> BigInt {
    BigInt::from_biguint(sign, value.into_parts().1)
}

/// Return `-value` if `negate` is true, otherwise return `value`.
#[inline]
fn conditional_negate(negate: bool, value: BigInt) -> BigInt {
    if negate {
        -value
    } else {
        value
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
    let output = extended_euclidean_algorithm(&a, &b, true);
    assert_eq!(output.gcd, a.gcd(&b));
    assert_eq!(&output.x.unwrap() * &a + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, &a / &output.gcd);
    assert_eq!(output.b_divided_by_gcd, &b / &output.gcd);

    let output = extended_euclidean_algorithm(&a, &b, false);
    assert_eq!(output.gcd, a.gcd(&b));
    assert!(output.x.is_none());
    assert_eq!(output.a_divided_by_gcd, &a / &output.gcd);
    assert_eq!(output.b_divided_by_gcd, &b / &output.gcd);
}
