// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the extended Euclidean algorithm for [BigInt]`s.
//! Besides the gcd and the Bezout coefficients, it also returns the quotients of the two inputs
//! divided by the GCD since these are often used, for example in the NUCOMP and NUDPL algorithms,
//! and come out for free while computing the Bezout coefficients.

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rand::{thread_rng, RngCore};
use std::cmp::min;
use std::ops::ShrAssign;

/// The output of the extended Euclidean algorithm on inputs `a` and `b`: The Bezout coefficients `x`
/// and `y` such that `ax + by = gcd`. The quotients `a / gcd` and `b / gcd` are also returned.
pub struct EuclideanAlgorithmOutput {
    pub gcd: BigInt,
    pub x: BigInt,
    pub y: BigInt,
    pub a_divided_by_gcd: BigInt,
    pub b_divided_by_gcd: BigInt,
}

#[inline]
fn odd_part(x: &mut BigInt) -> u64 {
    if x.is_odd() {
        return 0;
    }
    let s = x.trailing_zeros().unwrap();
    x.shr_assign(s);
    s
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
pub fn extended_euclidean_algorithm(a: &BigInt, b: &BigInt) -> EuclideanAlgorithmOutput {
    if a.is_zero() {
        return EuclideanAlgorithmOutput {
            gcd: b.clone(),
            x: BigInt::zero(),
            y: BigInt::one(),
            a_divided_by_gcd: BigInt::zero(),
            b_divided_by_gcd: BigInt::one(),
        };
    } else if b.is_zero() {
        return EuclideanAlgorithmOutput {
            gcd: a.clone(),
            x: BigInt::one(),
            y: BigInt::zero(),
            a_divided_by_gcd: BigInt::one(),
            b_divided_by_gcd: BigInt::zero(),
        };
    } else if a.is_negative() {
        let result = extended_euclidean_algorithm(&-a, b);
        return EuclideanAlgorithmOutput {
            gcd: result.gcd,
            x: -result.x,
            y: result.y,
            a_divided_by_gcd: -result.a_divided_by_gcd,
            b_divided_by_gcd: result.b_divided_by_gcd,
        };
    } else if b.is_negative() {
        let result = extended_euclidean_algorithm(a, &-b);
        return EuclideanAlgorithmOutput {
            gcd: result.gcd,
            x: result.x,
            y: -result.y,
            a_divided_by_gcd: result.a_divided_by_gcd,
            b_divided_by_gcd: -result.b_divided_by_gcd,
        };
    }

    // From here, we may assume that both inputs are positive integers.
    if a < b {
        return extended_euclidean_algorithm(b, a).flip();
    }

    let (q, r) = a.div_rem(&b);
    if r.is_zero() {
        return EuclideanAlgorithmOutput {
            gcd: b.clone(),
            x: BigInt::zero(),
            y: BigInt::one(),
            a_divided_by_gcd: q,
            b_divided_by_gcd: BigInt::one(),
        };
    }

    let mut s = (BigInt::one(), BigInt::zero());
    let mut t = (BigInt::zero(), BigInt::one());

    let mut u = r;
    let mut v = b.clone();

    let u_zeros = odd_part(&mut u);
    let v_zeros = odd_part(&mut v);
    let zeros = min(u_zeros, v_zeros);

    let mut shifts = u_zeros.abs_diff(v_zeros);
    if u_zeros > v_zeros {
        t.1 <<= shifts;
    } else if u_zeros < v_zeros {
        s.0 <<= shifts;
    };

    while &u != &v {
        let zeros;
        if u > v {
            u -= &v;
            zeros = odd_part(&mut u);
            t.0 += &t.1;
            t.1 <<= zeros;
            s.0 += &s.1;
            s.1 <<= zeros;
        } else {
            v -= &u;
            zeros = odd_part(&mut v);
            t.1 += &t.0;
            t.0 <<= zeros;
            s.1 += &s.0;
            s.0 <<= zeros;
        }
        shifts += zeros;
    }

    let ug = &t.0 + &t.1;
    let vg = &s.0 + &s.1;

    for _ in 0..shifts {
        if s.0.is_odd() | t.0.is_odd() {
            s.0 += &vg;
            t.0 += &ug;
        }
        // TODO: 35% of the time, the following two lines are executed
        s.0 >>= 1;
        t.0 >>= 1;
    }

    if &s.0 * 2 > vg {
        s.0 -= &vg;
        t.0 -= &ug;
    }

    EuclideanAlgorithmOutput {
        gcd: u << zeros,
        y: -t.0 - &q * &s.0,
        x: s.0,
        a_divided_by_gcd: ug + &q * &vg,
        b_divided_by_gcd: vg,
    }
}

#[test]
fn test_xgcd() {
    test_xgcd_single(BigInt::from(240), BigInt::from(46));
    test_xgcd_single(BigInt::from(-240), BigInt::from(46));
    test_xgcd_single(BigInt::from(240), BigInt::from(-46));
    test_xgcd_single(BigInt::from(-240), BigInt::from(-46));
}

#[test]
fn test_large_xgcd() {
    let bytes = 1024;

    for _ in 0..1000 {
        let mut a_bytes = vec![0u8; bytes];
        thread_rng().fill_bytes(&mut a_bytes);
        let a = BigInt::from_bytes_be(Sign::Plus, &a_bytes);

        let mut b_bytes = vec![0u8; bytes];
        thread_rng().fill_bytes(&mut b_bytes);
        let b = BigInt::from_bytes_be(Sign::Plus, &b_bytes);
        test_xgcd_single(a, b);
    }
}

#[cfg(test)]
fn test_xgcd_single(a: BigInt, b: BigInt) {
    let output = extended_euclidean_algorithm(&a, &b);
    assert_eq!(output.gcd, a.gcd(&b));
    assert_eq!(&output.x * &a + &output.y * &b, output.gcd);
    assert_eq!(output.a_divided_by_gcd, &a / &output.gcd);
    assert_eq!(output.b_divided_by_gcd, &b / &output.gcd);
}
