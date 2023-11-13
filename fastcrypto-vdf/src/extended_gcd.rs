// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the extended Euclidean algorithm for [BigInt]`s.
//! Besides the gcd and the Bezout coefficients, it also returns the quotients of the two inputs
//! divided by the GCD since these are often used, for example in the NUCOMP and NUDPL algorithms,
//! and come out for free while computing the Bezout coefficients.

use num_bigint::{BigInt, BigUint, RandomBits, Sign};
use num_integer::Integer;
use num_modular::ModularUnaryOps;
use num_traits::{One, Signed, Zero};
use std::cmp::min;
use std::mem;
use std::ops::{BitOr, BitXor, Mul, Neg, Shr, Sub};

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
    if b < a {
        return extended_euclidean_algorithm(b, a).flip();
    }

    let mut s = (BigInt::zero(), BigInt::one());
    let mut t = (BigInt::one(), BigInt::zero());
    let mut r = (a.clone(), b.clone());

    while !r.0.is_zero() {
        let (q, r_prime) = r.1.div_rem(&r.0);
        r.1 = r.0;
        r.0 = r_prime;

        let f = |mut x: (BigInt, BigInt)| {
            mem::swap(&mut x.0, &mut x.1);
            x.0 -= &q * &x.1;
            x
        };
        s = f(s);
        t = f(t);
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

#[cfg(test)]
use rand::{Rng, SeedableRng};

pub fn exact_div_signed(a: &BigInt, b: &BigInt) -> BigInt {
    BigInt::from_biguint(
        a.sign() * b.sign(),
        exact_div(&a.magnitude(), &b.magnitude()),
    )
}

/// Algorithm from Jebelean (1993), "An algorithm for exact division", J. Symb. Comput. 15, 2.
pub fn exact_div(a: &BigUint, b: &BigUint) -> BigUint {
    let divisor_trailing_zeros = b.to_u32_digits()[0].trailing_zeros();

    let mut a_digits = a.shr(divisor_trailing_zeros as usize).to_u32_digits();
    let b_digits = b.shr(divisor_trailing_zeros as usize).to_u32_digits();

    let result_length = a_digits.len() - b_digits.len() + 1;
    let length = min(b_digits.len(), result_length);

    let b_prime = (b_digits[0] as u64).invm(&(1 << 32)).unwrap() as u32;

    let mut q = Vec::new();

    for k in 0..result_length {
        q.push(a_digits[k].wrapping_mul(b_prime));

        // Skip on last iteration
        if k < result_length - 1 {
            let j = min(length, result_length - k);
            let a_new_digits = BigUint::from_slice(&a_digits[k..])
                .sub(BigUint::from_slice(&b_digits[0..j]).mul(q[k]))
                .to_u32_digits();
            a_digits[k..].fill(0);
            a_digits[k..k + a_new_digits.len()].copy_from_slice(&a_new_digits);
        }
    }
    BigUint::from_slice(&q)
}

#[test]
fn test_exact_div() {
    let mut rng = rand_pcg::Pcg32::seed_from_u64(123);

    for _ in 0..1000 {
        let n: u64 = rng.gen_range(10..1000);
        let b: BigUint = rng.sample(RandomBits::new(n));

        let m: u64 = rng.gen_range(10..1000);
        let c: BigUint = rng.sample(RandomBits::new(m));

        let a: BigUint = b.clone() * c.clone();
        assert_eq!(c, exact_div(&a, &b));
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
