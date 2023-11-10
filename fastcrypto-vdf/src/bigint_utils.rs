// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::{HashFunction, Sha256};
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_prime::PrimalityTestConfig;
use num_traits::{One, Signed, Zero};
use std::cmp::min;
use std::mem;
use std::ops::Neg;

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

pub fn hash_prime_default(
    seed: &[u8],
    length: usize,
    bitmask: &[usize],
) -> FastCryptoResult<BigInt> {
    hash_prime(seed, length, bitmask, |x| {
        num_prime::nt_funcs::is_prime(x, None).probably()
    })
}

/// Implementation of HashPrime from chiavdf (https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43):
/// Generates a random pseudo-prime using the hash and check method:
/// Randomly chooses x with bit-length `length`, then applies a mask
///   (for b in bitmask) { x |= (1 << b) }.
/// Then return x if it is a pseudo-prime, otherwise repeat.
///
/// The length must be a multiple of 8, otherwise `FastCryptoError::InvalidInput` is returned.
pub fn hash_prime<P: Fn(&BigUint) -> bool>(
    seed: &[u8],
    length: usize,
    bitmask: &[usize],
    primality_test: P,
) -> FastCryptoResult<BigInt> {
    if length % 8 != 0 {
        return Err(InvalidInput);
    }

    let mut sprout: Vec<u8> = vec![];
    sprout.extend_from_slice(seed);

    loop {
        let mut blob = vec![];
        while blob.len() * 8 < length {
            for i in (0..sprout.len()).rev() {
                sprout[i] = sprout[i].wrapping_add(1);
                if sprout[i] != 0 {
                    break;
                }
            }
            let hash = Sha256::digest(&sprout).digest;
            blob.extend_from_slice(&hash[..min(hash.len(), length / 8 - blob.len())]);
        }
        let mut x = BigUint::from_bytes_be(&blob);
        for b in bitmask {
            x.set_bit(*b as u64, true);
        }

        // The implementations of the primality test used below might be slightly different from the
        // one used by chiavdf, but since the risk of a false positive is very small (4^{-100}) this
        // is not an issue.
        if primality_test(&x) {
            return Ok(x.into());
        }
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
