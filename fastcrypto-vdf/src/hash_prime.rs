// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of a hash-to-prime function identical to the HashPrime
//! function from [chiavdf](https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43).

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::{HashFunction, Sha256};
use num_bigint::{BigInt, BigUint};
use std::cmp::min;

/// Implementation of a probabilistic primality test.
pub trait PrimalityCheck {
    /// Return true if `x` is probably a prime. If `false` is returned, `x` is guaranteed to be composite.
    fn is_prime(x: &BigUint) -> bool;
}

/// Implementation of HashPrime from chiavdf ():
/// Generates a random pseudo-prime using the hash and check method:
/// Randomly chooses x with bit-length `length`, then applies a mask
///   (for b in bitmask) { x |= (1 << b) }.
/// Then return x if it is a pseudo-prime, otherwise repeat.
///
/// The length must be a multiple of 8, otherwise `FastCryptoError::InvalidInput` is returned.
pub fn hash_prime<P: PrimalityCheck>(
    seed: &[u8],
    length: usize,
    bitmask: &[usize],
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
        if P::is_prime(&x) {
            return Ok(x.into());
        }
    }
}

/// Implementation of [hash_prime] using the primality test from `num_prime::nt_funcs::is_prime`.
pub fn hash_prime_default(
    seed: &[u8],
    length: usize,
    bitmask: &[usize],
) -> FastCryptoResult<BigInt> {
    hash_prime::<DefaultPrimalityCheck>(seed, length, bitmask)
}

/// Implementation of the [PrimalityCheck] trait using the primality test from `num_prime::nt_funcs::is_prime`.
pub struct DefaultPrimalityCheck {}

impl PrimalityCheck for DefaultPrimalityCheck {
    fn is_prime(x: &BigUint) -> bool {
        num_prime::nt_funcs::is_prime(x, None).probably()
    }
}
