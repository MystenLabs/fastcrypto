// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::{HashFunction, Sha256};
use num_bigint::{BigInt, Sign};
use num_prime::nt_funcs::is_prime;
use std::cmp::min;

/// Size of the random prime modulus B used in proving and verification.
pub const B_BITS: usize = 264;

struct PrimeCandidates {
    sprout: Vec<u8>,
    bitmask: Vec<usize>,
    length: usize,
}

impl PrimeCandidates {
    fn new(seed: &[u8], length: usize, bitmask: &[usize]) -> FastCryptoResult<Self> {
        if length % 8 != 0 {
            return Err(InvalidInput);
        }

        Ok(Self {
            sprout: seed.to_vec(),
            bitmask: bitmask.to_vec(),
            length,
        })
    }

    /// Returns true if a candidate is one of the next `upper_limit` candidates.
    fn check_candidate(&mut self, candidate: &BigInt, upper_limit: usize) -> bool {
        for _ in 0..upper_limit {
            if candidate == &self.next_candidate() {
                return true;
            }
        }
        false
    }

    /// Returns the next candidate.
    fn next_candidate(&mut self) -> BigInt {
        let mut blob = vec![];
        while blob.len() * 8 < self.length {
            for i in (0..self.sprout.len()).rev() {
                self.sprout[i] = self.sprout[i].wrapping_add(1);
                if self.sprout[i] != 0 {
                    break;
                }
            }
            let hash = Sha256::digest(&self.sprout).digest;
            blob.extend_from_slice(&hash[..min(hash.len(), self.length / 8 - blob.len())]);
        }
        let mut x = BigInt::from_bytes_be(Sign::Plus, &blob);
        for b in &self.bitmask {
            x.set_bit(*b as u64, true);
        }
        x
    }
}

/// Implementation of HashPrime from chiavdf (https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43):
/// Generates a random pseudo-prime using the hash and check method:
/// Randomly chooses x with bit-length `length`, then applies a mask
///   (for b in bitmask) { x |= (1 << b) }.
/// Then return x if it is a pseudo-prime, otherwise repeat.
///
/// The length must be a multiple of 8, otherwise `FastCryptoError::InvalidInput` is returned.
pub fn hash_prime(seed: &[u8], length: usize, bitmask: &[usize]) -> FastCryptoResult<BigInt> {
    let mut prime_candidates = PrimeCandidates::new(seed, length, bitmask)?;
    loop {
        let x = prime_candidates.next_candidate();

        // The implementations of the primality test used below might be slightly different from the
        // one used by chiavdf, but since the risk of a false positive is very small (4^{-100}) this
        // is not an issue.
        if is_prime(&x.to_biguint().unwrap(), None).probably() {
            return Ok(x);
        }
    }
}

/// Verify that the given number is a valid candidate and a prime.
pub fn verify_prime(p: &BigInt, seed: &[u8], bitmask: &[usize]) -> FastCryptoResult<bool> {
    let length = p.bits() as usize;
    let mut prime_candidates = PrimeCandidates::new(seed, length, bitmask).unwrap();
    let upper_limit = compute_upper_limit(length)?;
    if !prime_candidates.check_candidate(p, upper_limit) {
        return Ok(false);
    }
    Ok(is_prime(&p.to_biguint().unwrap(), None).probably())
}

/// Compute the number of candidates to check for a given bit length. This was chosen such that the
/// probability of all candidates being composite is less than 2^{-40}.
fn compute_upper_limit(bit_length: usize) -> FastCryptoResult<usize> {
    match bit_length {
        1024 => Ok(10_000),
        2048 => Ok(20_000),
        _ => Err(InvalidInput),
    }
}
