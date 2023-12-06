// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of a hash-to-prime function identical to the HashPrime
//! function from [chiavdf](https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43).

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::hash::{HashFunction, Sha256};
use num_bigint::BigUint;
use num_prime::nt_funcs::is_prime;
use std::cmp::min;

struct HashPrimeIterator {
    seed: Vec<u8>,
    length_in_bytes: usize,
    bitmask: Vec<usize>,
}

impl Iterator for HashPrimeIterator {
    type Item = BigUint;

    fn next(&mut self) -> Option<Self::Item> {
        let mut blob = vec![];
        while blob.len() < self.length_in_bytes {
            for i in (0..self.seed.len()).rev() {
                self.seed[i] = self.seed[i].wrapping_add(1);
                if self.seed[i] != 0 {
                    break;
                }
            }
            let hash = Sha256::digest(&self.seed).digest;
            blob.extend_from_slice(&hash[..min(hash.len(), self.length_in_bytes - blob.len())]);
        }
        let mut x = BigUint::from_bytes_be(&blob);
        for b in &self.bitmask {
            x.set_bit(*b as u64, true);
        }
        Some(x)
    }
}

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
    length_in_bytes: usize,
    bitmask: &[usize],
) -> BigUint {
    hash_prime_with_certificate::<P>(seed, length_in_bytes, bitmask).1
}

pub fn hash_prime_with_certificate<P: PrimalityCheck>(
    seed: &[u8],
    length_in_bytes: usize,
    bitmask: &[usize],
) -> (usize, BigUint) {
    let iterator = HashPrimeIterator {
        seed: seed.to_vec(),
        length_in_bytes,
        bitmask: bitmask.to_vec(),
    };
    iterator.enumerate().find(|(_, x)| P::is_prime(x)).unwrap()
}

/// Verify that the given prime is a prime and has the given index in the hash prime iterator.
pub fn verify_prime<P: PrimalityCheck>(
    seed: &[u8],
    length_in_bytes: usize,
    bitmask: &[usize],
    prime: &(usize, BigUint),
) -> FastCryptoResult<()> {
    let mut iterator = HashPrimeIterator {
        seed: seed.to_vec(),
        length_in_bytes,
        bitmask: bitmask.to_vec(),
    };
    // Check that the original index points to a prime
    let original_prime = iterator.nth(prime.0).expect("Iterator is infinite");
    if P::is_prime(&original_prime) && original_prime == prime.1 {
        return Ok(());
    }
    Err(FastCryptoError::InvalidProof)
}

/// Assuming that the prime has passed a [verify_prime], this verifies that the complaint represents
/// a prime prior to the given prime in the iterator, eg. that the complaint is valid.
pub fn verify_complaint<P: PrimalityCheck>(
    seed: &[u8],
    length_in_bytes: usize,
    bitmask: &[usize],
    prime: &(usize, BigUint),
    complaint: &usize,
) -> FastCryptoResult<()> {
    let mut iterator = HashPrimeIterator {
        seed: seed.to_vec(),
        length_in_bytes,
        bitmask: bitmask.to_vec(),
    };

    if complaint >= &prime.0 {
        return Err(FastCryptoError::InvalidInput);
    }

    // Check that the complaint index points to a prime
    let complaint_prime = iterator.nth(*complaint).expect("Iterator is infinite");
    if !P::is_prime(&complaint_prime) {
        return Err(FastCryptoError::InvalidProof);
    }

    Ok(())
}

/// Implementation of [hash_prime] using the primality test from `num_prime::nt_funcs::is_prime`.
pub fn hash_prime_default(seed: &[u8], length_in_bytes: usize, bitmask: &[usize]) -> BigUint {
    hash_prime::<DefaultPrimalityCheck>(seed, length_in_bytes, bitmask)
}

/// Implementation of the [PrimalityCheck] trait using the primality test from `num_prime::nt_funcs::is_prime`.
pub struct DefaultPrimalityCheck {}

impl PrimalityCheck for DefaultPrimalityCheck {
    fn is_prime(x: &BigUint) -> bool {
        is_prime(x, None).probably()
    }
}

#[cfg(test)]
mod tests {
    use crate::hash_prime::{
        hash_prime_default, verify_complaint, verify_prime, DefaultPrimalityCheck,
        HashPrimeIterator, PrimalityCheck,
    };
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_prime::PrimalityTestConfig;
    use std::str::FromStr;

    #[test]
    fn test_hash_prime() {
        let seed = [0u8; 32];
        let length = 64;
        let bitmask: [usize; 3] = [0, 1, 8 * length - 1];

        let prime = hash_prime_default(&seed, length, &bitmask);

        // Prime has right length
        assert_eq!((length * 8) as u64, prime.bits());

        // The last two bits are set (see bitmask)
        assert_eq!(BigUint::from(3u64), prime.mod_floor(&BigUint::from(4u64)));

        // The result is a prime, even when checking with a stricter test
        assert!(
            num_prime::nt_funcs::is_prime(&prime, Some(PrimalityTestConfig::strict())).probably()
        );

        // Regression test
        assert_eq!(prime, BigUint::from_str("7904272817142338150419757415334055106926417574777773392214522399425467199262039794276651240832053626391864792937889238336287002167559810128294881253078163").unwrap());
    }

    #[test]
    fn test_hash_prime_complaints() {
        let seed = [0u8; 32];
        let length_in_bytes = 64;
        let bitmask: [usize; 3] = [0, 1, 8 * length_in_bytes - 1];

        let iterator = HashPrimeIterator {
            seed: seed.to_vec(),
            length_in_bytes,
            bitmask: bitmask.to_vec(),
        }
        .enumerate();

        let mut candidates = vec![];

        for (i, x) in iterator.take(1000) {
            if DefaultPrimalityCheck::is_prime(&x) {
                candidates.push((i, x));
            }
        }

        for candidate in &candidates {
            assert!(verify_prime::<DefaultPrimalityCheck>(
                &seed,
                length_in_bytes,
                &bitmask,
                candidate
            )
            .is_ok());
        }

        assert!(verify_complaint::<DefaultPrimalityCheck>(
            &seed,
            length_in_bytes,
            &bitmask,
            &candidates[1],
            &candidates[0].0
        )
        .is_ok());
        assert!(verify_complaint::<DefaultPrimalityCheck>(
            &seed,
            length_in_bytes,
            &bitmask,
            &candidates[2],
            &candidates[1].0
        )
        .is_ok());
        assert!(verify_complaint::<DefaultPrimalityCheck>(
            &seed,
            length_in_bytes,
            &bitmask,
            &candidates[0],
            &candidates[1].0
        )
        .is_err());
    }
}
