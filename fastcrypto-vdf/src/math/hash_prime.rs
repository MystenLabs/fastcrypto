// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of a hash-to-prime function identical to the HashPrime
//! function from [chiavdf](https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43).
use fastcrypto::hash::{HashFunction, Sha256};
use num_bigint::BigUint;
use num_prime::nt_funcs::is_prime;
use num_prime::PrimalityTestConfig;
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

/// Implementation of HashPrime from chiavdf ():
/// Generates a random pseudo-prime using the hash and check method:
/// Randomly chooses x with bit-length `length`, then applies a mask
///   (for b in bitmask) { x |= (1 << b) }.
/// Then return x if it is a pseudo-prime, otherwise repeat.
pub(crate) fn hash_prime(seed: &[u8], length_in_bytes: usize, bitmask: &[usize]) -> BigUint {
    let mut iterator = HashPrimeIterator {
        seed: seed.to_vec(),
        length_in_bytes,
        bitmask: bitmask.to_vec(),
    };
    iterator.find(is_probable_prime).unwrap()
}

/// Check if the input is a probable prime.
///
/// We use the Baillie-PSW primality test here. This is in accordance with the recommendations of "Prime and
/// Prejudice: Primality Testing Under Adversarial Conditions" by Albrecht et al. (https://eprint.iacr.org/2018/749)
/// because this test is also used in use cases where an adversary could influence the input.
pub fn is_probable_prime(x: &BigUint) -> bool {
    is_prime(x, Some(PrimalityTestConfig::bpsw())).probably()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_prime::PrimalityTestConfig;
    use std::str::FromStr;

    #[test]
    fn test_hash_prime() {
        let seed = [0u8; 32];
        let length = 64;
        let bitmask: [usize; 3] = [0, 1, 8 * length - 1];

        let prime = hash_prime(&seed, length, &bitmask);

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
}
