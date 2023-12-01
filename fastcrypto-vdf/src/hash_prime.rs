// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of a hash-to-prime function identical to the HashPrime
//! function from [chiavdf](https://github.com/Chia-Network/chiavdf/blob/bcc36af3a8de4d2fcafa571602040a4ebd4bdd56/src/proof_common.h#L14-L43).

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
    length_in_bytes: usize,
    bitmask: &[usize],
) -> BigInt {
    let mut sprout: Vec<u8> = vec![];
    sprout.extend_from_slice(seed);

    loop {
        let mut blob = vec![];
        while blob.len() < length_in_bytes {
            for i in (0..sprout.len()).rev() {
                sprout[i] = sprout[i].wrapping_add(1);
                if sprout[i] != 0 {
                    break;
                }
            }
            let hash = Sha256::digest(&sprout).digest;
            blob.extend_from_slice(&hash[..min(hash.len(), length_in_bytes - blob.len())]);
        }
        let mut x = BigUint::from_bytes_be(&blob);
        for b in bitmask {
            x.set_bit(*b as u64, true);
        }

        // The implementations of the primality test used below might be slightly different from the
        // one used by chiavdf, but since the risk of a false positive is very small (4^{-100}) this
        // is not an issue.
        if P::is_prime(&x) {
            return x.into();
        }
    }
}

/// Implementation of [hash_prime] using the primality test from `num_prime::nt_funcs::is_prime`.
pub fn hash_prime_default(seed: &[u8], length_in_bytes: usize, bitmask: &[usize]) -> BigInt {
    hash_prime::<DefaultPrimalityCheck>(seed, length_in_bytes, bitmask)
}

/// Implementation of the [PrimalityCheck] trait using the primality test from `num_prime::nt_funcs::is_prime`.
pub struct DefaultPrimalityCheck {}

impl PrimalityCheck for DefaultPrimalityCheck {
    fn is_prime(x: &BigUint) -> bool {
        num_prime::nt_funcs::is_prime(x, None).probably()
    }
}

#[cfg(test)]
mod tests {
    use crate::hash_prime::hash_prime_default;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_prime::PrimalityTestConfig;
    use std::str::FromStr;

    #[test]
    fn test_hash_prime() {
        let seed = [0u8; 32];
        let length = 64;
        let bitmask: [usize; 3] = [0, 1, 8 * length - 1];

        let prime = hash_prime_default(&seed, length, &bitmask)
            .to_biguint()
            .unwrap();

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
