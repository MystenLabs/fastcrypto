// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Version 2 of the hash-to-class-group function. This implements the algorithm from
//! https://eprint.iacr.org/2024/295.pdf, where the `a` coordinate of the output is a product of one
//! large prime and `k` smaller primes.
//!
//! The difference to [crate::class_group::hash] is that this version samples the prime factors with
//! different sizes. The security against precomputation attacks is determined by the size of the
//! *largest* factor, but the size of the image is determined by the *product* of all the factors, so
//! for a given image size it is better to have one large factor and a number of small ones than to
//! have factors of equal size.

use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use num_traits::{One, Signed};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::ops::{Shl, Shr};

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::math::crt::solve_congruence_equation_system;
use crate::math::hash_prime::is_probable_prime;
use crate::math::jacobi;
use crate::math::modular_sqrt::modular_square_root;

/// The security parameter in bits. The large prime factor is sampled from a set of this size, so an
/// adversary needs to precompute the VDF on this many quadratic forms to be able to compute the VDF
/// quickly on any input. The image of the hash function is ~2^{2*SECURITY_PARAMETER_IN_BITS} / k!
/// which makes the hash function collision resistant.
const SECURITY_PARAMETER_IN_BITS: u64 = 128;

/// The number of small prime factors, called k in the paper. The benchmarks show that the running
/// time keeps decreasing up to k = 3, after which the sampling of the large prime factor dominates
/// and there is no further benefit. Increasing k also divides the size of the image by k!, so there
/// is no reason to go higher.
const DEFAULT_SMALL_PRIME_FACTORS: u64 = 3;

impl QuadraticForm {
    /// Generate a random quadratic form from a seed with the given discriminant. This method is
    /// deterministic, and it is a random oracle on a large subset of the class group.
    ///
    /// This method returns an [InvalidInput] error if the discriminant is too small for the default
    /// parameters to give a reduced form, and it may also happen if the discriminant is not a prime.
    pub fn hash_to_group_v2_with_default_parameters(
        seed: &[u8],
        discriminant: &Discriminant,
    ) -> FastCryptoResult<Self> {
        hash_to_group_v2_with_custom_parameters(
            seed,
            discriminant,
            SECURITY_PARAMETER_IN_BITS,
            DEFAULT_SMALL_PRIME_FACTORS,
        )
    }
}

/// Generate a random quadratic form from a seed with the given discriminant and custom parameters.
///
/// The `a` coordinate of the output is a product of one prime sampled from a set of size
/// 2^`security_parameter_in_bits` and `small_prime_factors` primes each sampled from a set of size
/// 2^(`security_parameter_in_bits` / `small_prime_factors`), so the image has size
/// ~2^(2 * `security_parameter_in_bits`) / `small_prime_factors`!.
///
/// Setting `small_prime_factors` to zero gives a single prime factor sampled from a set of size
/// 2^`security_parameter_in_bits`. This is only intended for benchmarking against a single-prime
/// baseline, since the image is then only 2^`security_parameter_in_bits` large.
///
/// An [InvalidInput] error is returned if the parameters do not guarantee that the output is
/// reduced, or if the discriminant is not a negative prime.
pub fn hash_to_group_v2_with_custom_parameters(
    seed: &[u8],
    discriminant: &Discriminant,
    security_parameter_in_bits: u64,
    small_prime_factors: u64,
) -> FastCryptoResult<QuadraticForm> {
    // The number of bits needed for the sets the factors are sampled from to have the sizes above.
    let large_factor_bits = bits_for_set_size(security_parameter_in_bits)?;
    let small_factor_bits = if small_prime_factors > 0 {
        bits_for_set_size(security_parameter_in_bits.div_ceil(small_prime_factors))?
    } else {
        0
    };

    // Ensure that the result is reduced. The `a` coordinate is smaller than 2^total_bits, and by
    // Lemma 1 in the paper, the form is reduced if this is smaller than sqrt(|discriminant|) / 2.
    let total_bits = small_prime_factors
        .checked_mul(small_factor_bits)
        .and_then(|small_bits| large_factor_bits.checked_add(small_bits))
        .ok_or(InvalidInput)?;
    if discriminant.as_bigint().abs().sqrt().shr(1) <= BigInt::one().shl(total_bits) {
        return Err(InvalidInput);
    }

    // Sample a and b such that a has the prime factorization described above and b is a square root
    // of the discriminant modulo a.
    let (a, mut b) = sample_modulus_v2(
        seed,
        discriminant,
        large_factor_bits,
        small_factor_bits,
        small_prime_factors,
    )?;

    // b must be odd but may be negative
    if b.is_even() {
        b -= &a;
    }

    QuadraticForm::from_a_b_and_discriminant(a, b, discriminant)
}

/// Sample one prime smaller than 2^`large_factor_bits` and `small_prime_factors` primes smaller than
/// 2^`small_factor_bits`, all distinct and all having the discriminant as a quadratic residue, and
/// return their product along with a square root of the discriminant modulo this product.
fn sample_modulus_v2(
    seed: &[u8],
    discriminant: &Discriminant,
    large_factor_bits: u64,
    small_factor_bits: u64,
    small_prime_factors: u64,
) -> FastCryptoResult<(BigInt, BigInt)> {
    // Seed a rng with the hash of the seed
    let mut rng = ChaCha8Rng::from_seed(Sha256::digest(seed).digest);

    let factor_count = small_prime_factors as usize + 1;
    let mut factors = Vec::with_capacity(factor_count);
    let mut square_roots = Vec::with_capacity(factor_count);

    // The first factor is the large one, the remaining ones are small.
    for i in 0..factor_count {
        let bits = if i == 0 {
            large_factor_bits
        } else {
            small_factor_bits
        };

        let mut factor;
        loop {
            factor = sample_odd_number(bits, &mut rng);

            // The factors must be distinct for the Chinese Remainder Theorem to apply, and the
            // image size in the paper assumes it.
            if factors.contains(&factor) {
                continue;
            }

            // The primality check does not try divisions with small primes, so we do it here. This
            // speeds up the algorithm significantly. This also rejects the small primes themselves,
            // which is intended: the factors must be odd primes for the Jacobi symbol below to be a
            // Legendre symbol and for the parity adjustment of b to be valid.
            if PRIMES.iter().any(|p| factor.is_multiple_of(p)) {
                continue;
            }

            if jacobi::jacobi(discriminant.as_bigint(), &factor)
                .expect("factor is odd and positive")
                == 1
                && is_probable_prime(factor.magnitude())
            {
                // Found a valid factor
                break;
            }
        }
        // This only fails if the discriminant is not prime.
        let square_root = modular_square_root(discriminant.as_bigint(), &factor, false)
            .map_err(|_| InvalidInput)?;
        factors.push(factor);
        square_roots.push(square_root);
    }

    let result = factors.iter().product();
    let square_root = solve_congruence_equation_system(&square_roots, &factors)
        .expect("The factors are distinct primes");

    Ok((result, square_root))
}

/// Returns the smallest `n` such that there are at least 2^`target_bits` primes smaller than 2^`n`
/// which have a given non-square integer as a quadratic residue, or an [InvalidInput] error if
/// `target_bits` is zero or if the result does not fit in a `u64`.
///
/// By the prime number theorem there are ~2^n / (n ln 2) primes smaller than 2^n, and half of them
/// have a given non-square as a quadratic residue, so the log2 of the number of usable primes is
///
/// log2(2^n / (2 n ln 2)) = n - log2(n) - log2(ln 2) - 1.
fn bits_for_set_size(target_bits: u64) -> FastCryptoResult<u64> {
    // A target of zero would be satisfied by n = 0 below, since log2(0) is -infinity, and we would
    // end up sampling from an empty range. There is no meaningful set size to ask for here.
    if target_bits == 0 {
        return Err(InvalidInput);
    }

    // The right-hand side above is increasing in n, so we can just increase n until it is large
    // enough. Starting from target_bits is safe since the correction term is positive.
    for n in target_bits..=target_bits + 64 {
        if usable_primes_below_2_pow(n) >= target_bits as f64 {
            return Ok(n);
        }
    }
    Err(InvalidInput)
}

/// Returns an approximation of the log2 of the number of primes smaller than 2^n which have a given
/// non-square integer as a quadratic residue.
fn usable_primes_below_2_pow(n: u64) -> f64 {
    n as f64 - (n as f64).log2() - 2f64.ln().log2() - 1.0
}

/// Sample a random odd number smaller than 2^`bits`.
fn sample_odd_number<R: Rng>(bits: u64, rng: &mut R) -> BigInt {
    let size_in_bytes = bits.div_ceil(8) as usize;
    let mut bytes = vec![0u8; size_in_bytes];
    rng.fill_bytes(&mut bytes);

    // Clear the bits above the requested size so the result is smaller than 2^bits.
    let excess_bits = (size_in_bytes as u64 * 8 - bits) as u32;
    if excess_bits > 0 {
        bytes[size_in_bytes - 1] &= 0xffu8 >> excess_bits;
    }

    // The least significant byte is first, so this makes the number odd.
    bytes[0] |= 1;

    BigInt::from_bytes_le(Sign::Plus, &bytes)
}

lazy_static! {
    /// The odd primes smaller than 100.
    static ref PRIMES: Vec<BigInt> = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97,
    ]
    .into_iter()
    .map(BigInt::from)
    .collect();
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use num_traits::{One, Signed};
    use rand::{thread_rng, RngCore};
    use std::ops::{Shl, Shr};

    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::hash_v2::{
        bits_for_set_size, hash_to_group_v2_with_custom_parameters, sample_odd_number,
        usable_primes_below_2_pow,
    };
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::ParameterizedGroupElement;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_bits_for_set_size() {
        for target in [16u64, 32, 64, 85, 128, 256] {
            let n = bits_for_set_size(target).unwrap();
            // The result is large enough,
            assert!(usable_primes_below_2_pow(n) >= target as f64);
            // and it is the smallest such value.
            assert!(usable_primes_below_2_pow(n - 1) < target as f64);
        }
        assert!(bits_for_set_size(0).is_err());
    }

    #[test]
    fn test_sample_odd_number_is_in_range() {
        let mut rng = ChaCha8Rng::from_seed([0u8; 32]);
        for bits in [8u64, 17, 64, 71, 136] {
            let bound = BigInt::one().shl(bits);
            for _ in 0..100 {
                let sampled = sample_odd_number(bits, &mut rng);
                assert!(sampled < bound);
                assert!(sampled.bit(0));
            }
        }
    }

    #[test]
    fn test_output_is_reduced_and_in_group() {
        let mut seed = [0u8; 32];
        let discriminant = Discriminant::from_seed(&seed, 1024).unwrap();

        for k in [1u64, 2, 3] {
            for _ in 0..5 {
                let qf =
                    hash_to_group_v2_with_custom_parameters(&seed, &discriminant, 128, k).unwrap();
                assert!(qf.is_reduced_assuming_normal());
                assert!(qf.is_in_group(&discriminant));
                seed[0] += 1;
            }
        }
    }

    #[test]
    fn test_a_is_smaller_than_the_reducedness_bound() {
        let discriminant = Discriminant::from_seed(b"seed", 1024).unwrap();
        let bound = discriminant.as_bigint().abs().sqrt().shr(1);

        let mut seed = [0u8; 32];
        for _ in 0..10 {
            thread_rng().fill_bytes(&mut seed);
            let qf = hash_to_group_v2_with_custom_parameters(&seed, &discriminant, 128, 2).unwrap();
            assert!(qf.a < bound);
        }
    }

    #[test]
    fn test_zero_security_parameter_is_rejected() {
        let discriminant = Discriminant::from_seed(b"seed", 1024).unwrap();
        // There is no valid range to sample the factors from, so this must be rejected instead of
        // panicking.
        for small_prime_factors in 0..=3 {
            assert!(hash_to_group_v2_with_custom_parameters(
                b"seed",
                &discriminant,
                0,
                small_prime_factors
            )
            .is_err());
        }
    }

    #[test]
    fn test_too_small_discriminant_is_rejected() {
        // The default parameters need a in a set of ~2^{136 + 3*50} = 2^286, so a discriminant of
        // 512 bits is too small for the output to be guaranteed reduced.
        let discriminant = Discriminant::from_seed(b"seed", 512).unwrap();
        assert!(
            QuadraticForm::hash_to_group_v2_with_default_parameters(b"seed", &discriminant)
                .is_err()
        );
    }

    #[test]
    fn test_deterministic_and_seed_dependent() {
        let discriminant = Discriminant::from_seed(b"discriminant seed", 1024).unwrap();

        let base = QuadraticForm::hash_to_group_v2_with_default_parameters(b"seed", &discriminant)
            .unwrap();
        let same = QuadraticForm::hash_to_group_v2_with_default_parameters(b"seed", &discriminant)
            .unwrap();
        assert_eq!(base, same);

        let other =
            QuadraticForm::hash_to_group_v2_with_default_parameters(b"another seed", &discriminant)
                .unwrap();
        assert_ne!(base, other);

        // A different k than the default gives a different element.
        let other_k =
            hash_to_group_v2_with_custom_parameters(b"seed", &discriminant, 128, 2).unwrap();
        assert_ne!(base, other_k);
    }
}
