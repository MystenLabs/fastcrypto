// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::math::crt::solve_congruence_equation_system;
use crate::math::hash_prime::{DefaultPrimalityCheck, PrimalityCheck};
use crate::math::jacobi;
use crate::math::modular_sqrt::modular_square_root;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;
use num_bigint::{BigInt, UniformBigInt};
use num_integer::Integer;
use num_traits::Signed;
use rand::distributions::uniform::UniformSampler;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::ops::{AddAssign, ShlAssign, Shr};

impl QuadraticForm {
    /// Generate a random quadratic form from a seed with the given discriminant. This method is deterministic and it is
    /// a random oracle on a large subset of the class group, namely the group elements whose `a` coordinate is a
    /// product of `k` primes all smaller than `(sqrt(|discriminant|)/2)^{1/k}`.
    ///
    /// Increasing `k` speeds-up the function (at least up to some break even point), but it also decreases the size of
    /// the range of the hash function, so `k` must be picked no larger than the `k` computed in [largest_allowed_k]. If
    /// it is larger, an [InvalidInput] error is returned. If in doubt, use the [hash_to_group_with_default_parameters]
    /// instead.
    pub fn hash_to_group(
        seed: &[u8],
        discriminant: &Discriminant,
        k: u16,
    ) -> FastCryptoResult<Self> {
        // Sample a and b such that a < sqrt(|discriminant|)/2 and b is the square root of the discriminant modulo a.
        let (a, mut b) = sample_modulus(discriminant, seed, k)?;

        // b must be odd but may be negative
        if b.is_even() {
            b -= &a;
        }

        Ok(QuadraticForm::from_a_b_discriminant(a, b, discriminant)
            .expect("a and b are constructed such that this never fails"))
    }

    /// Generate a random quadratic form from a seed with the given discriminant. This method is deterministic, and it
    /// is a random oracle on a large subset of the class group. This method picks a default `k` parameter and calls the
    /// [hash_to_group](QuadraticForm::hash_to_group) function with this `k`.
    pub fn hash_to_group_with_default_parameters(
        seed: &[u8],
        discriminant: &Discriminant,
    ) -> FastCryptoResult<Self> {
        let k = get_default_k(discriminant.bits() as usize);
        Self::hash_to_group(seed, discriminant, k)
    }
}

fn get_default_k(discriminant_bits: usize) -> u16 {
    // This is chosen to ensure that the range of the hash function is large (at least 2^256) but also that the
    // performance is near optimal, based on benchmarks.
    if discriminant_bits <= 2048 {
        16
    } else {
        32
    }
}

/// Increasing `k` reduces the range of the hash function for a given discriminant. This function returns a choice of
/// `k` such that the range is at least `2^256`, and chooses this it as large as possible. Consult the paper for
/// details.
fn largest_allowed_k(discriminant: &Discriminant) -> u16 {
    let bits = discriminant.bits();
    let lambda = 256.0;
    let log_b = bits as f64 / 2.0 - 1.0;
    let numerator = log_b - lambda;
    let denominator = (log_b * 2.0_f64.ln()).log2() + 1.0;
    (numerator / denominator).floor() as u16
}

/// Sample a product of `k` primes and return this along with the square root of the discriminant modulo `a`. If `k` is
/// larger than the largest allowed `k` (as computed in [largest_allowed_k]) for the given discriminant, an
/// [InvalidInput] error is returned.
fn sample_modulus(
    discriminant: &Discriminant,
    seed: &[u8],
    k: u16,
) -> FastCryptoResult<(BigInt, BigInt)> {
    // This heuristic bound ensures that the range of the hash function has size at least 2^256.
    if discriminant.bits() < 800 || k > largest_allowed_k(discriminant) {
        return Err(InvalidInput);
    }

    // If a is smaller than this bound and |b| < a, the form is guaranteed to be reduced.
    let mut bound: BigInt = discriminant.as_bigint().abs().sqrt().shr(1);
    if k > 1 {
        bound = bound.nth_root(k as u32);
    }

    // Seed a rng with the hash of the seed
    let mut rng = ChaCha8Rng::from_seed(Sha256::digest(seed).digest);
    let mut factors = Vec::with_capacity(k as usize);
    let mut square_roots = Vec::with_capacity(k as usize);

    for _ in 0..k {
        let mut factor;
        loop {
            factor = sample_odd_number(&bound, &mut rng);

            if factors.contains(&factor) {
                continue;
            }

            // The primality check does not try divisions with small primes, so we do it here. This speeds up the
            // algorithm significantly.
            if !trial_division(&factor, &PRIMES) {
                continue;
            }

            if jacobi::jacobi(discriminant.as_bigint(), &factor)
                .expect("factor is odd and positive")
                == 1
                && DefaultPrimalityCheck::is_probable_prime(factor.magnitude())
            {
                // Found a valid factor
                break;
            }
        }
        let square_root = modular_square_root(discriminant.as_bigint(), &factor, false)
            .expect("Legendre symbol checked above");
        factors.push(factor);
        square_roots.push(square_root);
    }

    let result = factors.iter().product();
    let square_root = solve_congruence_equation_system(&square_roots, &factors)
        .expect("The factors are distinct primes");

    Ok((result, square_root))
}

/// Sample a random odd number in [1, bound)
fn sample_odd_number<R: Rng>(bound: &BigInt, rng: &mut R) -> BigInt {
    let mut a = UniformBigInt::new(BigInt::from(1), bound.clone().shr(1)).sample(rng);
    a.shl_assign(1);
    a.add_assign(1);
    a
}

/// The odd primes smaller than 100.
const PRIMES: [u64; 24] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

/// Perform trial division on `n` with the given primes. Returns true if neither of the divisors divide `n`
fn trial_division(n: &BigInt, divisors: &[u64]) -> bool {
    for p in divisors {
        if n.is_multiple_of(&BigInt::from(*p)) {
            return false;
        }
    }
    true
}
