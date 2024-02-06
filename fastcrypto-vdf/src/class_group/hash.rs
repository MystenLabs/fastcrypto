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
    /// product of K primes all smaller than (sqrt(|discriminant|)/2)^{1/k}.
    ///
    /// The K parameter must be smaller than the number of bits in the discriminant divided by 32 to ensure that the
    /// sample space for the primes is large enough. Otherwise an error is returned.
    pub fn hash_to_group(
        seed: &[u8],
        discriminant: &Discriminant,
        k: u16,
    ) -> FastCryptoResult<Self> {
        // Sample a and b such that a < sqrt(|discriminant|)/2 and b' is the square root of the
        // discriminant modulo a.
        let (a, mut b) = sample_modulus(discriminant, seed, k)?;

        // b must be odd
        if b.is_even() {
            b -= &a;
        }

        Ok(QuadraticForm::from_a_b_discriminant(a, b, discriminant)
            .expect("a and b are constructed such that this never fails"))
    }
}

/// Sample a product of K primes and return this along with the square root of the discriminant modulo a.
fn sample_modulus(
    discriminant: &Discriminant,
    seed: &[u8],
    k: u16,
) -> FastCryptoResult<(BigInt, BigInt)> {
    // If a is smaller than this bound and |b| < a, the form is guaranteed to be reduced.
    let mut bound: BigInt = discriminant.as_bigint().abs().sqrt().shr(1);
    if k > 1 {
        bound = bound.nth_root(k as u32);
    }

    // This heuristic bound ensures that there will be enough distinct primes to sample from, so we won't end up in an
    // infinite loop. Consult the paper for details on how to pick the parameters.
    if k > (discriminant.bits() / 32) as u16 {
        return Err(InvalidInput);
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
