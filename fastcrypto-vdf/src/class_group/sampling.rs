// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::Discriminant;
use crate::hash_prime::{DefaultPrimalityCheck, PrimalityCheck};
use crate::math::crt::solve_equation;
use crate::math::jacobi;
use crate::math::modular::modular_square_root;
use fastcrypto::hash::HashFunction;
use fastcrypto::hash::Sha256;
use num_bigint::{BigInt, UniformBigInt};
use num_traits::Signed;
use rand::distributions::uniform::UniformSampler;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::ops::{AddAssign, ShlAssign, Shr};

/// Sample a product of K primes and return this along with the square root of the discriminant modulo a.
pub(super) fn sample_modulus(discriminant: &Discriminant, seed: &[u8], k: u16) -> (BigInt, BigInt) {
    // If a is smaller than this bound and |b| < a, the form is guaranteed to be reduced.
    let mut bound: BigInt = discriminant.0.abs().sqrt().shr(1);
    if k > 1 {
        bound = bound.nth_root(k as u32);
    }

    // TODO: Check this bound
    if bound < 8 * BigInt::from(k) * bound.bits() {
        panic!(
            "The bound, {}, is too small to sample {} distinct primes",
            bound, k
        );
    }

    // Seed a rng with the hash of the seed
    let mut rng = ChaCha8Rng::from_seed(Sha256::digest(seed).digest);
    let mut factors = Vec::with_capacity(k as usize);
    let mut square_roots = Vec::with_capacity(k as usize);

    for _ in 0..k {
        let mut factor;
        loop {
            factor = sample_odd_number(&bound, &mut rng);

            // TODO: The duplicates check takes some time for large k where it is typically not needed. Maybe parameterize this?
            if !factors.contains(&factor)
                && jacobi::jacobi(&discriminant.0, &factor).expect("factor is odd and positive")
                    == 1
                && DefaultPrimalityCheck::is_probable_prime(factor.magnitude())
            {
                // Found a valid factor
                break;
            }
        }
        let square_root = modular_square_root(&discriminant.0, &factor, false)
            .expect("Legendre symbol checked above");
        factors.push(factor);
        square_roots.push(square_root);
    }

    let result = factors.iter().product();
    let square_root =
        solve_equation(&square_roots, &factors).expect("The factors are distinct primes");

    (result, square_root)
}

/// Sample a random odd number in [1, bound)
fn sample_odd_number<R: Rng>(bound: &BigInt, rng: &mut R) -> BigInt {
    let mut a = UniformBigInt::new(BigInt::from(1), bound.clone().shr(1)).sample(rng);
    a.shl_assign(1);
    a.add_assign(1);
    a
}
