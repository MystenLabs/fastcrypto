// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::discriminant::Discriminant;
use crate::class_group::{hash, QuadraticForm};
use crate::math::crt::solve_equation;
use crate::math::hash_prime::{DefaultPrimalityCheck, PrimalityCheck};
use crate::math::jacobi;
use crate::math::modular::modular_square_root;
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
    pub fn hash_to_group(seed: &[u8], discriminant: &Discriminant, k: u16) -> Self {
        // Sample a and b such that a < sqrt(|discriminant|)/2 and b' is the square root of the
        // discriminant modulo a.
        let (a, mut b) = hash::sample_modulus(discriminant, seed, k);

        // b must be odd
        if b.is_even() {
            b -= &a;
        }

        QuadraticForm::from_a_b_discriminant(a, b, discriminant)
            .expect("a and b are constructed such that this never fails")
    }
}

/// Sample a product of K primes and return this along with the square root of the discriminant modulo a.
fn sample_modulus(discriminant: &Discriminant, seed: &[u8], k: u16) -> (BigInt, BigInt) {
    // If a is smaller than this bound and |b| < a, the form is guaranteed to be reduced.
    let mut bound: BigInt = discriminant.as_bigint().abs().sqrt().shr(1);
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
                && jacobi::jacobi(discriminant.as_bigint(), &factor)
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
