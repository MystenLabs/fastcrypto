// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::class_group::discriminant::Discriminant;
use crate::class_group::QuadraticForm;
use crate::math::hash_prime::{hash_prime, DefaultPrimalityCheck};
use crate::math::parameterized_group::{ParameterizedGroupElement, UnknownOrderGroupElement};
use crate::vdf::wesolowski::WesolowskisVDF;
use fastcrypto::groups::multiplier::ScalarMultiplier;
use num_bigint::BigInt;
use serde::Serialize;

/// Default size in bytes of the Fiat-Shamir challenge used in proving and verification.
pub const DEFAULT_CHALLENGE_SIZE_IN_BYTES: usize = 32;

pub trait FiatShamir<G: ParameterizedGroupElement + UnknownOrderGroupElement>: Sized {
    /// Compute the prime modulus used in proving and verification. This is a Fiat-Shamir construction
    /// to make the Wesolowski VDF non-interactive.
    fn compute_challenge<M: ScalarMultiplier<G, G::ScalarType>>(
        vdf: &WesolowskisVDF<G, Self, M>,
        input: &G,
        output: &G,
    ) -> G::ScalarType;
}

/// Implementation of the Fiat-Shamir challenge generation for usage with Wesolowski's VDF construction.
/// The implementation is strong, meaning that all public parameters are used in the challenge generation.
/// See https://eprint.iacr.org/2023/691.
pub struct StrongFiatShamir {}

impl FiatShamir<QuadraticForm> for StrongFiatShamir {
    fn compute_challenge<M: ScalarMultiplier<QuadraticForm, BigInt>>(
        vdf: &WesolowskisVDF<QuadraticForm, Self, M>,
        input: &QuadraticForm,
        output: &QuadraticForm,
    ) -> BigInt {
        let seed = bcs::to_bytes(&FiatShamirInput {
            input,
            output,
            iterations: vdf.iterations,
            group_parameter: &vdf.group_parameter,
        })
        .expect("Failed to serialize FiatShamirInput");
        hash_prime::<DefaultPrimalityCheck>(
            &seed,
            DEFAULT_CHALLENGE_SIZE_IN_BYTES,
            &[0, 8 * DEFAULT_CHALLENGE_SIZE_IN_BYTES - 1],
        )
        .into()
    }
}

#[derive(Serialize)]
struct FiatShamirInput<'a> {
    input: &'a QuadraticForm,
    output: &'a QuadraticForm,
    iterations: u64,
    group_parameter: &'a Discriminant,
}
