// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::{BigInt, Sign};
use serde::Serialize;
use std::marker::PhantomData;

use fastcrypto::hash::{HashFunction, Keccak256};

use crate::math::parameterized_group::ParameterizedGroupElement;

/// Default size in bytes of the Fiat-Shamir challenge used in proving and verification.
pub const DEFAULT_CHALLENGE_SIZE_IN_BYTES: usize = 32;

pub trait FiatShamir<G: ParameterizedGroupElement<ScalarType = BigInt>>: Sized {
    fn compute_challenge(input: &G, output: &G, iterations: u64, proof: &G) -> G::ScalarType;
}

pub(super) struct DefaultFiatShamir<G> {
    _group_element: PhantomData<G>,
}

impl<G: ParameterizedGroupElement<ScalarType = BigInt> + Serialize> FiatShamir<G>
    for DefaultFiatShamir<G>
{
    fn compute_challenge(input: &G, output: &G, iterations: u64, proof: &G) -> BigInt {
        let seed = bcs::to_bytes(&FiatShamirInput {
            input,
            output,
            iterations,
            proof,
        })
        .expect("Failed to serialize FiatShamirInput");
        let hash = Keccak256::digest(&seed);
        debug_assert!(hash.digest.len() >= DEFAULT_CHALLENGE_SIZE_IN_BYTES);
        BigInt::from_bytes_be(Sign::Plus, &hash.digest[..DEFAULT_CHALLENGE_SIZE_IN_BYTES])
    }
}

#[derive(Serialize)]
struct FiatShamirInput<'a, G> {
    input: &'a G,
    output: &'a G,
    iterations: u64,
    proof: &'a G,
}
