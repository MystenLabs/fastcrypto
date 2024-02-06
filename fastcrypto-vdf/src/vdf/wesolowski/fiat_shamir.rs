// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::math::hash_prime::{hash_prime, PrimalityCheck};
use crate::vdf::wesolowski::WesolowskisVDF;
use crate::{ParameterizedGroupElement, ToBytes, UnknownOrderGroupElement};
use num_bigint::BigInt;
use std::marker::PhantomData;

pub trait FiatShamir<G: ParameterizedGroupElement + UnknownOrderGroupElement>: Sized {
    /// Compute the prime modulus used in proving and verification. This is a Fiat-Shamir construction
    /// to make the Wesolowski VDF non-interactive.
    fn compute_challenge(vdf: &WesolowskisVDF<G, Self>, input: &G, output: &G) -> G::ScalarType;
}

impl<
        G: ParameterizedGroupElement<ScalarType = BigInt> + UnknownOrderGroupElement,
        const CHALLENGE_SIZE: usize,
        P: PrimalityCheck,
    > FiatShamir<G> for StrongFiatShamir<G, CHALLENGE_SIZE, P>
{
    fn compute_challenge(vdf: &WesolowskisVDF<G, Self>, input: &G, output: &G) -> BigInt {
        let mut seed = vec![];

        let input_bytes = input.to_bytes();
        seed.extend_from_slice(&(input_bytes.len() as u64).to_be_bytes());
        seed.extend_from_slice(&input_bytes);

        let output_bytes = output.to_bytes();
        seed.extend_from_slice(&(output_bytes.len() as u64).to_be_bytes());
        seed.extend_from_slice(&output_bytes);

        seed.extend_from_slice(&(vdf.iterations).to_be_bytes());
        seed.extend_from_slice(&vdf.group_parameter.to_bytes());

        hash_prime::<P>(&seed, CHALLENGE_SIZE, &[0, 8 * CHALLENGE_SIZE - 1]).into()
    }
}

/// Implementation of the Fiat-Shamir challenge generation for usage with Wesolowski's VDF construction.
/// The implementation is strong, meaning that all public parameters are used in the challenge generation.
/// See https://eprint.iacr.org/2023/691.
pub struct StrongFiatShamir<G, const CHALLENGE_SIZE: usize, P> {
    _group: PhantomData<G>,
    _primality_check: PhantomData<P>,
}
