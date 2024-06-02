// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use serde::Deserialize;

use fastcrypto::groups::{GroupElement, MultiScalarMul, Pairing};

pub mod api;

#[derive(Debug, Deserialize)]
pub struct Proof<G1: Pairing>
where
    G1::Other: Debug,
{
    a: G1,
    b: G1::Other,
    c: G1,
}

#[derive(Debug)]
pub struct VerifyingKey<G1: Pairing>
where
    G1::Other: Debug,
{
    alpha: G1,
    beta: G1::Other,
    gamma: G1::Other,
    delta: G1::Other,
    gamma_abc: Vec<G1>,
}

/// This is a helper function to store a pre-processed version of the verifying key.
/// This is roughly homologous to [`ark_groth16::data_structures::PreparedVerifyingKey`].
/// Note that contrary to Arkworks, we don't store a "prepared" version of the `gamma_neg` and
/// `delta_neg` fields because they are very large and unpractical to use in the binary API.
pub struct PreparedVerifyingKey<G1>
where
    G1: Pairing,
{
    /// The element vk.gamma_abc,
    /// aka the `[gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * G]`, where i spans the public inputs
    vk_gamma_abc: Vec<G1>,

    /// The element `e(alpha * G, beta * H)` in `GT`.
    alpha_beta: <G1 as Pairing>::Output,

    /// The element `- gamma * H` in `G2`, for use in pairings.
    gamma_neg: <G1 as Pairing>::Other,

    /// The element `- delta * H` in `G2`, for use in pairings.
    delta_neg: <G1 as Pairing>::Other,
}

impl<G1: Pairing> Proof<G1> {
    pub fn new(a: G1, b: G1::Other, c: G1) -> Self {
        Proof { a, b, c }
    }
}

impl<G1: Pairing> VerifyingKey<G1> {
    pub fn new(
        alpha: G1,
        beta: G1::Other,
        gamma: G1::Other,
        delta: G1::Other,
        gamma_abc: Vec<G1>,
    ) -> Self {
        VerifyingKey {
            alpha,
            beta,
            gamma,
            delta,
            gamma_abc,
        }
    }
}

impl<G1> From<&VerifyingKey<G1>> for PreparedVerifyingKey<G1>
where
    G1: Pairing,
{
    fn from(vk: &VerifyingKey<G1>) -> Self {
        PreparedVerifyingKey {
            vk_gamma_abc: vk.gamma_abc.clone(),
            alpha_beta: vk.alpha.pairing(&vk.beta),
            gamma_neg: -vk.gamma,
            delta_neg: -vk.delta,
        }
    }
}

impl<G1: Pairing> PreparedVerifyingKey<G1> {
    /// Verify Groth16 proof using the prepared verifying key (see more at
    /// [`crate::bn254::verifier::PreparedVerifyingKey`]), a vector of public inputs and the proof.
    pub fn verify(
        &self,
        public_inputs: &[G1::ScalarType],
        proof: &Proof<G1>,
    ) -> FastCryptoResult<()>
    where
        G1: MultiScalarMul,
        <G1 as Pairing>::Output: GroupElement,
    {
        let prepared_inputs = self.prepare_inputs(public_inputs)?;
        self.verify_with_prepared_inputs(&prepared_inputs, proof)
    }

    /// Verify Groth16 proof using the prepared verifying key (see more at
    /// [`crate::bn254::verifier::PreparedVerifyingKey`]), a prepared public input (see
    /// [`prepare_inputs`]) and the proof.
    pub fn verify_with_prepared_inputs(
        &self,
        prepared_inputs: &G1,
        proof: &Proof<G1>,
    ) -> FastCryptoResult<()>
    where
        <G1 as Pairing>::Output: GroupElement,
    {
        let lhs = G1::multi_pairing(
            &[proof.a, *prepared_inputs, proof.c],
            &[proof.b, self.gamma_neg, self.delta_neg],
        )?;
        if lhs == self.alpha_beta {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidProof)
        }
    }

    /// Prepare the public inputs for use in [`verify_with_prepared_inputs`].
    pub fn prepare_inputs(&self, public_inputs: &[G1::ScalarType]) -> FastCryptoResult<G1>
    where
        G1: MultiScalarMul,
    {
        if (public_inputs.len() + 1) != self.vk_gamma_abc.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        if public_inputs.is_empty() {
            return Ok(self.vk_gamma_abc[0]);
        }
        G1::multi_scalar_mul(public_inputs, &self.vk_gamma_abc[1..])
            .map(|x| x + self.vk_gamma_abc[0])
    }
}
