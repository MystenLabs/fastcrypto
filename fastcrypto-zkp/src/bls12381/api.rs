// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;

use crate::bls12381::verifier::PreparedVerifyingKey;
use crate::bls12381::FieldElement;
use crate::bls12381::Proof;
use crate::bls12381::VerifyingKey;

#[cfg(test)]
#[path = "unit_tests/api_tests.rs"]
mod api_tests;

/// Deserialize bytes as an Arkwork representation of a verifying key, and return a vector of the four components of a prepared verified key (see more at [`crate::verifier::PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    let vk = VerifyingKey::deserialize(vk_bytes)?;
    PreparedVerifyingKey::from(&vk).serialize()
}

/// Verify Groth16 proof using the serialized form of the four components in a prepared verifying key
/// (see more at [`crate::verifier::PreparedVerifyingKey`]), serialized proof public input, which should
/// be concatenated serialized field elements of the scalar field of [`crate::conversions::SCALAR_SIZE`]
/// bytes each, and serialized proof points.
pub fn verify_groth16_in_bytes(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError> {
    let x = FieldElement::deserialize_vector(proof_public_inputs_as_bytes)?;
    let proof = Proof::deserialize(proof_points_as_bytes)?;
    let blst_pvk = PreparedVerifyingKey::deserialize(&vec![
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    ])?;
    blst_pvk.verify(x.as_slice(), &proof)
}
