// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bls12_381::Bls12_381;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use fastcrypto::error::FastCryptoError;

use crate::bls12381::conversions::{BlsFr, SCALAR_SIZE};
use crate::bls12381::verifier::{
    process_vk_special, verify_with_processed_vk, PreparedVerifyingKey,
};

#[cfg(test)]
#[path = "unit_tests/api_tests.rs"]
mod api_tests;

/// Deserialize bytes as an Arkwork representation of a verifying key, and return a vector of the four components of a prepared verified key (see more at [`crate::verifier::PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(vk_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?;

    process_vk_special(&vk.into()).as_serialized()
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
    if proof_public_inputs_as_bytes.len() % SCALAR_SIZE != 0 {
        return Err(FastCryptoError::InputLengthWrong(SCALAR_SIZE));
    }
    let mut x = Vec::new();
    for chunk in proof_public_inputs_as_bytes.chunks(SCALAR_SIZE) {
        x.push(
            BlsFr::deserialize_compressed(chunk)
                .map_err(|_| FastCryptoError::InvalidInput)?
                .into(),
        );
    }

    let proof = Proof::<Bls12_381>::deserialize_compressed(proof_points_as_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?
        .into();

    let blst_pvk = PreparedVerifyingKey::deserialize(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    )?;

    verify_with_processed_vk(&blst_pvk, &x, &proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}
