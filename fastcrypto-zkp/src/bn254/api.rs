// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::verifier::{process_vk_special, PreparedVerifyingKey};
use crate::bn254::VerifyingKey as Bn254VerifyingKey;
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_crypto_primitives::snark::SNARK;
pub use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::FastCryptoError;
#[cfg(test)]
#[path = "unit_tests/api_tests.rs"]
mod api_tests;

/// Size of scalars in the BN254 construction.
pub const SCALAR_SIZE: usize = 32;

/// Deserialize bytes as an Arkwork representation of a verifying key, and return a vector of the
/// four components of a prepared verified key (see more at [`crate::bn254::verifier::PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?;
    process_vk_special(&Bn254VerifyingKey(vk)).as_serialized()
}

/// Verify Groth16 proof using the serialized form of the prepared verifying key (see more at
/// [`crate::bn254::verifier::PreparedVerifyingKey`]), serialized proof public input and serialized
/// proof points.
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

    let pvk = PreparedVerifyingKey::deserialize(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    )?;

    verify_groth16(&pvk, proof_public_inputs_as_bytes, proof_points_as_bytes)
}

/// Verify proof with a given verifying key in [struct PreparedVerifyingKey], serialized public inputs
/// and serialized proof points.
pub fn verify_groth16(
    pvk: &PreparedVerifyingKey,
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError> {
    let proof = Proof::<Bn254>::deserialize_compressed(proof_points_as_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?;
    let mut public_inputs = Vec::new();
    for chunk in proof_public_inputs_as_bytes.chunks(SCALAR_SIZE) {
        public_inputs.push(
            Bn254Fr::deserialize_compressed(chunk).map_err(|_| FastCryptoError::InvalidInput)?,
        );
    }
    Groth16::<Bn254>::verify_with_processed_vk(&pvk.as_arkworks_pvk(), &public_inputs, &proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}
