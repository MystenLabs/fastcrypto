// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    bn254::verifier::{process_vk_special, PreparedVerifyingKey},
    circom::{read_proof, read_public_inputs, read_vkey},
};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::FastCryptoError;

#[cfg(test)]
#[path = "unit_tests/api_tests.rs"]
mod api_tests;

pub use ark_ff::ToConstraintField;

/// Size of scalars in the BN254 construction.
pub const SCALAR_SIZE: usize = 32;

/// Deserialize bytes as an Arkwork representation of a verifying key, and return a vector of the
/// four components of a prepared verified key (see more at [`crate::bn254::verifier::PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?;
    process_vk_special(&vk).as_serialized()
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
    // Deserialize public inputs
    if proof_public_inputs_as_bytes.len() % SCALAR_SIZE != 0 {
        return Err(FastCryptoError::InputLengthWrong(SCALAR_SIZE));
    }
    let mut x = Vec::new();
    for chunk in proof_public_inputs_as_bytes.chunks(SCALAR_SIZE) {
        x.push(Bn254Fr::deserialize_compressed(chunk).map_err(|_| FastCryptoError::InvalidInput)?);
    }

    let pvk = PreparedVerifyingKey::deserialize(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    )?;

    let proof = Proof::<Bn254>::deserialize_compressed(proof_points_as_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?;

    Groth16::<Bn254>::verify_with_processed_vk(&pvk.as_arkworks_pvk(), &x, &proof)
        .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
}

/// Read in a json file of the verifying key and serialize it to bytes
pub fn serialize_verifying_key_from_file(vkey_path: &str) -> Vec<Vec<u8>> {
    let vk = read_vkey(vkey_path);
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    let mut vk_gamma_abc_g1_bytes = Vec::new();
    pvk.vk
        .gamma_abc_g1
        .serialize_compressed(&mut vk_gamma_abc_g1_bytes)
        .unwrap();
    let mut alpha_g1_beta_g2_bytes = Vec::new();
    pvk.alpha_g1_beta_g2
        .serialize_compressed(&mut alpha_g1_beta_g2_bytes)
        .unwrap();

    let mut gamma_g2_neg_pc_bytes = Vec::new();
    pvk.gamma_g2_neg_pc
        .serialize_compressed(&mut gamma_g2_neg_pc_bytes)
        .unwrap();

    let mut delta_g2_neg_pc_bytes = Vec::new();
    pvk.delta_g2_neg_pc
        .serialize_compressed(&mut delta_g2_neg_pc_bytes)
        .unwrap();

    vec![
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    ]
}

/// Read in a json file of the proof and serialize it to bytes
pub fn serialize_proof_from_file(proof_path: &str) -> Vec<u8> {
    let proof = read_proof(proof_path);
    let mut proof_points_bytes = Vec::new();
    proof
        .a
        .serialize_compressed(&mut proof_points_bytes)
        .unwrap();
    proof
        .b
        .serialize_compressed(&mut proof_points_bytes)
        .unwrap();
    proof
        .c
        .serialize_compressed(&mut proof_points_bytes)
        .unwrap();
    proof_points_bytes
}

/// Read in a json file of the public inputs and serialize it to bytes
pub fn serialize_public_inputs_from_file(public_inputs_path: &str) -> Vec<Vec<u8>> {
    let inputs = read_public_inputs(public_inputs_path);
    let mut res = Vec::new();
    for input in inputs {
        let mut input_bytes = Vec::new();
        input.serialize_compressed(&mut input_bytes).unwrap();
        res.push(input_bytes);
    }
    res
}
