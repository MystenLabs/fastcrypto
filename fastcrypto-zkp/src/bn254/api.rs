// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use fastcrypto::error::FastCryptoError;

#[cfg(test)]
#[path = "unit_tests/api_tests.rs"]
mod api_tests;

/// Verify Groth16 proof using the serialized form of the four components in a prepared verifying key
/// (see more at [`crate::verifier::PreparedVerifyingKey`]), serialized proof public input and serialized proof points.
pub fn verify_groth16_in_bytes(
    vk_bytes: &[u8],
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError> {
    let vk = VerifyingKey::deserialize_compressed(vk_bytes).map_err(|_| FastCryptoError::InvalidInput)?;

    let mut x = Vec::new();
    for chunk in proof_public_inputs_as_bytes.chunks(32) {
        if chunk.len() != 32 {
            return Err(FastCryptoError::InputLengthWrong(32));
        }
        x.push(Fr::deserialize_compressed(chunk).map_err(|_| FastCryptoError::InvalidInput)?);
    }

    let proof = Proof::<Bn254>::deserialize_compressed(proof_points_as_bytes)
        .map_err(|_| FastCryptoError::InvalidInput)?;

    Groth16::<Bn254>::verify(&vk, &x, &proof).map_err(|_| FastCryptoError::GeneralOpaqueError)
}
