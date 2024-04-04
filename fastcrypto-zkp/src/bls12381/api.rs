// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{
    G1Element, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH,
    SCALAR_LENGTH,
};

use crate::groth16::generic_api;

#[cfg(test)]
#[path = "unit_tests/api_tests.rs"]
mod api_tests;

/// Deserialize bytes as an Arkwork representation of a verifying key, and return a vector of the four components of a prepared verified key (see more at [`crate::verifier::PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    generic_api::prepare_pvk_bytes::<
        G1Element,
        { G1_ELEMENT_BYTE_LENGTH },
        { G2_ELEMENT_BYTE_LENGTH },
        { GT_ELEMENT_BYTE_LENGTH },
        { SCALAR_LENGTH },
    >(vk_bytes)
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
    generic_api::verify_groth16_in_bytes::<
        G1Element,
        { G1_ELEMENT_BYTE_LENGTH },
        { G2_ELEMENT_BYTE_LENGTH },
        { GT_ELEMENT_BYTE_LENGTH },
        { SCALAR_LENGTH },
    >(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &reverse_endianness(proof_public_inputs_as_bytes)?,
        proof_points_as_bytes,
    )
}

/// The public inputs are in big-endian byte order (like arkworks), but [fastcrypto::groups::bls12381::Scalar::from_byte_array]
/// expects them in little-endian.
fn reverse_endianness(scalars: &[u8]) -> FastCryptoResult<Vec<u8>> {
    if scalars.len() % SCALAR_LENGTH != 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    let mut reversed_scalars = Vec::with_capacity(scalars.len());
    for scalar in scalars.chunks_exact(SCALAR_LENGTH) {
        let mut scalar_bytes = [0u8; SCALAR_LENGTH];
        scalar_bytes.copy_from_slice(scalar);
        scalar_bytes.reverse();
        reversed_scalars.extend_from_slice(&scalar_bytes);
    }
    Ok(reversed_scalars)
}
