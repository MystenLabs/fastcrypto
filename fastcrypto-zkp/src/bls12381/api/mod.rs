// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::{
    G1Element, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH,
    SCALAR_LENGTH,
};

use crate::groth16::api;

mod conversions;
#[cfg(test)]
mod tests;

/// Create a prepared verifying key for Groth16 over the BLS12-381 curve construction. See
/// [`api::prepare_pvk_bytes`].
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    api::prepare_pvk_bytes::<
        G1Element,
        { G1_ELEMENT_BYTE_LENGTH },
        { G2_ELEMENT_BYTE_LENGTH },
        { GT_ELEMENT_BYTE_LENGTH },
        { SCALAR_LENGTH },
    >(vk_bytes)
}

/// Verify Groth16 proof over the BLS12-381 curve construction. See
/// [`api::verify_groth16_in_bytes`].
pub fn verify_groth16_in_bytes(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError> {
    api::verify_groth16_in_bytes::<
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
        public_inputs_as_bytes,
        proof_points_as_bytes,
    )
}
