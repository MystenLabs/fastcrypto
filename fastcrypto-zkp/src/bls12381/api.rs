// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groth16::generic_api;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{
    G1Element, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH,
    SCALAR_LENGTH,
};

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

/// The public inputs are in little-endian byte order, but [fastcrypto::groups::bls12381::Scalar::from_byte_array]
/// expects them in big-endian representation.
fn reverse_endianness(scalars: &[u8]) -> FastCryptoResult<Vec<u8>> {
    if scalars.len() % SCALAR_LENGTH != 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    let mut reversed_scalars = Vec::with_capacity(scalars.len());
    for scalar in scalars.chunks(SCALAR_LENGTH) {
        let mut scalar = scalar.to_vec();
        scalar.reverse();
        reversed_scalars.extend_from_slice(&scalar);
    }
    Ok(reversed_scalars)
}

#[cfg(test)]
mod tests {
    use crate::bls12381::api::reverse_endianness;
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use fastcrypto::groups::bls12381::{Scalar, SCALAR_LENGTH};
    use fastcrypto::serde_helpers::deserialize_vector;

    #[test]
    fn test_reverse_endianness() {
        let a = 123;
        let b = 456;
        let c = 789;

        let arkworks_scalars = [Fr::from(a), Fr::from(b), Fr::from(c)]
            .iter()
            .flat_map(|x| {
                let mut bytes = [0u8; SCALAR_LENGTH];
                x.serialize_compressed(bytes.as_mut_slice()).unwrap();
                bytes.to_vec()
            })
            .collect::<Vec<u8>>();

        let as_big_endian = reverse_endianness(&arkworks_scalars).unwrap();
        let blst_scalars = deserialize_vector::<SCALAR_LENGTH, Scalar>(&as_big_endian).unwrap();

        assert_eq!(blst_scalars.len(), 3);
        assert_eq!(blst_scalars[0], Scalar::from(a));
        assert_eq!(blst_scalars[1], Scalar::from(b));
        assert_eq!(blst_scalars[2], Scalar::from(c));
    }
}
