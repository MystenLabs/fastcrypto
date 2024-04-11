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
        &switch_scalar_endianness(proof_public_inputs_as_bytes)?,
        proof_points_as_bytes,
    )
}

/// The public inputs are in little-endian byte order, but [fastcrypto::groups::bls12381::Scalar::from_byte_array]
/// expects them in big-endian representation.
fn switch_scalar_endianness(scalars: &[u8]) -> FastCryptoResult<Vec<u8>> {
    if scalars.len() % SCALAR_LENGTH != 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    Ok(scalars
        .chunks(SCALAR_LENGTH)
        .flat_map(|chunk| {
            let mut scalar = chunk.to_vec();
            scalar.reverse();
            scalar
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::bls12381::api::switch_scalar_endianness;
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_serialize::CanonicalSerialize;
    use fastcrypto::groups::bls12381::{Scalar, SCALAR_LENGTH};
    use fastcrypto::serde_helpers::deserialize_vector;

    fn serialize_arkworks_scalars(scalars: &[Fr]) -> Vec<u8> {
        scalars
            .iter()
            .flat_map(|x| {
                let mut bytes = [0u8; SCALAR_LENGTH];
                x.serialize_compressed(bytes.as_mut_slice()).unwrap();
                bytes.to_vec()
            })
            .collect::<Vec<u8>>()
    }

    #[test]
    fn test_switch_scalar_endianness() {
        // For an empty input, the output should also be empty.
        assert_eq!(switch_scalar_endianness(&[]).unwrap(), Vec::<u8>::new());

        // Zero is the same in both big-endian and little-endian.
        assert_eq!(
            switch_scalar_endianness(&serialize_arkworks_scalars(&[Fr::zero()])).unwrap(),
            vec![0u8; SCALAR_LENGTH]
        );

        // Invalid input lengths
        assert!(switch_scalar_endianness(&[0; SCALAR_LENGTH - 1]).is_err());
        assert!(switch_scalar_endianness(&[0; SCALAR_LENGTH]).is_ok());
        assert!(switch_scalar_endianness(&[0; SCALAR_LENGTH + 1]).is_err());

        // Test with a few non-trivial numbers.
        let a = 123;
        let b = 456;
        let c = 789;

        let arkworks_scalars = serialize_arkworks_scalars(&[Fr::from(a), Fr::from(b), Fr::from(c)]);
        let as_big_endian = switch_scalar_endianness(&arkworks_scalars).unwrap();
        let blst_scalars = deserialize_vector::<SCALAR_LENGTH, Scalar>(&as_big_endian).unwrap();

        assert_eq!(blst_scalars.len(), 3);
        assert_eq!(blst_scalars[0], Scalar::from(a));
        assert_eq!(blst_scalars[1], Scalar::from(b));
        assert_eq!(blst_scalars[2], Scalar::from(c));
    }
}
