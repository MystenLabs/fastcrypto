// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{
    G1Element, FP_BYTE_LENGTH, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH,
    GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};

use crate::groth16::generic_api;

/// Deserialize bytes as an Arkwork representation of a verifying key, and return a vector of the four components of a prepared verified key (see more at [`crate::verifier::PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    let mut pvk_bytes = generic_api::prepare_pvk_bytes::<
        G1Element,
        { G1_ELEMENT_BYTE_LENGTH },
        { G2_ELEMENT_BYTE_LENGTH },
        { GT_ELEMENT_BYTE_LENGTH },
        { SCALAR_LENGTH },
    >(vk_bytes)?;
    pvk_bytes[1] = gt_element_conversion(&pvk_bytes[1])?;
    Ok(pvk_bytes)
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
        &switch_scalar_endianness::<SCALAR_LENGTH>(proof_public_inputs_as_bytes)?,
        proof_points_as_bytes,
    )
}

/// Given a vector of concatenated binary representations of scalars of the same length, this function
/// switches the endianess for each scalar and returns them as a vector.
fn switch_scalar_endianness<const SCALAR_SIZE_IN_BYTES: usize>(
    scalars: &[u8],
) -> FastCryptoResult<Vec<u8>> {
    if scalars.len() % SCALAR_SIZE_IN_BYTES != 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    let mut result = scalars.to_vec();
    switch_scalar_endianness_in_place::<SCALAR_SIZE_IN_BYTES>(&mut result)?;
    Ok(result)
}

fn switch_scalar_endianness_in_place<const SCALAR_SIZE_IN_BYTES: usize>(
    scalars: &mut [u8],
) -> FastCryptoResult<()> {
    if scalars.len() % SCALAR_SIZE_IN_BYTES != 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    scalars
        .chunks_exact_mut(SCALAR_SIZE_IN_BYTES)
        .for_each(|chunk| chunk.reverse());
    Ok(())
}

/// Given a arkworks represetation of a GT element, this converts the representation into a format
/// compatible with the [bls12381::GTElement] type.
fn gt_element_conversion(bytes: &[u8]) -> FastCryptoResult<Vec<u8>> {
    // The conversion has two steps:
    // 1) Reorder the six pairs of field elements in the following way: [0,1,2,3,4,5] <- [0,2,4,1,3,5]
    // 2) Switch all 12 field elements from little-endian to big-endian

    if bytes.len() != 12 * FP_BYTE_LENGTH {
        return Err(FastCryptoError::InvalidInput);
    }

    let mut result = bytes.to_vec();

    // Step 1
    result[2 * FP_BYTE_LENGTH..4 * FP_BYTE_LENGTH]
        .copy_from_slice(&bytes[4 * FP_BYTE_LENGTH..6 * FP_BYTE_LENGTH]);
    result[4 * FP_BYTE_LENGTH..6 * FP_BYTE_LENGTH]
        .copy_from_slice(&bytes[8 * FP_BYTE_LENGTH..10 * FP_BYTE_LENGTH]);
    result[6 * FP_BYTE_LENGTH..8 * FP_BYTE_LENGTH]
        .copy_from_slice(&bytes[2 * FP_BYTE_LENGTH..4 * FP_BYTE_LENGTH]);
    result[8 * FP_BYTE_LENGTH..10 * FP_BYTE_LENGTH]
        .copy_from_slice(&bytes[6 * FP_BYTE_LENGTH..8 * FP_BYTE_LENGTH]);

    // Step 2
    switch_scalar_endianness_in_place::<FP_BYTE_LENGTH>(&mut result)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_serialize::CanonicalSerialize;

    use fastcrypto::groups::bls12381::{Scalar, SCALAR_LENGTH};
    use fastcrypto::serde_helpers::deserialize_vector;

    use crate::bls12381::api::switch_scalar_endianness;

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
        assert_eq!(
            switch_scalar_endianness::<SCALAR_LENGTH>(&[]).unwrap(),
            Vec::<u8>::new()
        );

        // Zero is the same in both big-endian and little-endian.
        assert_eq!(
            switch_scalar_endianness::<SCALAR_LENGTH>(&serialize_arkworks_scalars(&[Fr::zero()]))
                .unwrap(),
            vec![0u8; SCALAR_LENGTH]
        );

        // Invalid input lengths
        assert!(switch_scalar_endianness::<SCALAR_LENGTH>(&[0; SCALAR_LENGTH - 1]).is_err());
        assert!(switch_scalar_endianness::<SCALAR_LENGTH>(&[0; SCALAR_LENGTH]).is_ok());
        assert!(switch_scalar_endianness::<SCALAR_LENGTH>(&[0; SCALAR_LENGTH + 1]).is_err());

        // Test with a few non-trivial numbers.
        let a = 123;
        let b = 456;
        let c = 789;

        let arkworks_scalars = serialize_arkworks_scalars(&[Fr::from(a), Fr::from(b), Fr::from(c)]);
        let as_big_endian = switch_scalar_endianness::<SCALAR_LENGTH>(&arkworks_scalars).unwrap();
        let blst_scalars = deserialize_vector::<SCALAR_LENGTH, Scalar>(&as_big_endian).unwrap();

        assert_eq!(blst_scalars.len(), 3);
        assert_eq!(blst_scalars[0], Scalar::from(a));
        assert_eq!(blst_scalars[1], Scalar::from(b));
        assert_eq!(blst_scalars[2], Scalar::from(c));
    }
}
