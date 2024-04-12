// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{
    G1Element, FP_BYTE_LENGTH, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH,
    GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};

use crate::groth16::generic_api;

/// Create a prepared verifying key for Groth16 over the BLS12-381 curve construction. See
/// [`generic_api::prepare_pvk_bytes`].
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    let mut pvk_bytes = generic_api::prepare_pvk_bytes::<
        G1Element,
        { G1_ELEMENT_BYTE_LENGTH },
        { G2_ELEMENT_BYTE_LENGTH },
        { GT_ELEMENT_BYTE_LENGTH },
        { SCALAR_LENGTH },
    >(vk_bytes)?;
    gt_element_conversion_in_place(&mut pvk_bytes[1])?;
    Ok(pvk_bytes)
}

/// Verify Groth16 proof over the BLS12-381 curve construction. See
/// [`generic_api::verify_groth16_in_bytes`].
pub fn verify_groth16_in_bytes(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError> {
    // The generic API expects scalars in big-endian format, but the input here is as little-endian
    // because this is used by arkworks.
    let mut proof_public_inputs_as_bytes = proof_public_inputs_as_bytes.to_vec();
    switch_scalar_endianness_in_place::<SCALAR_LENGTH>(&mut proof_public_inputs_as_bytes)?;

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
        &proof_public_inputs_as_bytes,
        proof_points_as_bytes,
    )
}

/// Given a vector of concatenated binary representations of scalars of the same length, this
/// function switches the endianess from big to little or vice-versa for each scalar.
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

/// Given a serialization of a [`fastcrypto::groups::bls12381::GTElement`], this method converts it
/// into a serialization of the corresponding arkworks [`PairingOutput`] type in place. It is _not_
/// verified whether the input is a valid serialization of a GT element.
fn gt_element_conversion_in_place(bytes: &mut [u8]) -> FastCryptoResult<()> {
    // An element in the quadratic extension of Fp consistes of two field elements.
    const FP_EXTENSION_BYTE_LENGTH: usize = 2 * FP_BYTE_LENGTH;
    if bytes.len() != 6 * FP_EXTENSION_BYTE_LENGTH {
        return Err(FastCryptoError::InvalidInput);
    }

    // The conversion has two steps:
    // 1) Re-order the six pairs of field elements (field extension elements) according to the
    //    following mapping: (0,1,2,3,4,5) -> (0,3,1,4,2,5),
    // 2) Switch all 12 field elements from big-endian to little-endian.

    // Step 1
    // Only the middle 4 pairs needs to be permuted: 2 -> 1, 4 -> 2, 3 -> 4, 1 -> 3
    let (zero_one_two, three_four_five) = bytes.split_at_mut(3 * FP_EXTENSION_BYTE_LENGTH);
    let (zero_one, two) = zero_one_two.split_at_mut(2 * FP_EXTENSION_BYTE_LENGTH);
    let (_zero, one) = zero_one.split_at_mut(FP_EXTENSION_BYTE_LENGTH);
    let (three_four, _five) = three_four_five.split_at_mut(2 * FP_EXTENSION_BYTE_LENGTH);
    let (three, four) = three_four.split_at_mut(FP_EXTENSION_BYTE_LENGTH);

    let tmp = one.to_vec();
    one.copy_from_slice(two);
    two.copy_from_slice(four);
    four.copy_from_slice(three);
    three.copy_from_slice(&tmp);

    // Step 2
    switch_scalar_endianness_in_place::<FP_BYTE_LENGTH>(bytes)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::PairingOutput;
    use ark_ec::Group;
    use ark_ff::Zero;
    use ark_serialize::CanonicalSerialize;

    use fastcrypto::groups::bls12381::{GTElement, Scalar, FP_BYTE_LENGTH, SCALAR_LENGTH};
    use fastcrypto::groups::GroupElement;
    use fastcrypto::serde_helpers::{deserialize_vector, ToFromByteArray};

    use crate::bls12381::api::{gt_element_conversion_in_place, switch_scalar_endianness_in_place};

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
        let mut empty = Vec::new();
        switch_scalar_endianness_in_place::<SCALAR_LENGTH>(&mut empty).unwrap();
        assert_eq!(empty, Vec::<u8>::new());

        // Zero is the same in both big-endian and little-endian.
        let mut zero = serialize_arkworks_scalars(&[Fr::zero()]);
        switch_scalar_endianness_in_place::<SCALAR_LENGTH>(&mut zero).unwrap();
        assert_eq!(zero, vec![0u8; SCALAR_LENGTH]);

        // Invalid input lengths
        assert!(
            switch_scalar_endianness_in_place::<SCALAR_LENGTH>(&mut [0; SCALAR_LENGTH - 1])
                .is_err()
        );
        assert!(
            switch_scalar_endianness_in_place::<SCALAR_LENGTH>(&mut [0; SCALAR_LENGTH]).is_ok()
        );
        assert!(
            switch_scalar_endianness_in_place::<SCALAR_LENGTH>(&mut [0; SCALAR_LENGTH + 1])
                .is_err()
        );

        // Test with a few non-trivial numbers.
        let a = 123;
        let b = 456;
        let c = 789;

        let mut scalars = serialize_arkworks_scalars(&[Fr::from(a), Fr::from(b), Fr::from(c)]);
        switch_scalar_endianness_in_place::<SCALAR_LENGTH>(&mut scalars).unwrap();
        let blst_scalars = deserialize_vector::<SCALAR_LENGTH, Scalar>(&scalars).unwrap();

        assert_eq!(blst_scalars.len(), 3);
        assert_eq!(blst_scalars[0], Scalar::from(a));
        assert_eq!(blst_scalars[1], Scalar::from(b));
        assert_eq!(blst_scalars[2], Scalar::from(c));
    }

    #[test]
    fn test_gt_element_conversion() {
        let generator = PairingOutput::<Bls12_381>::generator();
        let mut compressed_bytes = Vec::new();
        let mut uncompressed_bytes = Vec::new();

        // GT elements cannot be compressed, so compressed and uncompressed serialization should be the same.
        generator
            .serialize_compressed(&mut compressed_bytes)
            .unwrap();
        generator
            .serialize_uncompressed(&mut uncompressed_bytes)
            .unwrap();
        assert_eq!(compressed_bytes, uncompressed_bytes);

        // The arkworks serialization does not match the GroupElement serialization.
        let mut expected = GTElement::generator().to_byte_array();
        assert_eq!(compressed_bytes.len(), expected.len());
        assert_ne!(compressed_bytes, expected);

        // After conversion, the arkworks serialization should match the GroupElement serialization.
        gt_element_conversion_in_place(&mut expected).unwrap();
        assert_eq!(compressed_bytes, expected);

        // The identity is the same in both representations
        let arkworks_id = PairingOutput::<Bls12_381>::zero();
        let mut arkworks_bytes = Vec::new();
        arkworks_id
            .serialize_uncompressed(&mut arkworks_bytes)
            .unwrap();

        let mut fc_bytes = GTElement::zero().to_byte_array();
        assert_ne!(&fc_bytes.to_vec(), &arkworks_bytes);
        gt_element_conversion_in_place(&mut fc_bytes).unwrap();
        assert_eq!(&fc_bytes.to_vec(), &arkworks_bytes);

        // Invalid input lengths
        assert!(gt_element_conversion_in_place(&mut [0; 0]).is_err());
        assert!(gt_element_conversion_in_place(&mut [0; 12 * FP_BYTE_LENGTH - 1]).is_err());
        assert!(gt_element_conversion_in_place(&mut [0; 12 * FP_BYTE_LENGTH + 1]).is_err());
    }
}
