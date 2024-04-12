// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::bls12381::{
    G1Element, GTElement, Scalar, FP_BYTE_LENGTH, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH,
    GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};
use fastcrypto::serde_helpers::ToFromByteArray;

use crate::groth16::generic_api;
use crate::groth16::generic_api::{FromLittleEndianByteArray, GTSerialize};

/// Create a prepared verifying key for Groth16 over the BLS12-381 curve construction. See
/// [`generic_api::prepare_pvk_bytes`].
pub fn prepare_pvk_bytes(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError> {
    generic_api::prepare_pvk_bytes::<
        G1Element,
        { G1_ELEMENT_BYTE_LENGTH },
        { G2_ELEMENT_BYTE_LENGTH },
        { GT_ELEMENT_BYTE_LENGTH },
        { SCALAR_LENGTH },
    >(vk_bytes)
}

/// Verify Groth16 proof over the BLS12-381 curve construction. See
/// [`generic_api::verify_groth16_in_bytes`].
pub fn verify_groth16_in_bytes(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    public_inputs_as_bytes: &[u8],
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
        public_inputs_as_bytes,
        proof_points_as_bytes,
    )
}

impl FromLittleEndianByteArray<SCALAR_LENGTH> for Scalar {
    fn from_little_endian_byte_array(bytes: &[u8; SCALAR_LENGTH]) -> FastCryptoResult<Self> {
        let mut reversed = *bytes;
        reversed.reverse();
        Scalar::from_byte_array(&reversed)
    }
}

impl GTSerialize<GT_ELEMENT_BYTE_LENGTH> for GTElement {
    fn to_arkworks_bytes(&self) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
        gt_element_to_arkworks(&self.to_byte_array())
    }

    fn from_arkworks_bytes(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        GTElement::from_byte_array(&arkworks_to_gt_element(bytes))
    }
}

// An element in the quadratic extension of Fp consists of two field elements.
const FP_EXTENSION_BYTE_LENGTH: usize = 2 * FP_BYTE_LENGTH;

/// Reorder the six field extensions in a GT element according to the permutation.
/// This functions panics if one of the elements in the permutation is larger than 5.
fn generic_convert(
    bytes: &[u8; 6 * FP_EXTENSION_BYTE_LENGTH],
    permutation: &[usize; 6],
) -> [u8; 6 * FP_EXTENSION_BYTE_LENGTH] {
    let mut result = [0u8; 12 * FP_BYTE_LENGTH];
    for (from, to) in permutation.iter().enumerate() {
        let from = from * FP_EXTENSION_BYTE_LENGTH;
        let to = to * FP_EXTENSION_BYTE_LENGTH;
        result[to..to + FP_EXTENSION_BYTE_LENGTH]
            .copy_from_slice(&bytes[from..from + FP_EXTENSION_BYTE_LENGTH]);
    }
    result
        .chunks_exact_mut(FP_BYTE_LENGTH)
        .for_each(|chunk| chunk.reverse());
    result
}

/// Given a serialization of a arkworks [`PairingOutput`] element, this function returns a
/// serialization of the corresponding [`GTElement`] element. It is
/// _not_ verified whether the input is a valid serialization.
fn arkworks_to_gt_element(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
    const PERMUTATION: [usize; 6] = [0, 2, 4, 1, 3, 5];
    generic_convert(bytes, &PERMUTATION)
}

/// Given a serialization of a [`GTElement`], this function returns a
/// serialization of the corresponding element as a arkworks [`PairingOutput`] type. It is _not_
/// verified whether the input is a valid serialization..
fn gt_element_to_arkworks(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
    const PERMUTATION: [usize; 6] = [0, 3, 1, 4, 2, 5];
    generic_convert(bytes, &PERMUTATION)
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ec::pairing::PairingOutput;
    use ark_ec::Group;
    use ark_ff::Zero;
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::thread_rng;

    use fastcrypto::groups::bls12381::{G1Element, GTElement};
    use fastcrypto::groups::GroupElement;
    use fastcrypto::serde_helpers::ToFromByteArray;

    use crate::bls12381::api::{
        arkworks_to_gt_element, gt_element_to_arkworks, verify_groth16_in_bytes,
    };
    use crate::bls12381::test_helpers::from_arkworks_scalar;
    use crate::bls12381::{PreparedVerifyingKey, VerifyingKey};
    use crate::dummy_circuits::Fibonacci;
    use crate::groth16::Proof;

    #[test]
    fn test_gt_element_conversion() {
        let generator = PairingOutput::<Bls12_381>::generator();
        let mut arkworks_bytes = Vec::new();
        let mut uncompressed_bytes = Vec::new();

        // GT elements cannot be compressed, so compressed and uncompressed serialization should be the same.
        generator.serialize_compressed(&mut arkworks_bytes).unwrap();
        generator
            .serialize_uncompressed(&mut uncompressed_bytes)
            .unwrap();
        assert_eq!(arkworks_bytes, uncompressed_bytes);

        // The arkworks serialization does not match the GroupElement serialization.
        let fc_bytes = GTElement::generator().to_byte_array();
        assert_eq!(arkworks_bytes.len(), fc_bytes.len());
        assert_ne!(arkworks_bytes, fc_bytes);

        // After conversion, the arkworks serialization should match the GroupElement serialization.
        assert_eq!(arkworks_bytes, gt_element_to_arkworks(&fc_bytes));
        assert_eq!(
            arkworks_to_gt_element(&arkworks_bytes.try_into().unwrap()),
            fc_bytes
        );

        // Compare serializations of the identity element
        let arkworks_id = PairingOutput::<Bls12_381>::zero();
        let mut arkworks_bytes = Vec::new();
        arkworks_id
            .serialize_uncompressed(&mut arkworks_bytes)
            .unwrap();
        let fc_bytes = GTElement::zero().to_byte_array();
        assert_ne!(&fc_bytes.to_vec(), &arkworks_bytes);
        assert_eq!(&gt_element_to_arkworks(&fc_bytes).to_vec(), &arkworks_bytes);
        assert_eq!(
            arkworks_to_gt_element(&arkworks_bytes.try_into().unwrap()),
            fc_bytes
        );
    }

    #[test]
    fn test_verify_groth16_in_bytes_multiple_inputs() {
        let mut rng = thread_rng();

        let a = Fr::from(123);
        let b = Fr::from(456);

        let params = {
            let circuit = Fibonacci::<Fr>::new(42, a, b);
            Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
                .unwrap()
        };

        let proof = {
            let circuit = Fibonacci::<Fr>::new(42, a, b);
            Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &params, &mut rng)
                .unwrap()
        };

        // Proof::write serializes uncompressed and also adds a length to each element, so we serialize
        // each individual element here to avoid that.
        let mut proof_bytes = Vec::new();
        proof.a.serialize_compressed(&mut proof_bytes).unwrap();
        proof.b.serialize_compressed(&mut proof_bytes).unwrap();
        proof.c.serialize_compressed(&mut proof_bytes).unwrap();

        let mut vk_bytes = Vec::new();
        params.vk.serialize_compressed(&mut vk_bytes).unwrap();
        let vk = VerifyingKey::from_arkworks_format(&vk_bytes).unwrap();
        let pvk = PreparedVerifyingKey::from(&vk);

        let inputs: Vec<_> = vec![from_arkworks_scalar(&a), from_arkworks_scalar(&b)];

        let proof: Proof<G1Element> = bcs::from_bytes(&proof_bytes).unwrap();
        assert!(pvk.verify(&inputs, &proof).is_ok());

        let pvk = pvk.serialize_into_parts();

        // This circuit has two public inputs:
        let mut inputs_bytes = Vec::new();
        a.serialize_compressed(&mut inputs_bytes).unwrap();
        b.serialize_compressed(&mut inputs_bytes).unwrap();

        assert!(verify_groth16_in_bytes(
            &pvk[0],
            &pvk[1],
            &pvk[2],
            &pvk[3],
            &inputs_bytes,
            &proof_bytes
        )
        .unwrap());

        inputs_bytes[0] += 1;
        assert!(!verify_groth16_in_bytes(
            &pvk[0],
            &pvk[1],
            &pvk[2],
            &pvk[3],
            &inputs_bytes,
            &proof_bytes
        )
        .unwrap());
    }
}
