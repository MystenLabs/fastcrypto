// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::{deserialize_vector, GroupElement, MultiScalarMul, Pairing, Scalar};

use crate::groth16::{PreparedVerifyingKey, Proof, VerifyingKey};

/// Deserialize bytes as an Arkworks representation of a verifying key, and return a vector of the
/// four components of a prepared verified key (see more at [`PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes<G1>(vk_bytes: &[u8]) -> Result<Vec<Vec<u8>>, FastCryptoError>
where
    G1: Pairing + MultiScalarMul + Serialize + for<'a> Deserialize<'a>,
    <G1 as Pairing>::Other: Serialize + for<'a> Deserialize<'a>,
    <G1 as Pairing>::Output: GroupElement + Serialize + for<'a> Deserialize<'a>,
{
    // TODO: The serialization does not match Arkworks' format.
    let vk: VerifyingKey<G1> =
        bcs::from_bytes(vk_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    PreparedVerifyingKey::from(&vk).serialize_into_parts()
}

/// Verify Groth16 proof using the serialized form of the four components in a prepared verifying key
/// (see more at [`PreparedVerifyingKey`]), serialized proof public input, which should
/// be concatenated serialized field elements of the scalar field of [`crate::conversions::SCALAR_SIZE`]
/// bytes each, and serialized proof points.
pub fn verify_groth16_in_bytes<G1, const G1_SIZE: usize>(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError>
    where
        G1: Pairing + MultiScalarMul + Serialize + for<'a> Deserialize<'a>,
        <G1 as Pairing>::Other: Serialize + for<'a> Deserialize<'a>,
        <G1 as Pairing>::Output: GroupElement + Serialize + for<'a> Deserialize<'a>,
{
    let x = deserialize_vector::<G1::ScalarType>(proof_public_inputs_as_bytes, G1::ScalarType::SIZE_IN_BYTES)?;
    let proof = bincode::deserialize(proof_points_as_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    let blst_pvk = PreparedVerifyingKey::<G1>::deserialize_from_parts(&vec![
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    ], G1_SIZE)?;
    Ok(blst_pvk.verify(x.as_slice(), &proof).is_ok())
}

#[cfg(test)]
mod tests {
    use crate::dummy_circuits::{DummyCircuit, Fibonacci};
    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;
    use std::ops::Mul;
    use fastcrypto::groups::bls12381::{G1_ELEMENT_BYTE_LENGTH, G1Element};
    use crate::groth16::api::{prepare_pvk_bytes, verify_groth16_in_bytes};

    #[test]
    fn test_verify_groth16_in_bytes_api() {
        const PUBLIC_SIZE: usize = 128;
        let rng = &mut thread_rng();
        let c = DummyCircuit::<Fr> {
            a: Some(<Fr>::rand(rng)),
            b: Some(<Fr>::rand(rng)),
            num_variables: PUBLIC_SIZE,
            num_constraints: 10,
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
        let proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();
        let v = c.a.unwrap().mul(c.b.unwrap());
        let mut vk_bytes = vec![];
        vk.serialize_compressed(&mut vk_bytes).unwrap();

        let bytes = prepare_pvk_bytes::<G1Element>(vk_bytes.as_slice()).unwrap();
        let vk_gamma_abc_g1_bytes = &bytes[0];
        let alpha_g1_beta_g2_bytes = &bytes[1];
        let gamma_g2_neg_pc_bytes = &bytes[2];
        let delta_g2_neg_pc_bytes = &bytes[3];

        let mut proof_inputs_bytes = vec![];
        v.serialize_compressed(&mut proof_inputs_bytes).unwrap();

        let mut proof_points_bytes = vec![];
        proof.serialize_compressed(&mut proof_points_bytes).unwrap();

        // Success case.
        assert!(verify_groth16_in_bytes::<G1Element, { G1_ELEMENT_BYTE_LENGTH }>(
            vk_gamma_abc_g1_bytes,
            alpha_g1_beta_g2_bytes,
            gamma_g2_neg_pc_bytes,
            delta_g2_neg_pc_bytes,
            &proof_inputs_bytes,
            &proof_points_bytes
        )
            .unwrap());

        // Negative test: Replace the A element with a random point.
        let mut modified_proof_points_bytes = proof_points_bytes.clone();
        let _ = &G1Affine::rand(rng)
            .serialize_compressed(&mut modified_proof_points_bytes[0..48])
            .unwrap();
        assert!(!verify_groth16_in_bytes::<G1Element, { G1_ELEMENT_BYTE_LENGTH }>(
            vk_gamma_abc_g1_bytes,
            alpha_g1_beta_g2_bytes,
            gamma_g2_neg_pc_bytes,
            delta_g2_neg_pc_bytes,
            &proof_inputs_bytes,
            &modified_proof_points_bytes
        )
            .unwrap());

        // Length of verifying key is incorrect.
        let mut modified_bytes = bytes[0].clone();
        modified_bytes.pop();
        assert!(verify_groth16_in_bytes::<G1Element, { G1_ELEMENT_BYTE_LENGTH }>(
            &modified_bytes,
            alpha_g1_beta_g2_bytes,
            gamma_g2_neg_pc_bytes,
            delta_g2_neg_pc_bytes,
            &proof_inputs_bytes,
            &proof_points_bytes
        )
            .is_err());

        // Length of public inputs is incorrect.
        let mut modified_proof_inputs_bytes = proof_inputs_bytes.clone();
        modified_proof_inputs_bytes.pop();
        assert!(verify_groth16_in_bytes::<G1Element, { G1_ELEMENT_BYTE_LENGTH }>(
            vk_gamma_abc_g1_bytes,
            alpha_g1_beta_g2_bytes,
            gamma_g2_neg_pc_bytes,
            delta_g2_neg_pc_bytes,
            &modified_proof_inputs_bytes,
            &proof_points_bytes
        )
            .is_err());

        // length of proof is incorrect
        let mut modified_proof_points_bytes = proof_points_bytes.to_vec();
        modified_proof_points_bytes.pop();
        assert!(verify_groth16_in_bytes::<G1Element, { G1_ELEMENT_BYTE_LENGTH }>(
            vk_gamma_abc_g1_bytes,
            alpha_g1_beta_g2_bytes,
            gamma_g2_neg_pc_bytes,
            delta_g2_neg_pc_bytes,
            &proof_inputs_bytes,
            &modified_proof_points_bytes
        )
            .is_err());
    }

}