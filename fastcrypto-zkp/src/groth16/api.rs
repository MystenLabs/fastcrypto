// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{
    deserialize_vector, serialize_vector, GroupElement, MultiScalarMul, Pairing,
};
use fastcrypto::serde_helpers::ToFromByteArray;

use crate::groth16::{PreparedVerifyingKey, VerifyingKey};

/// Deserialize bytes as an Arkworks representation of a verifying key, and return a vector of the
/// four components of a prepared verified key (see more at [`PreparedVerifyingKey`]).
pub fn prepare_pvk_bytes<
    G1,
    const G1_SIZE: usize,
    const G2_SIZE: usize,
    const GT_SIZE: usize,
    const FR_SIZE: usize,
>(
    vk_bytes: &[u8],
) -> Result<Vec<Vec<u8>>, FastCryptoError>
where
    G1: Pairing + MultiScalarMul + for<'a> Deserialize<'a> + ToFromByteArray<G1_SIZE>,
    <G1 as Pairing>::Other: for<'a> Deserialize<'a> + ToFromByteArray<G2_SIZE>,
    <G1 as Pairing>::Output: GroupElement + for<'a> Deserialize<'a> + ToFromByteArray<GT_SIZE>,
{
    // TODO: The serialization does not match Arkworks' format.
    let vk = VerifyingKey::<G1>::from_arkworks_format::<G1_SIZE, G2_SIZE>(vk_bytes)?;
    Ok(PreparedVerifyingKey::from(&vk).serialize_into_parts())
}

/// Verify Groth16 proof using the serialized form of the four components in a prepared verifying key
/// (see more at [`PreparedVerifyingKey`]), serialized proof public input, which should
/// be concatenated serialized field elements of the scalar field of [`crate::conversions::SCALAR_SIZE`]
/// bytes each, and serialized proof points.
pub fn verify_groth16_in_bytes<
    G1,
    const G1_SIZE: usize,
    const G2_SIZE: usize,
    const GT_SIZE: usize,
    const FR_SIZE: usize,
>(
    vk_gamma_abc_g1_bytes: &[u8],
    alpha_g1_beta_g2_bytes: &[u8],
    gamma_g2_neg_pc_bytes: &[u8],
    delta_g2_neg_pc_bytes: &[u8],
    proof_public_inputs_as_bytes: &[u8],
    proof_points_as_bytes: &[u8],
) -> Result<bool, FastCryptoError>
where
    G1: Pairing + MultiScalarMul + ToFromByteArray<G1_SIZE> + for<'a> Deserialize<'a>,
    <G1 as Pairing>::Other: ToFromByteArray<G2_SIZE> + for<'a> Deserialize<'a>,
    <G1 as Pairing>::Output: GroupElement + ToFromByteArray<GT_SIZE> + for<'a> Deserialize<'a>,
    G1::ScalarType: ToFromByteArray<FR_SIZE> + for<'a> Deserialize<'a>,
{
    let x = deserialize_vector::<FR_SIZE, G1::ScalarType>(proof_public_inputs_as_bytes)?;
    let proof =
        bincode::deserialize(proof_points_as_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
    println!("proof: {:?}", proof);

    let blst_pvk = PreparedVerifyingKey::<G1>::deserialize_from_parts(&vec![
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
    ])?;
    Ok(blst_pvk.verify(x.as_slice(), &proof).is_ok())
}

impl<G1: Pairing> VerifyingKey<G1> {
    pub fn from_arkworks_format<const G1_SIZE: usize, const G2_SIZE: usize>(
        vk_bytes: &[u8],
    ) -> FastCryptoResult<Self>
    where
        G1: ToFromByteArray<G1_SIZE>,
        <G1 as Pairing>::Other: ToFromByteArray<G2_SIZE>,
    {
        if (vk_bytes.len() - (G1_SIZE + 3 * G2_SIZE + 8)) % G1_SIZE != 0 {
            return Err(FastCryptoError::InvalidInput);
        }

        let mut i = 0;

        let alpha = G1::from_byte_array(
            vk_bytes[i..G1_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        i += G1_SIZE;

        let beta = G1::Other::from_byte_array(
            vk_bytes[i..i + G2_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        i += G2_SIZE;

        let gamma = G1::Other::from_byte_array(
            vk_bytes[i..i + G2_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        i += G2_SIZE;

        let delta = G1::Other::from_byte_array(
            vk_bytes[i..i + G2_SIZE]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        i += G2_SIZE;

        let n = u64::from_le_bytes(
            vk_bytes[i..i + 8]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        );

        i += 8;

        let gamma_abc = deserialize_vector::<G1_SIZE, G1>(&vk_bytes[i..])
            .map_err(|_| FastCryptoError::InvalidInput)?;

        if gamma_abc.len() != n as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(VerifyingKey {
            alpha,
            beta,
            gamma,
            delta,
            gamma_abc,
        })
    }
}

impl<G1: Pairing> PreparedVerifyingKey<G1>
where
    <G1 as Pairing>::Output: GroupElement,
{
    pub fn serialize_into_parts<const G1_SIZE: usize, const G2_SIZE: usize, const GT_SIZE: usize>(
        &self,
    ) -> Vec<Vec<u8>>
    where
        G1: ToFromByteArray<G1_SIZE>,
        G1::Other: ToFromByteArray<G2_SIZE>,
        <G1 as Pairing>::Output: ToFromByteArray<GT_SIZE>,
    {
        let mut result = Vec::with_capacity(4);
        result.push(serialize_vector(&self.vk_gamma_abc));
        result.push(self.alpha_beta.to_byte_array().to_vec());
        result.push(self.gamma_neg.to_byte_array().to_vec());
        result.push(self.delta_neg.to_byte_array().to_vec());
        result
    }

    pub fn deserialize_from_parts<
        const G1_SIZE: usize,
        const G2_SIZE: usize,
        const GT_SIZE: usize,
    >(
        parts: &Vec<&[u8]>,
    ) -> FastCryptoResult<Self>
    where
        G1: ToFromByteArray<G1_SIZE>,
        G1::Other: ToFromByteArray<G2_SIZE>,
        <G1 as Pairing>::Output: ToFromByteArray<GT_SIZE>,
    {
        if parts.len() != 4 {
            return Err(FastCryptoError::InvalidInput);
        }

        if parts[0].len() % G1_SIZE != 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        let vk_gamma_abc = deserialize_vector::<G1_SIZE, G1>(parts[0])?;
        let alpha_beta = <G1 as Pairing>::Output::from_byte_array(
            parts[1]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;
        let gamma_neg = <G1 as Pairing>::Other::from_byte_array(
            parts[2]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;
        let delta_neg = <G1 as Pairing>::Other::from_byte_array(
            parts[3]
                .try_into()
                .map_err(|_| FastCryptoError::InvalidInput)?,
        )?;

        Ok(Self {
            vk_gamma_abc,
            alpha_beta,
            gamma_neg,
            delta_neg,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;

    use ark_bls12_381::{Bls12_381, Fr, G1Affine};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;
    use blake2::digest::Mac;

    use fastcrypto::groups::bls12381::{
        G1Element, Scalar, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH,
        SCALAR_LENGTH,
    };
    use fastcrypto::groups::serialize_vector;

    use crate::bls12381::conversions::bls_fr_to_blst_fr;
    use crate::dummy_circuits::DummyCircuit;
    use crate::groth16::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
    use crate::groth16::{PreparedVerifyingKey, Proof, VerifyingKey};

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
        let ark_proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();
        let result = c.a.unwrap().mul(c.b.unwrap());
        let public_inputs = vec![Scalar(bls_fr_to_blst_fr(&result))];
        let mut vk_bytes = vec![];
        vk.serialize_compressed(&mut vk_bytes).unwrap();

        let bytes = prepare_pvk_bytes::<
            G1Element,
            G1_ELEMENT_BYTE_LENGTH,
            G2_ELEMENT_BYTE_LENGTH,
            GT_ELEMENT_BYTE_LENGTH,
            SCALAR_LENGTH,
        >(vk_bytes.as_slice())
        .unwrap();
        let vk_gamma_abc_g1_bytes = &bytes[0];
        let alpha_g1_beta_g2_bytes = &bytes[1];
        let gamma_g2_neg_pc_bytes = &bytes[2];
        let delta_g2_neg_pc_bytes = &bytes[3];

        let mut public_inputs_bytes = serialize_vector(&public_inputs);

        println!("ark proof: {:?}", ark_proof);

        let mut proof_bytes = Vec::new();
        ark_proof.serialize_compressed(&mut proof_bytes).unwrap();
        let proof: Proof<G1Element> = bincode::deserialize(&proof_bytes).unwrap();
        let vk = VerifyingKey::from_arkworks_format(&vk_bytes).unwrap();

        let prepared_vk = PreparedVerifyingKey::from(&vk);

        assert!(prepared_vk.verify(&public_inputs, &proof).is_ok());

        // Success case.
        assert!(verify_groth16_in_bytes::<
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
            &public_inputs_bytes,
            &proof_bytes
        )
        .unwrap());

        // Negative test: Replace the A element with a random point.
        let mut modified_proof_points_bytes = proof_bytes.clone();
        let _ = &G1Affine::rand(rng)
            .serialize_compressed(&mut modified_proof_points_bytes[0..48])
            .unwrap();
        assert!(!verify_groth16_in_bytes::<
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
            &public_inputs_bytes,
            &modified_proof_points_bytes
        )
        .unwrap());

        // Length of verifying key is incorrect.
        let mut modified_bytes = bytes[0].clone();
        modified_bytes.pop();
        assert!(verify_groth16_in_bytes::<
            G1Element,
            { G1_ELEMENT_BYTE_LENGTH },
            { G2_ELEMENT_BYTE_LENGTH },
            { GT_ELEMENT_BYTE_LENGTH },
            { SCALAR_LENGTH },
        >(
            &modified_bytes,
            alpha_g1_beta_g2_bytes,
            gamma_g2_neg_pc_bytes,
            delta_g2_neg_pc_bytes,
            &public_inputs_bytes,
            &proof_bytes
        )
        .is_err());

        // Length of public inputs is incorrect.
        let mut modified_proof_inputs_bytes = public_inputs_bytes.clone();
        modified_proof_inputs_bytes.pop();
        assert!(verify_groth16_in_bytes::<
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
            &modified_proof_inputs_bytes,
            &proof_bytes
        )
        .is_err());

        // length of proof is incorrect
        let mut modified_proof_points_bytes = proof_bytes.to_vec();
        modified_proof_points_bytes.pop();
        assert!(verify_groth16_in_bytes::<
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
            &public_inputs_bytes,
            &modified_proof_points_bytes
        )
        .is_err());
    }
}
