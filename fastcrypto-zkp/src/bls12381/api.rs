// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::{
    G1_ELEMENT_BYTE_LENGTH, G1Element, G2_ELEMENT_BYTE_LENGTH,
    GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
};

use crate::groth16::api;

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

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::thread_rng;

    use fastcrypto::groups::bls12381::G1Element;
    use crate::bls12381::api::verify_groth16_in_bytes;
    use crate::bls12381::test_helpers::from_arkworks_scalar;
    use crate::bls12381::{PreparedVerifyingKey, VerifyingKey};
    use crate::dummy_circuits::Fibonacci;
    use crate::groth16::Proof;

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
