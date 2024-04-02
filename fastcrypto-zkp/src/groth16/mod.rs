// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Pairing};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Proof<G1: Pairing> {
    a: G1,
    b: G1::Other,
    c: G1,
}

#[derive(Debug, Deserialize)]
pub struct VerifyingKey<G1: Pairing> {
    alpha: G1,
    beta: G1::Other,
    gamma: G1::Other,
    delta: G1::Other,
    gamma_abc: Vec<G1>,
}

/// This is a helper function to store a pre-processed version of the verifying key.
/// This is roughly homologous to [`ark_groth16::data_structures::PreparedVerifyingKey`].
/// Note that contrary to Arkworks, we don't store a "prepared" version of the `gamma_neg` and
/// `delta_neg` fields because they are very large and unpractical to use in the binary API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedVerifyingKey<G1>
where
    G1: Pairing,
    <G1 as Pairing>::Output: GroupElement,
{
    /// The element vk.gamma_abc,
    /// aka the `[gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * G]`, where i spans the public inputs
    vk_gamma_abc: Vec<G1>,

    /// The element `e(alpha * G, beta * H)` in `GT`.
    alpha_beta: <G1 as Pairing>::Output,

    /// The element `- gamma * H` in `G2`, for use in pairings.
    gamma_neg: <G1 as Pairing>::Other,

    /// The element `- delta * H` in `G2`, for use in pairings.
    delta_neg: <G1 as Pairing>::Other,
}

impl<G1> From<&VerifyingKey<G1>> for PreparedVerifyingKey<G1>
where
    G1: Pairing,
    <G1 as Pairing>::Output: GroupElement,
{
    fn from(vk: &VerifyingKey<G1>) -> Self {
        PreparedVerifyingKey {
            vk_gamma_abc: vk.gamma_abc.clone(),
            alpha_beta: vk.alpha.pairing(&vk.beta),
            gamma_neg: -vk.gamma,
            delta_neg: -vk.delta,
        }
    }
}

impl<G1> PreparedVerifyingKey<G1>
where
    G1: Pairing + MultiScalarMul,
    <G1 as Pairing>::Output: GroupElement,
{
    pub fn verify(
        &self,
        public_inputs: &[G1::ScalarType],
        proof: &Proof<G1>,
    ) -> FastCryptoResult<()> {
        let prepared_inputs = self.prepare_inputs(public_inputs)?;
        self.verify_with_prepared_inputs(&prepared_inputs, proof)
    }

    pub fn verify_with_prepared_inputs(
        &self,
        prepared_inputs: &G1,
        proof: &Proof<G1>,
    ) -> FastCryptoResult<()> {
        let lhs = proof.a.pairing(&proof.b)
            + prepared_inputs.pairing(&self.gamma_neg)
            + proof.c.pairing(&self.delta_neg);

        if lhs == self.alpha_beta {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidProof)
        }
    }

    pub fn prepare_inputs(&self, public_inputs: &[G1::ScalarType]) -> FastCryptoResult<G1> {
        if (public_inputs.len() + 1) != self.vk_gamma_abc.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let prepared_input =
            self.vk_gamma_abc[0] + G1::multi_scalar_mul(public_inputs, &self.vk_gamma_abc[1..])?;
        Ok(prepared_input)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::thread_rng;
    use fastcrypto::groups::bls12381::{G1Element, Scalar};

    use crate::dummy_circuits::Fibonacci;
    use crate::groth16::{PreparedVerifyingKey, VerifyingKey as MyVerifyingKey};

    #[test]
    fn test_verification() {
        let mut rng = thread_rng();

        let a = Fr::from(123);
        let b = Fr::from(456);

        let params = {
            let circuit = Fibonacci::<Fr>::new(42, a, b);
            Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng)
                .unwrap()
        };

        let ark_proof = {
            let circuit = Fibonacci::<Fr>::new(42, a, b);
            Groth16::<Bls12_381>::create_random_proof_with_reduction(circuit, &params, &mut rng)
                .unwrap()
        };

        let mut proof_bytes = Vec::new();
        ark_proof.serialize_compressed(&mut proof_bytes).unwrap();
        let proof = bincode::deserialize(&proof_bytes).unwrap();

        let mut vk_bytes = Vec::new();
        params.vk.serialize_compressed(&mut vk_bytes).unwrap();
        let vk = bincode::deserialize::<MyVerifyingKey<G1Element>>(&vk_bytes).unwrap();

        let prepared_vk = PreparedVerifyingKey::from(&vk);
        let public_inputs = vec![Scalar::from(123), Scalar::from(456)];
        prepared_vk.verify(&public_inputs, &proof).unwrap()
    }
}
