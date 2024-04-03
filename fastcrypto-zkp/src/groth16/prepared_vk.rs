// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use itertools::Itertools;
use serde::{Deserialize, Serialize};

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{deserialize_vector, GroupElement, MultiScalarMul, Pairing, Scalar};
use fastcrypto::serde_helpers::ToFromByteArray;

use crate::groth16::{PreparedVerifyingKey, Proof};

impl<G1> PreparedVerifyingKey<G1>
where
    G1: Pairing + MultiScalarMul + Serialize + for<'a> Deserialize<'a>,
    <G1 as Pairing>::Other: Serialize + for<'a> Deserialize<'a>,
    <G1 as Pairing>::Output: GroupElement + Serialize + for<'a> Deserialize<'a>,
{
    pub fn serialize_into_parts(&self) -> FastCryptoResult<Vec<Vec<u8>>> {
        let mut result = Vec::with_capacity(4);
        result.push(
            self.vk_gamma_abc
                .iter()
                .map(|g1| bcs::to_bytes(g1).map_err(|_| FastCryptoError::InvalidInput))
                .flatten_ok()
                .collect::<FastCryptoResult<Vec<u8>>>()?,
        );
        result.push(bcs::to_bytes(&self.alpha_beta).map_err(|_| FastCryptoError::InvalidInput)?);
        result.push(bcs::to_bytes(&self.gamma_neg).map_err(|_| FastCryptoError::InvalidInput)?);
        result.push(bcs::to_bytes(&self.delta_neg).map_err(|_| FastCryptoError::InvalidInput)?);
        Ok(result)
    }

    pub fn deserialize_from_parts(parts: &Vec<&[u8]>, g1_size_in_bytes: usize) -> FastCryptoResult<Self> {
        if parts.len() != 4 {
            return Err(FastCryptoError::InvalidInput);
        }

        if parts[0].len() % g1_size_in_bytes != 0 {
            return Err(FastCryptoError::InvalidInput);
        }

        let vk_gamma_abc = deserialize_vector::<G1>(parts[0], g1_size_in_bytes)?;
        let alpha_beta = bcs::from_bytes(parts[1]).map_err(|_| FastCryptoError::InvalidInput)?;
        let gamma_neg = bcs::from_bytes(parts[2]).map_err(|_| FastCryptoError::InvalidInput)?;
        let delta_neg = bcs::from_bytes(parts[3]).map_err(|_| FastCryptoError::InvalidInput)?;

        Ok(Self {
            vk_gamma_abc,
            alpha_beta,
            gamma_neg,
            delta_neg,
        })
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
    use crate::groth16::{PreparedVerifyingKey, Proof};

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
        let proof: Proof<G1Element> = bincode::deserialize(&proof_bytes).unwrap();

        let mut vk_bytes = Vec::new();
        params.vk.serialize_compressed(&mut vk_bytes).unwrap();
        let vk = bincode::deserialize(&vk_bytes).unwrap();

        let prepared_vk = PreparedVerifyingKey::from(&vk);
        let public_inputs = vec![Scalar::from(123), Scalar::from(456)];
        prepared_vk.verify(&public_inputs, &proof).unwrap()
    }
}
