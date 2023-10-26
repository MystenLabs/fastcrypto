// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;
use std::ops::Neg;

use ark_bn254::{Bn254, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::bn::G2Prepared;
use ark_ec::pairing::Pairing;
use ark_groth16::{Groth16, PreparedVerifyingKey as ArkPreparedVerifyingKey};
use ark_snark::SNARK;

use crate::bn254::api::SCALAR_SIZE;
use crate::bn254::{FieldElement, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};

#[cfg(test)]
#[path = "unit_tests/verifier_tests.rs"]
mod verifier_tests;

/// This is a helper function to store a pre-processed version of the verifying key.
/// This is roughly homologous to [`ark_groth16::data_structures::PreparedVerifyingKey`].
/// Note that contrary to Arkworks, we don't store a "prepared" version of the gamma_g2_neg_pc,
/// delta_g2_neg_pc fields because they are very large and unpractical to use in the binary api.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedVerifyingKey {
    /// The element vk.gamma_abc_g1,
    /// aka the `[gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * G]`, where i spans the public inputs
    pub vk_gamma_abc_g1: Vec<G1Affine>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: Fq12,
    /// The element `- gamma * H` in `E::G2`, for use in pairings.
    pub gamma_g2_neg_pc: G2Affine,
    /// The element `- delta * H` in `E::G2`, for use in pairings.
    pub delta_g2_neg_pc: G2Affine,
}

impl PreparedVerifyingKey {
    /// Verify Groth16 proof using the prepared verifying key (see more at
    /// [`PreparedVerifyingKey`]), a vector of public inputs and
    /// the proof.
    pub fn verify(
        &self,
        public_inputs: &[FieldElement],
        proof: &Proof,
    ) -> Result<bool, FastCryptoError> {
        let x: Vec<Fr> = public_inputs.iter().map(|x| x.0).collect();
        Groth16::<Bn254>::verify_with_processed_vk(&self.into(), &x, &proof.0)
            .map_err(|e| FastCryptoError::GeneralError(e.to_string()))
    }

    /// Serialize the prepared verifying key to its vectors form.
    pub fn serialize(&self) -> Result<Vec<Vec<u8>>, FastCryptoError> {
        let mut res = Vec::new();

        let mut vk_gamma = Vec::new();
        for g1 in &self.vk_gamma_abc_g1 {
            let mut g1_bytes = Vec::new();
            g1.serialize_compressed(&mut g1_bytes)
                .map_err(|_| FastCryptoError::InvalidInput)?;
            vk_gamma.append(&mut g1_bytes);
        }
        res.push(vk_gamma);

        let mut fq12 = Vec::new();
        self.alpha_g1_beta_g2
            .serialize_compressed(&mut fq12)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        res.push(fq12);

        let mut gamma_bytes = Vec::new();
        self.gamma_g2_neg_pc
            .serialize_compressed(&mut gamma_bytes)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        res.push(gamma_bytes);

        let mut delta_bytes = Vec::new();
        self.delta_g2_neg_pc
            .serialize_compressed(&mut delta_bytes)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        res.push(delta_bytes);
        Ok(res)
    }

    /// Deserialize the prepared verifying key from the serialized fields of vk_gamma_abc_g1,
    /// alpha_g1_beta_g2, gamma_g2_neg_pc, delta_g2_neg_pc
    pub fn deserialize<V: Borrow<[u8]>>(bytes: &Vec<V>) -> Result<Self, FastCryptoError> {
        if bytes.len() != 4 {
            return Err(FastCryptoError::InputLengthWrong(bytes.len()));
        }

        let vk_gamma_abc_g1_bytes = bytes[0].borrow();
        if vk_gamma_abc_g1_bytes.len() % SCALAR_SIZE != 0 {
            return Err(FastCryptoError::InvalidInput);
        }

        let mut vk_gamma_abc_g1: Vec<G1Affine> = Vec::new();
        for g1_bytes in vk_gamma_abc_g1_bytes.chunks(SCALAR_SIZE) {
            let g1 = G1Affine::deserialize_compressed(g1_bytes)
                .map_err(|_| FastCryptoError::InvalidInput)?;
            vk_gamma_abc_g1.push(g1);
        }

        let alpha_g1_beta_g2 = Fq12::deserialize_compressed(bytes[1].borrow())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        let gamma_g2_neg_pc = G2Affine::deserialize_compressed(bytes[2].borrow())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        let delta_g2_neg_pc = G2Affine::deserialize_compressed(bytes[3].borrow())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        Ok(PreparedVerifyingKey {
            vk_gamma_abc_g1,
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
        })
    }
}

impl From<&PreparedVerifyingKey> for ArkPreparedVerifyingKey<Bn254> {
    /// Returns a [`ark_groth16::data_structures::PreparedVerifyingKey`] corresponding to this for
    /// usage in the arkworks api.
    fn from(pvk: &PreparedVerifyingKey) -> Self {
        // Note that not all the members are set here, but we set enough to be able to run
        // Groth16::<Bn254>::verify_with_processed_vk.
        let mut ark_pvk = ArkPreparedVerifyingKey::default();
        ark_pvk.vk.gamma_abc_g1 = pvk.vk_gamma_abc_g1.clone();
        ark_pvk.alpha_g1_beta_g2 = pvk.alpha_g1_beta_g2;
        ark_pvk.gamma_g2_neg_pc = G2Prepared::from(&pvk.gamma_g2_neg_pc);
        ark_pvk.delta_g2_neg_pc = G2Prepared::from(&pvk.delta_g2_neg_pc);
        ark_pvk
    }
}

impl From<&VerifyingKey> for PreparedVerifyingKey {
    /// Takes an input [`ark_groth16::VerifyingKey`] `vk` and returns a `PreparedVerifyingKey`. This is roughly homologous to
    /// [`ark_groth16::PreparedVerifyingKey::process_vk`].
    ///
    /// ## Example:
    /// ```
    /// use fastcrypto_zkp::{dummy_circuits::Fibonacci};
    /// use ark_bn254::{Bn254, Fr};
    /// use ark_ff::One;
    /// use ark_groth16::Groth16;
    /// use ark_std::rand::thread_rng;
    /// use fastcrypto_zkp::bn254::verifier::PreparedVerifyingKey;
    /// use fastcrypto_zkp::bn254::VerifyingKey;
    ///
    /// let mut rng = thread_rng();
    /// let params = {
    ///     let c = Fibonacci::<Fr>::new(42, Fr::one(), Fr::one()); // 42 constraints, initial a = b = 1 (standard Fibonacci)
    ///     Groth16::<Bn254>::generate_random_parameters_with_reduction(c, &mut rng).unwrap()
    /// };
    ///
    /// // Prepare the verification key (for proof verification). Ideally, we would like to do this only
    /// // once per circuit.
    /// let pvk = PreparedVerifyingKey::from(&VerifyingKey::from(params.vk));
    /// ```
    fn from(vk: &VerifyingKey) -> Self {
        (&vk.0).into()
    }
}

impl VerifyingKey {
    /// Deserialize a serialized Groth16 verifying key in compressed format using arkworks' canonical serialisation format: https://docs.rs/ark-serialize/latest/ark_serialize/.
    pub fn deserialize(bytes: &[u8]) -> FastCryptoResult<Self> {
        ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(bytes)
            .map(VerifyingKey)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl From<&ark_groth16::VerifyingKey<Bn254>> for PreparedVerifyingKey {
    fn from(vk: &ark_groth16::VerifyingKey<Bn254>) -> Self {
        PreparedVerifyingKey {
            vk_gamma_abc_g1: vk.gamma_abc_g1.clone(),
            alpha_g1_beta_g2: Bn254::pairing(vk.alpha_g1, vk.beta_g2).0,
            gamma_g2_neg_pc: vk.gamma_g2.neg(),
            delta_g2_neg_pc: vk.delta_g2.neg(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::bn254::verifier::PreparedVerifyingKey;
    use crate::dummy_circuits::DummyCircuit;
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::rand::thread_rng;
    use ark_std::UniformRand;

    #[test]
    fn test_serialization() {
        const PUBLIC_SIZE: usize = 128;
        let rng = &mut thread_rng();
        let c = DummyCircuit::<Fr> {
            a: Some(<Fr>::rand(rng)),
            b: Some(<Fr>::rand(rng)),
            num_variables: PUBLIC_SIZE,
            num_constraints: 10,
        };
        let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();
        let pvk = PreparedVerifyingKey::from(&vk);

        let serialized = pvk.serialize().unwrap();
        let deserialized = PreparedVerifyingKey::deserialize(&serialized).unwrap();
        assert_eq!(pvk, deserialized);
    }
}
