// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use std::{iter, ops::Neg, ptr};

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine, Fq12};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::bn::G2Prepared;
use ark_groth16::{Groth16, PreparedVerifyingKey as ArkPreparedVerifyingKey, Proof, VerifyingKey};
use ark_relations::r1cs::SynthesisError;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};

#[cfg(test)]
#[path = "unit_tests/verifier_tests.rs"]
mod verifier_tests;

#[derive(Debug)]
pub struct PreparedVerifyingKey(ArkPreparedVerifyingKey<Bn254>);

/// Takes an input [`ark_groth16::VerifyingKey`] `vk` and returns a `PreparedVerifyingKey`. This is roughly homologous to
/// [`ark_groth16::PreparedVerifyingKey::process_vk`], but uses a blst representation of the elements.
///
/// ## Example:
/// ```
/// use ark_bn254::{Bn254, Fr};
/// use fastcrypto_zkp::dummy_circuits::Fibonacci;
/// use ark_ff::One;
/// use ark_groth16::{
///     generate_random_parameters
/// };
/// use ark_std::rand::thread_rng;
/// use fastcrypto_zkp::bn254::verifier::process_vk;
///
/// let mut rng = thread_rng();
/// let params = {
///     let c = Fibonacci::<Fr>::new(42, Fr::one(), Fr::one()); // 42 constraints, initial a = b = 1 (standard Fibonacci)
///     generate_random_parameters::<Bn254, _, _>(c, &mut rng).unwrap()
/// };
///
/// // Prepare the verification key (for proof verification). Ideally, we would like to do this only
/// // once per circuit.
/// let pvk = process_vk(&params.vk);
/// ```
pub fn process_vk(vk: &VerifyingKey<Bn254>) -> FastCryptoResult<PreparedVerifyingKey> {
    Ok(PreparedVerifyingKey(Groth16::<Bn254>::process_vk(vk).map_err(|_| FastCryptoError::GeneralOpaqueError)?))
}

/// Returns the validity of the Groth16 proof passed as argument. The format of the inputs is assumed to be in arkworks format.
/// See [`multipairing_with_processed_vk`] for the actual pairing computation details.
///
/// ## Example
/// ```
/// use fastcrypto_zkp::{dummy_circuits::Fibonacci};
/// use ark_bn254::{Bn254, Fr};
/// use ark_ff::One;
/// use ark_groth16::{
///     create_random_proof, generate_random_parameters
/// };
/// use ark_std::rand::thread_rng;
/// use fastcrypto_zkp::bn254::verifier::{process_vk, verify_with_processed_vk};
///
/// let mut rng = thread_rng();
///
/// let params = {
///     let circuit = Fibonacci::<Fr>::new(42, Fr::one(), Fr::one()); // 42 constraints, initial a = b = 1
///     generate_random_parameters::<Bn254, _, _>(circuit, &mut rng).unwrap()
/// };
///
/// // Prepare the verification key (for proof verification). Ideally, we would like to do this only
/// // once per circuit.
/// let pvk = process_vk(&params.vk).unwrap();
///
/// let proof = {
///     let circuit = Fibonacci::<Fr>::new(42, Fr::one(), Fr::one()); // 42 constraints, initial a = b = 1
///     // Create a proof with our parameters, picking a random witness assignment
///     create_random_proof(circuit, &params, &mut rng).unwrap()
/// };
///
/// // We provide the public inputs which we know are used in our circuits
/// // this must be the same as the inputs used in the proof right above.
/// let inputs: Vec<_> = [Fr::one(); 2].to_vec();
///
/// // Verify the proof
/// let r = verify_with_processed_vk(&pvk, &inputs, &proof).unwrap();
/// ```
pub fn verify_with_processed_vk(
    pvk: &PreparedVerifyingKey,
    x: &[Fr],
    proof: &Proof<Bn254>,
) -> FastCryptoResult<bool> {
    Ok(Groth16::<Bn254>::verify_with_processed_vk(&pvk.0, x, proof)
        .map_err(|_| FastCryptoError::InvalidProof)?)
}

// impl PreparedVerifyingKey {
//     /// Deserialize the prepared verifying key from the serialized fields of vk_gamma_abc_g1,
//     /// alpha_g1_beta_g2, gamma_g2_neg_pc and delta_g2_neg_pc
//     pub fn deserialize(bytes: &[u8],
//     ) -> Result<Self, FastCryptoError> {
//
//         let mut vk_gamma_abc_g1: Vec<G1Affine> = Vec::new();
//         for g1_bytes in vk_gamma_abc_g1_bytes.chunks(32) {
//             let g1 = G1Affine::deserialize(g1_bytes).map_err(|_| FastCryptoError::InvalidInput)?;
//             vk_gamma_abc_g1.push(g1);
//         }
//
//         let alpha_g1_beta_g2 = Fq12::deserialize(alpha_g1_beta_g2_bytes)
//                 .map_err(|_| FastCryptoError::InvalidInput)?;
//
//         let gamma_g2_neg_pc = G2Affine::deserialize_uncompressed(gamma_g2_neg_pc_bytes)
//             .map_err(|_| FastCryptoError::InvalidInput)?;
//
//         let delta_g2_neg_pc = G2Affine::deserialize_uncompressed(delta_g2_neg_pc_bytes)
//             .map_err(|_| FastCryptoError::InvalidInput)?;
//
//         let mut key = ArkPreparedVerifyingKey::default();
//         key.vk.gamma_abc_g1 = vk_gamma_abc_g1;
//         key.alpha_g1_beta_g2 = alpha_g1_beta_g2;
//         key.gamma_g2_neg_pc = G2Prepared::from(gamma_g2_neg_pc);
//         key.delta_g2_neg_pc = G2Prepared::from(delta_g2_neg_pc);
//
//         Ok(PreparedVerifyingKey(key))
//     }
//
//     /// Serialize the prepared verifying key to its vectors form.
//     pub fn as_serialized(&self) -> Result<Vec<Vec<u8>>, FastCryptoError> {
//         let mut res = Vec::new();
//         let mut vk_gamma = Vec::new();
//         for g1 in &self.0.vk.gamma_abc_g1 {
//             let mut g1_bytes = Vec::new();
//             g1.serialize(&mut g1_bytes)
//                 .map_err(|_| FastCryptoError::InvalidInput)?;
//             vk_gamma.append(&mut g1_bytes);
//         }
//         res.push(vk_gamma);
//
//         let mut alpha_g1_beta_g2 = Vec::new();
//         self.0.alpha_g1_beta_g2.serialize(&mut alpha_g1_beta_g2).map_err(|_| FastCryptoError::InvalidInput)?;
//         res.push(alpha_g1_beta_g2);
//
//         let mut gamma_g2_neg_pc = Vec::new();
//         self.0.gamma_g2_neg_pc.ell_coeffs[0].serialize(&mut gamma_g2_neg_pc).map_err(|_| FastCryptoError::InvalidInput)?;
//         res.push(gamma_g2_neg_pc);
//
//         let mut delta_g2_neg_pc = Vec::new();
//         self.0.delta_g2_neg_pc.ell_coeffs[0].serialize(&mut delta_g2_neg_pc).map_err(|_| FastCryptoError::InvalidInput)?;
//         res.push(delta_g2_neg_pc);
//
//         Ok(res)
//     }
// }