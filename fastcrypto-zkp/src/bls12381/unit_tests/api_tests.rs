// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::api::{prepare_pvk_bytes, verify_groth16_in_bytes};
use crate::bls12381::verifier::{process_vk_special, verify_with_processed_vk};
use crate::bls12381::FieldElement;
use crate::dummy_circuits::{DummyCircuit, Fibonacci};
use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use ark_std::UniformRand;
use std::ops::Mul;

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
    let blst_pvk = process_vk_special(&vk.into());

    let bytes = blst_pvk.as_serialized().unwrap();
    let vk_gamma_abc_g1_bytes = &bytes[0];
    let alpha_g1_beta_g2_bytes = &bytes[1];
    let gamma_g2_neg_pc_bytes = &bytes[2];
    let delta_g2_neg_pc_bytes = &bytes[3];

    let mut proof_inputs_bytes = vec![];
    v.serialize_compressed(&mut proof_inputs_bytes).unwrap();

    let mut proof_points_bytes = vec![];
    proof.serialize_compressed(&mut proof_points_bytes).unwrap();

    // Success case.
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &proof_inputs_bytes,
        &proof_points_bytes
    )
    .is_ok());

    // Length of verifying key is incorrect.
    let mut modified_bytes = bytes[0].clone();
    modified_bytes.pop();
    assert!(verify_groth16_in_bytes(
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
    assert!(verify_groth16_in_bytes(
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
    assert!(verify_groth16_in_bytes(
        vk_gamma_abc_g1_bytes,
        alpha_g1_beta_g2_bytes,
        gamma_g2_neg_pc_bytes,
        delta_g2_neg_pc_bytes,
        &proof_inputs_bytes,
        &modified_proof_points_bytes
    )
    .is_err());
}

#[test]
fn test_prepare_pvk_bytes() {
    const PUBLIC_SIZE: usize = 128;
    let rng = &mut thread_rng();
    let c = DummyCircuit::<Fr> {
        a: Some(<Fr>::rand(rng)),
        b: Some(<Fr>::rand(rng)),
        num_variables: PUBLIC_SIZE,
        num_constraints: 10,
    };

    let (_, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();

    let mut vk_bytes = vec![];
    vk.serialize_compressed(&mut vk_bytes).unwrap();

    // Success case.
    assert!(prepare_pvk_bytes(vk_bytes.as_slice()).is_ok());

    // Length of verifying key is incorrect.
    let mut modified_bytes = vk_bytes.clone();
    modified_bytes.pop();
    assert!(prepare_pvk_bytes(&modified_bytes).is_err());
}

#[test]
fn test_verify_groth16_in_bytes_multiple_inputs() {
    let mut rng = thread_rng();

    let a = Fr::from(123);
    let b = Fr::from(456);

    let params = {
        let circuit = Fibonacci::<Fr>::new(42, a, b);
        Groth16::<Bls12_381>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap()
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

    let pvk = process_vk_special(&params.vk.into());

    let inputs: Vec<_> = [FieldElement(a), FieldElement(b)].to_vec();
    assert!(verify_with_processed_vk(&pvk, &inputs, &proof.into()).unwrap());

    let pvk = pvk.as_serialized().unwrap();

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
