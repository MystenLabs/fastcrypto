// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bn254::api::verify_groth16_in_bytes;
use crate::dummy_circuits::Fibonacci;
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;

#[test]
fn test_verify_groth16_in_bytes_multiple_inputs() {
    let mut rng = thread_rng();

    let a = Fr::from(123);
    let b = Fr::from(456);

    let params = {
        let circuit = Fibonacci::<Fr>::new(42, a, b);
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap()
    };

    let proof = {
        let circuit = Fibonacci::<Fr>::new(42, a, b);
        Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &params, &mut rng).unwrap()
    };

    let inputs: Vec<_> = [a, b].to_vec();
    assert!(Groth16::<Bn254>::verify(&params.vk, &inputs, &proof).unwrap());

    let mut vk_bytes = Vec::new();
    params.vk.serialize_compressed(&mut vk_bytes).unwrap();

    // This circuit has two public inputs:
    let mut inputs_bytes = Vec::new();
    a.serialize_compressed(&mut inputs_bytes).unwrap();
    b.serialize_compressed(&mut inputs_bytes).unwrap();

    // Proof::write serializes uncompressed and also adds a length to each element, so we serialize
    // each individual element here to avoid that.
    let mut proof_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_bytes).unwrap();
    proof.b.serialize_compressed(&mut proof_bytes).unwrap();
    proof.c.serialize_compressed(&mut proof_bytes).unwrap();

    assert!(verify_groth16_in_bytes(&vk_bytes, &inputs_bytes, &proof_bytes).unwrap());

    inputs_bytes[0] += 1;
    assert!(!verify_groth16_in_bytes(&vk_bytes, &inputs_bytes, &proof_bytes).unwrap());
}
