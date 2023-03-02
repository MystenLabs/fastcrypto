// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{Bn254, Fr};
use ark_groth16::{create_random_proof, generate_random_parameters};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use crate::bn254::api::verify_groth16_in_bytes;
use crate::bn254::verifier::{process_vk, verify_with_processed_vk};
use crate::dummy_circuits::Fibonacci;

// #[test]
// fn test_verify_groth16_in_bytes_multiple_inputs() {
//     let mut rng = thread_rng();
//
//     let a = Fr::from(123);
//     let b = Fr::from(456);
//
//     let params = {
//         let circuit = Fibonacci::<Fr>::new(42, a, b);
//         generate_random_parameters::<Bn254, _, _>(circuit, &mut rng).unwrap()
//     };
//
//     let pvk = process_vk(&params.vk).unwrap();
//
//     let proof = {
//         let circuit = Fibonacci::<Fr>::new(42, a, b);
//         create_random_proof(circuit, &params, &mut rng).unwrap()
//     };
//
//     let inputs: Vec<_> = [a, b].to_vec();
//     assert!(verify_with_processed_vk(&pvk, &inputs, &proof).unwrap());
//
//     let pvk = pvk.as_serialized().unwrap();
//
//     // This circuit has two public inputs:
//     let mut inputs_bytes = Vec::new();
//     a.serialize(&mut inputs_bytes).unwrap();
//     b.serialize(&mut inputs_bytes).unwrap();
//
//     // Proof::write serializes uncompressed and also adds a length to each element, so we serialize
//     // each individual element here to avoid that.
//     let mut proof_bytes = Vec::new();
//     proof.a.serialize(&mut proof_bytes).unwrap();
//     proof.b.serialize(&mut proof_bytes).unwrap();
//     proof.c.serialize(&mut proof_bytes).unwrap();
//
//     assert!(verify_groth16_in_bytes(
//         &pvk[0],
//         &pvk[1],
//         &pvk[2],
//         &pvk[3],
//         &inputs_bytes,
//         &proof_bytes
//     )
//         .unwrap());
//
//     inputs_bytes[0] += 1;
//     assert!(!verify_groth16_in_bytes(
//         &pvk[0],
//         &pvk[1],
//         &pvk[2],
//         &pvk[3],
//         &inputs_bytes,
//         &proof_bytes
//     )
//         .unwrap());
// }