// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Mul;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;

use crate::bls12381::test_helpers::{from_arkworks_proof, from_arkworks_scalar, from_arkworks_vk};
use crate::dummy_circuits::DummyCircuit;

#[test]
fn test_verify_with_processed_vk() {
    const PUBLIC_SIZE: usize = 128;
    let rng = &mut thread_rng();
    let c = DummyCircuit::<Fr> {
        a: Some(<Fr>::rand(rng)),
        b: Some(<Fr>::rand(rng)),
        num_variables: PUBLIC_SIZE,
        num_constraints: 256,
    };

    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
    let ark_proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();
    let public_input = c.a.unwrap().mul(c.b.unwrap());

    let proof = from_arkworks_proof(&ark_proof);
    let vk = from_arkworks_vk(&vk);
    let prepared_vk = crate::groth16::PreparedVerifyingKey::from(&vk);
    let public_inputs = vec![from_arkworks_scalar(&public_input)];

    assert!(prepared_vk.verify(&public_inputs, &proof).is_ok());
}
