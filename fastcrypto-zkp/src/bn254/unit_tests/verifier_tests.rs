// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;
use std::ops::Mul;

use crate::dummy_circuits::DummyCircuit;

#[test]
fn test_verify() {
    const PUBLIC_SIZE: usize = 128;
    let rng = &mut thread_rng();
    let c = DummyCircuit::<Fr> {
        a: Some(<Fr>::rand(rng)),
        b: Some(<Fr>::rand(rng)),
        num_variables: PUBLIC_SIZE,
        num_constraints: 65536,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c, rng).unwrap();
    let proof = Groth16::<Bn254>::prove(&pk, c, rng).unwrap();
    let v = c.a.unwrap().mul(c.b.unwrap());

    assert!(Groth16::<Bn254>::verify(&vk, &[v], &proof).unwrap());
}
