// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::SNARK;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use proptest::{collection, prelude::*};
use std::{
    iter,
    ops::{AddAssign, Mul, Neg},
};

use crate::dummy_circuits::DummyCircuit;

#[test]
fn test_verify() {
    const PUBLIC_SIZE: usize = 128;
    let rng = &mut ark_std::test_rng();
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
