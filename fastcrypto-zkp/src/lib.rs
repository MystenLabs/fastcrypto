// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fastcrypto-zkp is an experimental crate that offers a faster implementation of the Groth16 zkSNARK
//! verifier, based on BLST, but following the same API as Arkworks' Groth16 implementation.
//! It includes benchmarks and tests to compare the performance and native formats of the two implementations.

#[macro_use]
extern crate ff;

use crate::bn254::poseidon::constants::load_constants;
use ark_ff::{BigInteger, PrimeField};
use byte_slice_cast::AsByteSlice;
use ff::PrimeField as OtherPrimeField;
use neptune::hash_type::HashType;
use neptune::matrix::transpose;
use neptune::poseidon::HashMode::Correct;
use neptune::poseidon::PoseidonConstants;
use neptune::Poseidon;
use std::str::FromStr;
use typenum::U2;

#[derive(PrimeField)]
#[PrimeFieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[PrimeFieldGenerator = "5"]
#[PrimeFieldReprEndianness = "big"]
pub struct Fr([u64; 4]);

pub mod bls12381;

pub mod bn254;

/// Simple circuits used in benchmarks and demos
pub mod dummy_circuits;

pub mod circom;

#[test]
fn test_neptune() {
    // t = 3
    let constants = load_constants();

    let m = transpose(&constants.matrices[1]);
    let c = &constants.constants[1];

    let poseidon_constants = PoseidonConstants::new_from_parameters(
        3,
        m,
        c.clone(),
        8,
        57,
        HashType::<Fr, U2>::ConstantLength(2),
    );

    let mut poseidon = Poseidon::new(&poseidon_constants);

    poseidon.input(from_str("1")).unwrap();
    poseidon.input(from_str("2")).unwrap();

    let hash = poseidon.hash_in_mode(Correct);

    let expected = crate::bn254::poseidon::PoseidonWrapper::new()
        .hash(vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("2").unwrap(),
        ])
        .unwrap();

    assert_eq!(
        hash.to_repr().as_byte_slice(),
        expected.into_bigint().to_bytes_be().as_slice()
    );
}

fn from_str(string: &str) -> Fr {
    Fr::from_str_vartime(string).unwrap()
}
