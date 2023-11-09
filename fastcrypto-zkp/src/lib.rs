// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Fastcrypto-zkp is an experimental crate that offers a faster implementation of the Groth16 zkSNARK
//! verifier, based on BLST, but following the same API as Arkworks' Groth16 implementation.
//! It includes benchmarks and tests to compare the performance and native formats of the two implementations.

extern crate ff;

use ff::PrimeField;

/// Definition of the BN254 prime field.
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
