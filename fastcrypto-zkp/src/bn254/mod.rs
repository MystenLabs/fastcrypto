// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]
//! Groth16 verifier over the BN254 elliptic curve construction.

use derive_more::From;

/// API that takes in serialized inputs
pub mod api;

/// Groth16 SNARK verifier
pub mod verifier;

/// Poseidon hash function over BN254
pub mod poseidon;

/// Zk login structs and utilities
pub mod zk_login;

/// api
pub mod zk_login_api;

/// A field element in the BN254 construction. Thin wrapper around `api::Bn254Fr`.
#[derive(Debug, From)]
pub struct FieldElement(pub(crate) api::Bn254Fr);

/// A Groth16 proof in the BN254 construction. Thin wrapper around `ark_groth16::Proof::<ark_bn254::Bn254>`.
#[derive(Debug, From)]
pub struct Proof(pub(crate) ark_groth16::Proof<ark_bn254::Bn254>);

/// A Groth16 verifying key in the BN254 construction. Thin wrapper around `ark_groth16::VerifyingKey::<ark_bn254::Bn254>`.
#[derive(Debug, From)]
pub struct VerifyingKey(pub(crate) ark_groth16::VerifyingKey<ark_bn254::Bn254>);
