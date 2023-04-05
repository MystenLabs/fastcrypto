// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]

//! Groth16 verifier over the BLS12-381 elliptic curve construction.

use derive_more::From;

/// Conversions between arkworks <-> blst
pub mod conversions;

/// Groth16 SNARK verifier
pub mod verifier;

/// API that takes in serialized inputs
pub mod api;

/// A field element in the BLS12-381 construction. Thin wrapper around `conversions::BlsFr`.
#[derive(Debug, From, Copy, Clone)]
pub struct FieldElement(pub(crate) conversions::BlsFr);

/// A Groth16 proof in the BLS12-381 construction. Thin wrapper around `ark_groth16::Proof::<ark_bls12_381::Bls12_381>`.
#[derive(Debug, From)]
pub struct Proof(pub(crate) ark_groth16::Proof<ark_bls12_381::Bls12_381>);

/// A Groth16 verifying key in the BLS12-381 construction. Thin wrapper around `ark_groth16::VerifyingKey::<ark_bls12_381::Bls12_381>`.
#[derive(Debug, From)]
pub struct VerifyingKey(pub(crate) ark_groth16::VerifyingKey<ark_bls12_381::Bls12_381>);
