// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]

//! Groth16 verifier over the BLS12-381 elliptic curve construction.

use fastcrypto::groups::bls12381::G1Element;

use crate::groth16;

/// API that takes in serialized inputs
pub mod api;

/// A prepared Groth16 verifying key in the BLS12-381 construction.
pub type PreparedVerifyingKey = groth16::PreparedVerifyingKey<G1Element>;

/// A Groth16 verifying key in the BLS12-381 construction.
pub type VerifyingKey = groth16::VerifyingKey<G1Element>;

/// A Groth16 proof in the BLS12-381 construction.
pub type Proof = groth16::Proof<G1Element>;
