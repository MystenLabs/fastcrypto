// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]

//! Groth16 verifier over the BLS12-381 elliptic curve construction.

use crate::groth16;
use fastcrypto::groups::bls12381::G1Element;

/// API that takes in serialized inputs
pub mod api;

#[cfg(test)]
#[path = "unit_tests/verifier_tests.rs"]
mod verifier_tests;

#[cfg(test)]
#[path = "unit_tests/api_tests.rs"]
mod api_tests;

#[cfg(test)]
#[path = "unit_tests/test_helpers.rs"]
pub(crate) mod test_helpers;

/// A prepared Groth16 verifying key in the BLS12-381 construction.
pub type PreparedVerifyingKey = groth16::PreparedVerifyingKey<G1Element>;

/// A Groth16 verifying key in the BLS12-381 construction.
pub type VerifyingKey = groth16::VerifyingKey<G1Element>;

/// A Groth16 proof in the BLS12-381 construction.
pub type Proof = groth16::Proof<G1Element>;
