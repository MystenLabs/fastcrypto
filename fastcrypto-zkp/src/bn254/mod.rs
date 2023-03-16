// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, missing_debug_implementations)]

//! Groth16 verifier over the BN254 elliptic curve construction.

/// API that takes in serialized inputs
pub mod api;

/// Groth16 SNARK verifier
pub mod verifier;
