// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use)]

//! Groth16 verifier over the BN254 elliptic curve construction.

/// API that takes in serialized inputs
pub mod api;

/// Groth16 SNARK verifier
pub mod verifier;

/// Poseidon hash function over BN254
pub mod poseidon;

/// Zk login module utilities
pub mod zk_login;
