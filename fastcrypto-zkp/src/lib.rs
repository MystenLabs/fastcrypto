// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms, missing_debug_implementations)]

//! Fastcrypto-zkp is an experimental crate that offers a faster implementation of the Groth16 zkSNARK
//! verifier, based on BLST, but following the same API as Arkworks' Groth16 implementation.
//! It includes benchmarks and tests to compare the performance and native formats of the two implementations.

/// Conversions between arkworks <-> blst
pub mod conversions;

/// Simple circuits used in benchmarks and demos
pub mod dummy_circuits;

/// Groth16 SNARK verifier
pub mod verifier;

/// API that takes in serialized inputs
pub mod api;
