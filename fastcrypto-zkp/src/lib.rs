// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms, missing_debug_implementations)]

//! Fastcrypto-proving is a crate that offers a faster implementation of the Groth16 zkSNARK
//! verifier, based on BLST, but following the same API as Arkworks' Groth16 implementation.

/// Conversions between arkworks <-> blst
pub mod conversions;

#[doc(hidden)]
pub mod dummy_circuit;

/// Groth16 SNARK verifier
pub mod verifier;
