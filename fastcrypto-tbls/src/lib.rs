// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms, missing_debug_implementations)]

//! An experimental crate that implements threshold BLS (tBLS) and distributed key generation (DKG)
//! protocols.

/// Emulates the outputs of non-secure DKG with fixed keys.
pub mod fake_tbls_key_generator;

#[cfg(test)]
#[path = "tests/fake_tbls_key_generator_tests.rs"]
pub mod fake_tbls_key_generator_tests;
