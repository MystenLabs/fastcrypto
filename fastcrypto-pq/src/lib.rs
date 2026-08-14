// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

//! Post-quantum signature schemes
//!
//! Kept out of the core `fastcrypto` crate deliberately: the C backend (mldsa-native) is
//! compiled by the `mysten-mldsa-native-rs` wrapper crate this one depends on, which needs a
//! C toolchain and has no wasm32-unknown-unknown support yet. Neither requirement should
//! apply to consumers who only need the classical schemes.
//!
//! Currently implements ML-DSA-65 (FIPS 204). The exact mldsa-native pin and its update
//! procedure are documented in the wrapper crate's PROVENANCE.md.

// Each scheme is a self-contained module directory; a new scheme is a sibling directory plus
// one line here, and its tests in src/tests/<scheme>_tests.rs.
pub mod mldsa65;
pub mod sphincs;

#[cfg(test)]
#[path = "tests/mldsa65_tests.rs"]
pub mod mldsa65_tests;
