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
//! Kept out of the core `fastcrypto` crate deliberately: these schemes vendor and compile a C
//! library (see `deps/mldsa-native`, a git submodule — run `git submodule update --init` before
//! building), which `fastcrypto` itself does not need and whose build requirements (a C
//! toolchain, no wasm32-unknown-unknown support yet) shouldn't apply to consumers who only need
//! the classical schemes.
//!
//! Currently implements ML-DSA-65 (FIPS 204) on top of mldsa-native; see `PROVENANCE.md` for the
//! pinned commit.

mod sys;
