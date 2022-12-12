// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

//! An experimental crate that implements threshold BLS (tBLS) and distributed key generation (DKG)
//! protocols.

pub mod tbls;

#[cfg(test)]
#[path = "tests/tbls_tests.rs"]
pub mod tbls_tests;

pub mod mocked_dkg;
