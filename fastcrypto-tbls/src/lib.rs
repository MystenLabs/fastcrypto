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

pub mod ecies;
pub mod mocked_dkg;
pub mod polynomial;
pub mod random_oracle;
pub mod tbls;
pub mod types;

#[cfg(test)]
#[path = "tests/tbls_tests.rs"]
pub mod tbls_tests;

#[cfg(test)]
#[path = "tests/polynomial_tests.rs"]
pub mod polynomial_tests;

#[cfg(test)]
#[path = "tests/ecies_tests.rs"]
pub mod ecies_tests;

#[cfg(test)]
#[path = "tests/random_oracle_tests.rs"]
pub mod random_oracle_tests;
