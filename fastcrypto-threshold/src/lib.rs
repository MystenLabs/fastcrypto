// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(not(test), forbid(unsafe_code))]
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

//! A crate that implements threshold BLS (tBLS) and distributed key generation (DKG)
//! protocols.

#[cfg(not(creusot))]
pub mod dkg_v1;
#[cfg(not(creusot))]
pub mod dl_verification;
#[cfg(not(creusot))]
pub mod ecies_v1;
#[cfg(not(creusot))]
pub mod knapsack_weight_reduction;
#[cfg(not(creusot))]
pub mod mocked_dkg;
#[cfg(not(creusot))]
pub mod nodes;
#[cfg(not(creusot))]
pub mod polynomial;
mod quorum;
#[cfg(not(creusot))]
pub mod tbls;
#[cfg(not(creusot))]
pub mod threshold_schnorr;
#[cfg(not(creusot))]
pub mod types;

// TODO: needs to use ecies_v1
// #[cfg(any(test, feature = "experimental"))]
// pub mod nidkg;

#[cfg(test)]
#[path = "tests/tbls_tests.rs"]
pub mod tbls_tests;

#[cfg(test)]
#[path = "tests/polynomial_tests.rs"]
pub mod polynomial_tests;

#[cfg(test)]
#[path = "tests/ecies_v1_tests.rs"]
pub mod ecies_v1_tests;

#[cfg(test)]
#[path = "tests/random_oracle_tests.rs"]
pub mod random_oracle_tests;

#[cfg(test)]
#[path = "tests/dkg_v1_tests.rs"]
pub mod dkg_v1_tests;

#[cfg(test)]
#[path = "tests/nodes_tests.rs"]
pub mod nodes_tests;

#[cfg(test)]
#[path = "tests/knapsack_weight_reduction_tests.rs"]
pub mod knapsack_weight_reduction_tests;

// TODO: needs to use ecies_v1
// #[cfg(test)]
// #[path = "tests/nidkg_tests.rs"]
// pub mod nidkg_tests;

#[cfg(not(creusot))]
pub mod nizk;
#[cfg(test)]
#[path = "tests/nizk_tests.rs"]
pub mod nizk_tests;
#[cfg(not(creusot))]
pub mod random_oracle;
