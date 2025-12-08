// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

//! A crate that implements threshold BLS (tBLS) and distributed key generation (DKG)
//! protocols.

pub mod dkg_v1;
pub mod dl_verification;
pub mod ecies_v1;
pub mod mocked_dkg;
pub mod nizk;
pub mod nodes;
pub mod polynomial;
pub mod random_oracle;
pub mod tbls;
pub mod threshold_schnorr;
pub mod types;
pub mod weight_reduction;

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

// TODO: needs to use ecies_v1
// #[cfg(test)]
// #[path = "tests/nidkg_tests.rs"]
// pub mod nidkg_tests;

#[cfg(test)]
#[path = "tests/nizk_tests.rs"]
pub mod nizk_tests;

#[cfg(test)]
#[path = "tests/super_swiper_test.rs"]
pub mod super_swiper_test;
