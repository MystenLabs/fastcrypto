// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Runs the Creusot proofs on the production source of the verified part of the weight
//! reduction. The file is included as is, so the proofs are about the code that ships. See the
//! module documentation of `verified.rs` and README.md for what is proved.

// The functions are `pub(crate)` in fastcrypto-tbls and have no callers here.
#[allow(dead_code)]
#[path = "../../src/knapsack_weight_reduction/verified.rs"]
pub mod verified;
