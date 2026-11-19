// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verus proofs for the fastcrypto-threshold weight reduction. See README.md.

// Lets `#[verus_spec(...)]` annotate loops, so the verified code can stay plain Rust. Verus's
// toolchain accepts this feature gate.
#![feature(proc_macro_hygiene)]

// The functions are `pub(crate)` as in fastcrypto-threshold and have no callers here.
#[allow(dead_code)]
pub mod verified_knapsack_weight_reduction;
