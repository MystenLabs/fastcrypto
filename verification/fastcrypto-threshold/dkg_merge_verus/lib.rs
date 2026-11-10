// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verus proofs for `Party::merge` in the fastcrypto-threshold DKG. See README.md.

// Lets `#[verus_spec(...)]` annotate loops and closures, so the verified code can stay plain Rust.
// Verus's toolchain accepts this feature gate.
#![feature(proc_macro_hygiene)]

// The functions have no callers here.
#[allow(dead_code)]
pub mod verified_dkg_merge;
