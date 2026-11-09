// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Opens the Lean model of `fastcrypto::groups::ristretto255`, built by `build.rs`.

use fastcrypto_lean_testing::lean_rs::LeanCapability;

/// Opens the Lean model.
pub fn open() -> LeanCapability<'static> {
    fastcrypto_lean_testing::open(
        env!("LEAN_RS_CAPABILITY_RISTRETTO_MODEL_MANIFEST"),
        "LEAN_RS_CAPABILITY_RISTRETTO_MODEL_MANIFEST",
    )
}
