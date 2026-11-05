// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Opens the Lean model of `fastcrypto_tbls::polynomial`, built by `build.rs`.

pub use lean_rs;

/// The path of the build manifest of the Lean model.
pub const MANIFEST: &str = env!("LEAN_RS_CAPABILITY_SHAMIR_MODEL_MANIFEST");
