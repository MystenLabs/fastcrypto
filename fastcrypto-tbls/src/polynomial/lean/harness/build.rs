// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the Lean model in `../model` as a shared library and records its exports.

use fastcrypto_lean_testing::build::lean_toolchain::CargoLeanCapability;
use fastcrypto_lean_testing::build::{export, obj, u64};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    CargoLeanCapability::new("../model", "ShamirModel")
        .package("shamir_model")
        .module("ShamirModel")
        .export_signature(export("shamir_model_degree_bound", vec![obj()]))
        .export_signature(export("shamir_model_c0", vec![obj()]))
        .export_signature(export("shamir_model_eval", vec![obj(), u64()]))
        .export_signature(export("shamir_model_add", vec![obj(), obj()]))
        .export_signature(export("shamir_model_recover_c0", vec![u64(), obj(), obj()]))
        .build()?;
    Ok(())
}
