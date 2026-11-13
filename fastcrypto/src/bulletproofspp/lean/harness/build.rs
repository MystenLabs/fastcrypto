// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the Lean bindings in `../bindings` and the two models they use as shared libraries, and
//! records the exports the tests call.

use fastcrypto_lean_testing::build::lean_toolchain::CargoLeanCapability;
use fastcrypto_lean_testing::build::{export, lake_build, library_dependency, obj, u64};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    lake_build("../bindings");
    CargoLeanCapability::new("../bindings", "BpppHarness")
        .package("bppp_harness")
        .module("BpppHarness")
        .dependency(library_dependency(
            "../../../groups/lean/model",
            "ristretto_model",
            "RistrettoModel",
        ))
        .dependency(library_dependency("../model", "bppp_model", "BpppModel"))
        .export_signature(export("bppp_harness_verify_batch", vec![u64(), obj()]))
        .export_signature(export("bppp_harness_prove_batch", vec![u64(), obj()]))
        .build()?;
    Ok(())
}
