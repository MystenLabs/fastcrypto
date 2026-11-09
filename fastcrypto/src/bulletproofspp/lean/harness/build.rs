// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the Lean model in `../model` and its two dependencies as shared libraries, and records
//! the export the tests call.

use fastcrypto_lean_testing::build::lean_toolchain::{CargoLeanCapability, LeanLibraryDependency};
use fastcrypto_lean_testing::build::{export, obj, u64};
use std::path::Path;
use std::process::Command;

const RISTRETTO_MODEL: &str = "../../../groups/lean/model";
const BPPP_MODEL: &str = "../../../../../../bppp-lean-master/model";

fn dependency(dir: &str, package: &str, module: &str) -> LeanLibraryDependency {
    println!("cargo:rerun-if-changed=../model/{dir}");
    let library = format!(
        "lib{}_{module}.{}",
        package.replace('_', "__"),
        std::env::consts::DLL_EXTENSION
    );
    let path = Path::new("../model")
        .join(dir)
        .join(".lake/build/lib")
        .join(library)
        .canonicalize()
        .expect("the Lean library was built");
    LeanLibraryDependency::path(path)
        .export_symbols_for_dependents()
        .initializer(package, module)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The capability below only rebuilds when files in `../model` itself change.
    let status = Command::new("lake")
        .arg("build")
        .current_dir("../model")
        .status()?;
    assert!(status.success(), "lake build failed");

    CargoLeanCapability::new("../model", "BpppHarness")
        .package("bppp_harness")
        .module("BpppHarness")
        .dependency(dependency(
            RISTRETTO_MODEL,
            "ristretto_model",
            "RistrettoModel",
        ))
        .dependency(dependency(BPPP_MODEL, "bppp_model", "BpppModel"))
        .export_signature(export("bppp_harness_verify_batch", vec![u64(), obj()]))
        .export_signature(export("bppp_harness_prove_batch", vec![u64(), obj()]))
        .build()?;
    Ok(())
}
