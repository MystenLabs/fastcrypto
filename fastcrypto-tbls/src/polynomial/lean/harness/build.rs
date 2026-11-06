// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the Lean model in `../model` as a shared library and records its exports.

use lean_toolchain::{
    CargoLeanCapability, LeanExportAbiRepr as Repr, LeanExportArgAbi as Arg,
    LeanExportOwnership as Own, LeanExportResultConvention, LeanExportReturnAbi,
    LeanExportSignature,
};

fn obj() -> Arg {
    Arg::new(Repr::LeanObject, Own::Owned)
}

fn u64_arg() -> Arg {
    Arg::new(Repr::U64, Own::None)
}

fn export(name: &str, args: Vec<Arg>) -> LeanExportSignature {
    LeanExportSignature::function(
        name,
        args,
        LeanExportReturnAbi::new(
            Repr::LeanObject,
            Own::Owned,
            LeanExportResultConvention::Pure,
        ),
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    CargoLeanCapability::new("../model", "ShamirModel")
        .package("shamir_model")
        .module("ShamirModel")
        .export_signature(export("shamir_model_degree_bound", vec![obj()]))
        .export_signature(export("shamir_model_c0", vec![obj()]))
        .export_signature(export("shamir_model_eval", vec![obj(), u64_arg()]))
        .export_signature(export("shamir_model_add", vec![obj(), obj()]))
        .export_signature(export(
            "shamir_model_recover_c0",
            vec![u64_arg(), obj(), obj()],
        ))
        .build()?;
    Ok(())
}
