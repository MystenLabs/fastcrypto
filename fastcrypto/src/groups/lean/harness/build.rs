// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the Lean model in `../model` as a shared library and records its exports.

use fastcrypto_lean_testing::build::lean_toolchain::CargoLeanCapability;
use fastcrypto_lean_testing::build::{export, obj, u64};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut model = CargoLeanCapability::new("../model", "RistrettoModel")
        .package("ristretto_model")
        .module("RistrettoModel");
    for name in ["point_zero", "point_generator"] {
        model = model.export_signature(export(&format!("ristretto_model_{name}"), vec![u64()]));
    }
    for name in [
        "point_decode",
        "point_neg",
        "point_double",
        "scalar_decode",
        "scalar_neg",
        "scalar_inverse",
        "scalar_mod_order",
        "scalar_mod_order_wide",
    ] {
        model = model.export_signature(export(&format!("ristretto_model_{name}"), vec![obj()]));
    }
    for name in [
        "point_add",
        "point_sub",
        "point_mul",
        "point_div",
        "point_msm",
        "point_from_uniform",
        "scalar_add",
        "scalar_sub",
        "scalar_mul",
    ] {
        model = model.export_signature(export(
            &format!("ristretto_model_{name}"),
            vec![obj(), obj()],
        ));
    }
    model.build()?;
    Ok(())
}
