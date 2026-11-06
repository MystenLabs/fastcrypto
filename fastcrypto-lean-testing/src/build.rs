// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Export signatures for `lean_toolchain::CargoLeanCapability`, for the usual shapes of a model's
//! exports: Lean objects (`String`, `Array`, `Except`, ...) and `UInt64`s in, a Lean object out.

pub use lean_toolchain;
use lean_toolchain::{
    LeanExportAbiRepr as Repr, LeanExportArgAbi as Arg, LeanExportOwnership as Own,
    LeanExportResultConvention, LeanExportReturnAbi, LeanExportSignature,
};

/// An owned Lean object argument.
pub fn obj() -> Arg {
    Arg::new(Repr::LeanObject, Own::Owned)
}

/// A `UInt64` argument.
pub fn u64() -> Arg {
    Arg::new(Repr::U64, Own::None)
}

/// A pure export `name` taking `args` and returning an owned Lean object.
pub fn export(name: &str, args: Vec<Arg>) -> LeanExportSignature {
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
