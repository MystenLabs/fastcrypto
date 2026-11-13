// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Export signatures for `lean_toolchain::CargoLeanCapability`, for the usual shapes of a model's
//! exports: Lean objects (`String`, `Array`, `Except`, ...) and `UInt64`s in, a Lean object out.

pub use lean_toolchain;
use lean_toolchain::{
    LeanExportAbiRepr as Repr, LeanExportArgAbi as Arg, LeanExportOwnership as Own,
    LeanExportResultConvention, LeanExportReturnAbi, LeanExportSignature, LeanLibraryDependency,
};
use std::path::Path;
use std::process::Command;

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

/// Runs `lake build` in the package at `dir`, which also builds its dependencies. Needed when a
/// model uses other Lake packages: `CargoLeanCapability` only notices changes to files in its own
/// package.
pub fn lake_build(dir: &str) {
    let status = Command::new("lake")
        .arg("build")
        .current_dir(dir)
        .status()
        .expect("lake");
    assert!(status.success(), "lake build failed in {dir}");
}

/// The shared library of the Lake package `package` in `dir`, with root module `module`, as a
/// dependency of a model. It must have been built (see [lake_build]).
pub fn library_dependency(dir: &str, package: &str, module: &str) -> LeanLibraryDependency {
    println!("cargo:rerun-if-changed={dir}");
    let library = format!(
        "lib{}_{module}.{}",
        package.replace('_', "__"),
        std::env::consts::DLL_EXTENSION
    );
    let path = Path::new(dir)
        .join(".lake/build/lib")
        .join(library)
        .canonicalize()
        .expect("the Lean library was built");
    LeanLibraryDependency::path(path)
        .export_symbols_for_dependents()
        .initializer(package, module)
}
