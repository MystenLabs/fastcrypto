// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Builds the vendored mldsa-native library (git submodule at `deps/mldsa-native`; see
//! `PROVENANCE.md` for the pinned commit) for the ML-DSA-65 parameter set.
//!
//! Debugging hint: This build intentionally mirrors upstream's build. mldsa-native is designed to be compiled
//! as a single translation unit: `mldsa_native.c` `#include`s every implementation file, so we
//! compile only that file. If someone later adds `src/*.c` files to this build as well, every
//! function will be defined twice and the link will fail.
//!
//! `src/abi_check.c` intentionally produces no code. Instead, it contains compile-time checks
//! that fail if a future update of mldsa-native changes the ABI we expose through Rust FFI
//! (function signatures or size constants). That catches incompatible upstream changes during
//! the build instead of at runtime.
//!
//! We currently build only the portable C implementation. mldsa-native automatically selects
//! that implementation whenever no architecture-specific backend is enabled, so the library
//! still works correctly on every supported target. Faster verified AVX2/NEON implementations
//! can be enabled later without changing the Rust API.
//!
//! `MLD_CONFIG_NO_RANDOMIZED_API` removes mldsa-native's API variants that obtain randomness
//! themselves. This crate always passes randomness (seed / rnd) explicitly across the FFI
//! boundary, so the vendored C never needs to call a random-number generator.
//!
//! The code is compiled as C99 to match upstream's build. MSVC ignores the C99 flag, which is
//! harmless because upstream keeps the code C90-compatible.
//!
//! `wasm32-unknown-unknown` is not supported yet because it lacks the libc headers required by
//! mldsa-native (`string.h`, `assert.h`, etc.). The library itself is otherwise expected to be
//! portable to wasm, but that target has not yet been validated end to end.

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = manifest_dir.join("deps/mldsa-native/mldsa");
    let abi_check = manifest_dir.join("src/abi_check.c");

    if !src.join("mldsa_native.c").exists() {
        panic!(
            "mldsa-native submodule not found at {}. Run `git submodule update --init` in the repo root.",
            src.display()
        );
    }

    cc::Build::new()
        .file(src.join("mldsa_native.c"))
        .file(&abi_check)
        .include(&src)
        .define("MLD_CONFIG_PARAMETER_SET", "65")
        .define("MLD_CONFIG_NO_RANDOMIZED_API", None)
        .define("MLD_CONFIG_INTERNAL_API_QUALIFIER", "static")
        .std("c99")
        .compile("mldsa65");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", abi_check.display());
}
