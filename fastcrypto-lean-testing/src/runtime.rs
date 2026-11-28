// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::serde_helpers::ToFromByteArray;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;

pub use lean_rs;
use lean_rs::{LeanBuiltCapability, LeanCapability, LeanRuntime};

/// Opens the Lean model whose build manifest is at `manifest`, as recorded by `build.rs` in the
/// environment variable `env_var`. Panics if the runtime or the model fails to load.
pub fn open(manifest: &'static str, env_var: &str) -> LeanCapability<'static> {
    let runtime = LeanRuntime::init().expect("Lean runtime");
    LeanCapability::from_build_manifest(
        runtime,
        LeanBuiltCapability::manifest_path(manifest).manifest_env_var(env_var),
    )
    .expect("Lean model")
}

/// Checks that `rust` and `lean` return the same value on inputs drawn from `inputs`.
pub fn same<S, T>(inputs: S, rust: impl Fn(&S::Value) -> T, lean: impl Fn(&S::Value) -> T)
where
    S: Strategy,
    S::Value: Clone,
    T: PartialEq + std::fmt::Debug,
{
    TestRunner::default()
        .run(&inputs, |input| {
            prop_assert_eq!(rust(&input), lean(&input));
            Ok(())
        })
        .unwrap();
}

/// The hex encoding of `x.to_byte_array()`.
pub fn hex<const N: usize, T: ToFromByteArray<N>>(x: &T) -> String {
    hex::encode(x.to_byte_array())
}

/// [hex] of each element.
pub fn hex_all<const N: usize, T: ToFromByteArray<N>>(xs: &[T]) -> Vec<String> {
    xs.iter().map(hex).collect()
}
