// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for checking fastcrypto code against a Lean model of it.
//!
//! A model is a Lake library of `@[export]` functions, built as a shared library by the test
//! crate's `build.rs` (see [build]) and called from property tests through `lean-rs`. Values cross
//! the boundary as Lean `String`s, `Array`s, `UInt64`s and `Except`s; scalars and points as hex
//! strings of their byte encoding (see [hex]).

#[cfg(feature = "build")]
pub mod build;

#[cfg(feature = "runtime")]
mod runtime;

#[cfg(feature = "runtime")]
pub use runtime::*;
