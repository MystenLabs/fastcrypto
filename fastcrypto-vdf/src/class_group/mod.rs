// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.
//!
//! There are two implementations available. The first is a pure Rust implementation using the num-bigint
//! crate. The second uses the Rug crate which is a wrapper around the GMP C++ library which is faster
//! but requires the GMP library to be installed. The latter is enabled by building with the `gmp` feature
//! set.
//!
//! Serialization is compatible with the chiavdf library (https://github.com/Chia-Network/chiavdf).

/// Implementation using the num-bigint crate which is pure Rust but slower than using the GMP module.
#[cfg(not(feature = "gmp"))]
mod num_bigint;

/// A discriminant for an imaginary class group. The discriminant is a negative integer which is
/// equal to 1 mod 4.
#[cfg(not(feature = "gmp"))]
pub use crate::class_group::num_bigint::Discriminant;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
///
/// The `partial_gcd_limit` variable must be equal to `|discriminant|^{1/4}` and is used to speed up
/// the composition algorithm.
#[cfg(not(feature = "gmp"))]
pub use crate::class_group::num_bigint::QuadraticForm;

/// Implementation using the Rug crate which is a wrapper around the GMP C++ library which is faster
/// than the pure Rust implementation but requires the GMP library to be installed.
#[cfg(feature = "gmp")]
mod gmp;

/// A discriminant for an imaginary class group. The discriminant is a negative integer which is
/// equal to 1 mod 4.
#[cfg(feature = "gmp")]
pub use crate::class_group::gmp::Discriminant;

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
///
/// The `partial_gcd_limit` variable must be equal to `|discriminant|^{1/4}` and is used to speed up
/// the composition algorithm.
#[cfg(feature = "gmp")]
pub use crate::class_group::gmp::QuadraticForm;
