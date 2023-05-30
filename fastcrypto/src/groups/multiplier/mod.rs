// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains implementations of optimised scalar multiplication algorithms where the
//! group element is fixed and certain multiples of this may be pre-computed.

use crate::groups::GroupElement;

#[cfg(feature = "experimental")]
pub mod bgmw;
mod integer_utils;
pub mod windowed;

/// Trait for scalar multiplication for a fixed group element, e.g. by using precomputed values.
pub trait ScalarMultiplier<G: GroupElement> {
    /// Create a new scalar multiplier with the given base element.
    fn new(base_element: G) -> Self;

    /// Compute `self.base_element * scalar`.
    fn mul(&self, scalar: &G::ScalarType) -> G;

    /// Compute `self.base_element * base_scalar + other_element * other_scalar`.
    fn two_scalar_mul(
        &self,
        base_scalar: &G::ScalarType,
        other_element: &G,
        other_scalar: &G::ScalarType,
    ) -> G {
        // The default implementation. May be overwritten by implementations that allow optimised double multiplication.
        self.mul(base_scalar) + *other_element * other_scalar
    }
}
