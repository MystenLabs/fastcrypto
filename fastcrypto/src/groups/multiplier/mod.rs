// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains implementations of optimised scalar multiplication algorithms where the
//! group element is fixed and certain multiples of this may be pre-computed.

use crate::groups::GroupElement;

pub mod fixed_window;
mod integer_utils;

/// Trait for scalar multiplication for a fixed group element, e.g. by using precomputed values.
pub trait ScalarMultiplier<G: GroupElement> {
    /// Create a new scalar multiplier with the given base element.
    fn new(base_element: G) -> Self;

    /// Multiply the base element by the given scalar.
    fn mul(&self, scalar: &G::ScalarType) -> G;

    /// Compute `self.base_scalar * base_element + other_scalar * other_element`.
    fn mul_double(
        &self,
        base_scalar: &G::ScalarType,
        other_element: &G,
        other_scalar: &G::ScalarType,
    ) -> G {
        // The default implementation if not optimised double multiplication is implemented.
        self.mul(base_scalar) + *other_element * other_scalar
    }
}
