// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::GroupElement;

pub mod comb_method;
pub mod fixed_window;
mod integer_utils;

/// Trait for scalar multiplication for a fixed group element, e.g. by using precomputed values.
pub trait ScalarMultiplier<G: GroupElement> {
    /// Create a new scalar multiplier for the given base element.
    fn new(base_element: G) -> Self;

    /// Multiply the base element by the given scalar.
    fn mul(&self, scalar: &G::ScalarType) -> G;
}

/// Implementation of a `Multiplier` where scalar multiplication is done without any pre-computation by
/// simply calling the GroupElement implementation.
pub struct DefaultMultiplier<G: GroupElement>(G);

impl<G: GroupElement> ScalarMultiplier<G> for DefaultMultiplier<G> {
    fn new(base_element: G) -> Self {
        Self(base_element)
    }

    fn mul(&self, scalar: &G::ScalarType) -> G {
        self.0 * scalar
    }
}
