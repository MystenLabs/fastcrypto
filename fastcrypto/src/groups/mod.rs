// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod ristretto255;

/// Trait impl'd by additive groups.
pub trait AdditiveGroup {
    type Element: Eq;
    type Scalar;

    /// Return an instance of the identity element in this group.
    fn identity() -> Self::Element;

    /// Return true if the given element is the identity of this group.
    fn is_identity(element: &Self::Element) -> bool {
        element == &Self::identity()
    }

    /// Return the sum of two elements.
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// Return the additive inverse of an element.
    fn neg(a: &Self::Element) -> Self::Element;

    /// Return the difference of two elements.
    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element {
        Self::add(a, &Self::neg(b))
    }

    /// Return the result of a scalar multiplication of a group element with the given scalar.
    fn mul(scalar: &Self::Scalar, element: &Self::Element) -> Self::Element;
}
