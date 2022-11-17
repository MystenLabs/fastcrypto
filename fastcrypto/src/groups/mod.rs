// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Impl operator overload for the elements of a given group for all combinations of owned and borrowed
/// values.
/// * `scalar` -  Type of scalars. Should be equal to group::Scalar.
/// * `element` - Type of elements. Should be equal to group::Element.
/// * `group` - Type of group.
#[macro_export]
macro_rules! impl_group {
    ($scalar:ident, $element:ident, $group:ident) => {
        impl_op_ex!(+ |a: &$element, b: &$element| -> $element { $group::add(a, b) });
        impl_op_ex!(- |a: &$element, b: &$element| -> $element { $group::sub(a, b) });
        impl_op_ex!(* |a: &$scalar, b: &$element| -> $element { $group::mul(a, b) });
        impl_op_ex!(- |a: &$element| -> $element { $group::neg(a) });
    };
}

pub mod ristretto255;

/// Trait impl'd by additive groups.
pub trait AdditiveGroup {
    /// Type representing elements of this group.
    type Element: PartialEq + Eq + Serialize + DeserializeOwned;

    /// Type representing scalars for this group, e.g. integers modulo the group order.
    /// These are used for scalar multiplication of [Self::Element]s.
    type Scalar: From<u64> + Eq + PartialEq + Serialize + DeserializeOwned;

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
