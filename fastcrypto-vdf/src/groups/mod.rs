// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Add;

use fastcrypto::groups::Doubling;

pub mod class_group;
pub mod rsa_group;

/// Trait implemented by elements of an additive group where the group is parameterized: Concretely,
///  1) RSA groups parameterized by the modulus and
///  2) class groups parameterized by a discriminant.
pub trait ParameterizedGroupElement:
    Sized + Clone + for<'a> Add<&'a Self, Output = Self> + Eq + Doubling
{
    /// The type of the parameter which uniquely defines this group.
    type ParameterType;

    /// Return an instance of the identity element in this group.
    fn zero(parameter: &Self::ParameterType) -> Self;

    /// Returns true if this is an element of the group defined by `parameter`.
    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool;
}
