// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, Neg};

use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Doubling;

/// This trait is implemented by types which can be used as parameters for a parameterized group.
/// See [ParameterizedGroupElement].
pub trait Parameter: Eq + Sized {
    /// Compute a random instance of a given size from a seed.
    fn from_seed(seed: &[u8], size_in_bits: usize) -> FastCryptoResult<Self>;
}

/// Trait implemented by elements of an additive group where the group is parameterized, for example
/// by the modulus in case of the group being Z mod N or the discriminant in case of class groups.
pub trait ParameterizedGroupElement:
    Sized + Clone + for<'a> Add<&'a Self, Output = Self> + Add<Output = Self> + Neg + Eq + Doubling
{
    /// The type of the parameter which uniquely defines this group.
    type ParameterType: Parameter;

    /// Integer type used for multiplication.
    type ScalarType: From<u64>;

    /// Return an instance of the identity element in this group.
    fn zero(parameter: &Self::ParameterType) -> Self;

    /// Returns true if this is an element of the group defined by `parameter`.
    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool;
}
