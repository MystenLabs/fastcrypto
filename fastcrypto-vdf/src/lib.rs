// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Doubling;
use std::ops::{Add, Mul, Neg};

#[cfg(any(test, feature = "experimental"))]
pub mod class_group;

#[cfg(any(test, feature = "experimental"))]
pub mod vdf;

#[cfg(any(test, feature = "experimental"))]
pub mod hash_prime;

#[cfg(any(test, feature = "experimental"))]
pub mod math;

/// This trait is implemented by types which can be used as parameters for a parameterized group.
/// See [ParameterizedGroupElement].
pub trait Parameter: Eq + Sized + ToBytes {
    /// Compute a random instance of a given size from a seed.
    fn from_seed(seed: &[u8], size_in_bits: usize) -> FastCryptoResult<Self>;
}

/// Trait implemented by elements of an additive group where the group is parameterized, for example
/// by the modulus in case of the group being Z mod N or the discriminant in case of class groups.
pub trait ParameterizedGroupElement:
    Sized
    + Clone
    + for<'a> Add<&'a Self, Output = Self>
    + Add<Output = Self>
    + for<'a> Mul<&'a Self::ScalarType, Output = Self>
    + Neg
    + Eq
    + ToBytes
    + Doubling
{
    /// The type of the parameter which uniquely defines this group.
    type ParameterType: Parameter;

    /// Integer type used for multiplication.
    type ScalarType: From<u64>;

    /// Return an instance of the identity element in this group.
    fn zero(parameters: &Self::ParameterType) -> Self;

    /// Compute scale * self.
    fn mul(&self, scale: &Self::ScalarType) -> Self;

    /// Check whether this group element is in the same group as `other`.
    fn same_group(&self, other: &Self) -> bool;
}

/// Trait impl'd by elements of groups where the order is unknown.
pub trait UnknownOrderGroupElement {}

pub trait ToBytes {
    /// Serialize this object into a byte vector.
    fn to_bytes(&self) -> Vec<u8>;
}
