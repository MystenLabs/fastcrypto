// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::traits::AllowedRng;
use core::ops::{Add, Div, Mul, Neg, Sub};
use std::fmt::Debug;
use std::ops::{AddAssign, SubAssign};

pub mod bls12381;
#[cfg(feature = "experimental")]
pub mod class_group;
pub mod ristretto255;
pub mod secp256r1;

pub mod multiplier;

/// Trait impl'd by elements of an additive cyclic group.
pub trait GroupElement:
    Copy
    + Clone
    + Debug
    + Eq
    + Add<Output = Self>
    + AddAssign
    + for<'a> Add<&'a Self, Output = Self>
    + Sub<Output = Self>
    + SubAssign
    + for<'a> Sub<&'a Self, Output = Self>
    + Neg<Output = Self>
    + Mul<Self::ScalarType, Output = Self>
    + Div<Self::ScalarType, Output = Result<Self, FastCryptoError>>
    + for<'a> Mul<&'a Self::ScalarType, Output = Self>
    + Sized
{
    /// Type of scalars used in the [Self::mul] multiplication method.
    type ScalarType: Scalar;

    /// Return an instance of the identity element in this group.
    fn zero() -> Self;

    /// Return an instance of the generator for this group.
    fn generator() -> Self;

    /// Compute 2 * Self. May be overwritten by implementations that have a fast doubling operation.
    fn double(&self) -> Self {
        *self + self
    }
}

/// Trait impl'd by scalars to be used with [GroupElement].
pub trait Scalar: GroupElement<ScalarType = Self> + Copy + From<u64> + Sized + Debug {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self;
    fn inverse(&self) -> FastCryptoResult<Self>;
}

pub trait Pairing: GroupElement {
    type Other: GroupElement;
    type Output;

    fn pairing(&self, other: &Self::Other) -> <Self as Pairing>::Output;
}

/// Trait for groups that have a standardized "hash_to_point"/"hash_to_curve" function (see
/// [https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve#section-3].
pub trait HashToGroupElement {
    /// Hashes the given message and maps the result to a group element.
    fn hash_to_group_element(msg: &[u8]) -> Self;
}

/// Trait for groups that support multi-scalar multiplication.
pub trait MultiScalarMul: GroupElement {
    fn multi_scalar_mul(scalars: &[Self::ScalarType], points: &[Self]) -> FastCryptoResult<Self>;
}

/// Trait implemented by elements of an additive group where the group is parameterized, for example
/// by the modulus in case of the group being Z mod N or the discriminant in case of class groups.
pub trait ParameterizedGroupElement:
    Sized + Clone + for<'a> Add<&'a Self, Output = Self> + Neg + Eq
{
    /// The type of the parameter which uniquely defines this group.
    type ParameterType: Eq;

    /// Integer type used for multiplication.
    type ScalarType: From<u64>;

    /// Return an instance of the identity element in this group.
    fn zero(parameters: &Self::ParameterType) -> Self;

    /// Compute 2 * Self. May be overwritten by implementations that have a fast doubling operation.
    fn double(&self) -> Self {
        self.clone().add(self)
    }

    /// Compute scale * self.
    fn mul(&self, scale: &Self::ScalarType) -> Self;

    /// Serialize this group element.
    fn as_bytes(&self) -> Vec<u8>;

    /// Get the defining parameter for this group element.
    fn get_group_parameter(&self) -> Self::ParameterType;
}

/// Trait impl'd by elements of groups where the order is unknown.
pub trait UnknownOrderGroupElement {}
