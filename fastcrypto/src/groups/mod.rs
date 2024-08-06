// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::traits::AllowedRng;
use core::ops::{Add, Div, Mul, Neg, Sub};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::ops::{AddAssign, SubAssign};

pub mod bls12381;
pub mod bn254;
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
}

// TODO: Move Serialize + DeserializeOwned to GroupElement.

/// Trait impl'd by scalars to be used with [GroupElement].
pub trait Scalar:
    GroupElement<ScalarType = Self> + Copy + From<u128> + Sized + Debug + Serialize + DeserializeOwned
{
    fn rand<R: AllowedRng>(rng: &mut R) -> Self;
    fn inverse(&self) -> FastCryptoResult<Self>;
}

/// Trait for group elements that has a fast doubling operation.
pub trait Doubling {
    /// Compute 2 * Self = Self + Self.
    fn double(&self) -> Self;
}

pub trait Pairing: GroupElement {
    type Other: GroupElement;
    type Output;

    fn pairing(&self, other: &Self::Other) -> <Self as Pairing>::Output;

    /// Multi-pairing operation that computes the sum of pairings of two slices of elements.
    fn multi_pairing(
        points_g1: &[Self],
        points_g2: &[Self::Other],
    ) -> FastCryptoResult<<Self as Pairing>::Output>
    where
        <Self as Pairing>::Output: GroupElement,
    {
        if points_g1.len() != points_g2.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        if points_g1.is_empty() {
            return Ok(<Self as Pairing>::Output::zero());
        }
        Ok(points_g1
            .iter()
            .skip(1)
            .zip(points_g2.iter().skip(1))
            .map(|(g1, g2)| g1.pairing(g2))
            .fold(
                points_g1[0].pairing(&points_g2[0]),
                <Self as Pairing>::Output::add,
            ))
    }
}

/// Trait for groups that have a reduction from a random buffer to a group element that is secure
/// when used for Fiat-Shamir. Note that the resulting group element is not guaranteed to be
/// uniformly distributed, but only to have enough entropy to be used for Fiat-Shamir heuristic.
pub trait FiatShamirChallenge {
    fn fiat_shamir_reduction_to_group_element(uniform_buffer: &[u8]) -> Self;
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

/// Faster deserialization in case the input is trusted (otherwise it can be insecure).
pub trait FromTrustedByteArray<const LENGTH: usize>: Sized {
    fn from_trusted_byte_array(bytes: &[u8; LENGTH]) -> FastCryptoResult<Self>;
}
