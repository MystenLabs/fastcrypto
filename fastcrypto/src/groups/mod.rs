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
pub mod ristretto255;
pub mod secp256r1;

pub mod multiplier;
pub mod secp256k1;

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

    fn sum(terms: impl Iterator<Item = Self>) -> Self {
        terms.fold(Self::zero(), |acc, x| acc + x)
    }

    /// Compute the inner product of two iterators. The sum stops when the shortest iterator ends.
    fn inner_product<B: IntoIterator<Item = Self::ScalarType>>(
        a: impl IntoIterator<Item = Self>,
        b: B,
    ) -> Self {
        Self::sum(a.into_iter().zip(b).map(|(a, b)| a * b))
    }
}

// TODO: Move Serialize + DeserializeOwned to GroupElement.

/// Trait impl'd by scalars to be used with [GroupElement].
pub trait Scalar:
    GroupElement<ScalarType = Self> + Copy + From<u128> + Sized + Debug + Serialize + DeserializeOwned
{
    fn rand<R: AllowedRng>(rng: &mut R) -> Self;
    fn inverse(&self) -> FastCryptoResult<Self>;
    fn product(terms: impl Iterator<Item = Self>) -> Self {
        terms.fold(Self::generator(), |acc, x| acc * x)
    }
}

/// Trait for group elements that has a fast doubling operation.
pub trait Doubling: Clone {
    /// Compute 2 * Self = Self + Self.
    fn double(self) -> Self;

    /// Compute input * 2^repetitions by repeated doubling.
    fn repeated_doubling(self, repetitions: u64) -> Self {
        (0..repetitions).fold(self, |acc, _| acc.double())
    }
}

pub trait Pairing: GroupElement {
    type Other: GroupElement<ScalarType = Self::ScalarType>;
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
/// [RFC 9380, section 3](https://www.rfc-editor.org/rfc/rfc9380.html#section-3)).
pub trait HashToGroupElement {
    /// Hashes the given message and maps the result to a group element.
    fn hash_to_group_element(msg: &[u8]) -> Self;
}

/// Trait for groups that support multi-scalar multiplication.
pub trait MultiScalarMul: GroupElement {
    fn multi_scalar_mul(scalars: &[Self::ScalarType], points: &[Self]) -> FastCryptoResult<Self>;
}

/// Trait for groups that support multi-scalar multiplication with precomputed
/// tables over a fixed set of points, trading memory for speed when the same
/// points (e.g. a commitment key) are used in many multi-scalar multiplications.
pub trait PrecomputableMultiScalarMul: GroupElement {
    /// Precomputed tables for a fixed set of points.
    type Precomputation: MixedMultiScalarMul<Point = Self>;

    /// Build precomputation tables for `points`.
    fn precompute(points: &[Self]) -> FastCryptoResult<Self::Precomputation>;
}

/// Trait for the precomputed tables built by [PrecomputableMultiScalarMul::precompute].
pub trait MixedMultiScalarMul {
    /// The group whose points the tables were built for.
    type Point: GroupElement;

    /// The number of points these tables were built for.
    fn num_static_points(&self) -> usize;

    /// Compute the mixed multi-scalar multiplication
    ///
    /// `a_1*P_1 + ... + a_n*P_n + b_1*Q_1 + ... + b_m*Q_m`,
    ///
    /// where the `P_i` are the `n` static points these tables were built for,
    /// and the `Q_j` are the `m` dynamic points freshly supplied on every
    /// call. `static_scalars` holds the `a_i` and must have length `n`;
    /// `dynamic_scalars` holds the `b_j` and must have length `m`. The scalar 
    /// multiplication `a_i*P_i` is evaluated via the precomputed tables, so 
    /// when the `P_i` are reused across many calls this is faster than a regular 
    /// MSM over all `n + m` points. This only holds up to a size that depends on the
    /// implementation; above it a regular MSM is faster and the caller should
    /// use one instead.
    fn mixed_multi_scalar_mul(
        &self,
        static_scalars: &[<Self::Point as GroupElement>::ScalarType],
        dynamic_scalars: &[<Self::Point as GroupElement>::ScalarType],
        dynamic_points: &[Self::Point],
    ) -> FastCryptoResult<Self::Point>;
}

/// Faster deserialization that skips validation of the result: the subgroup membership check for
/// curve points and the canonical range check for scalars. Only safe for trusted input; otherwise
/// use [`crate::serde_helpers::ToFromByteArray::from_byte_array`].
pub trait FromTrustedByteArray<const LENGTH: usize>: Sized {
    fn from_trusted_byte_array(bytes: &[u8; LENGTH]) -> FastCryptoResult<Self>;
}
