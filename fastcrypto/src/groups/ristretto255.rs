// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of the [ristretto255 group](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-03.html) which is a group of
//! prime order 2^{252} + 27742317777372353535851937790883648493 built over Curve25519.

use crate::error::FastCryptoError::InvalidInput;
use crate::error::FastCryptoResult;
use crate::groups::{
    Doubling, FiatShamirChallenge, FromTrustedByteArray, GroupElement, HashToGroupElement,
    MultiScalarMul, Scalar,
};
use crate::hash::Sha512;
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use crate::{
    error::FastCryptoError, hash::HashFunction, serialize_deserialize_with_to_from_byte_array,
};
use curve25519_dalek;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint as ExternalPoint;
use curve25519_dalek::scalar::Scalar as ExternalScalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use derive_more::{Add, Div, Neg, Sub};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::Field;
use fastcrypto_derive::GroupOpsExtend;
use std::ops::{Add, Div, Mul};
use zeroize::Zeroize;

pub const RISTRETTO_POINT_BYTE_LENGTH: usize = 32;
pub const RISTRETTO_SCALAR_BYTE_LENGTH: usize = 32;

/// Represents a point in the Ristretto group for Curve25519.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Add, Sub, Neg, GroupOpsExtend)]
pub struct RistrettoPoint(pub(crate) ExternalPoint);

impl RistrettoPoint {
    /// Construct a RistrettoPoint from the given data using a Ristretto-flavoured Elligator 2 map.
    /// If the input bytes are uniformly distributed, the resulting point will be uniformly
    /// distributed over the Ristretto group.
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        RistrettoPoint(ExternalPoint::from_uniform_bytes(bytes))
    }
}

impl Doubling for RistrettoPoint {
    fn double(self) -> Self {
        Self(self.0.add(self.0))
    }
}

impl MultiScalarMul for RistrettoPoint {
    fn multi_scalar_mul(scalars: &[Self::ScalarType], points: &[Self]) -> FastCryptoResult<Self> {
        if scalars.len() != points.len() {
            return Err(InvalidInput);
        }

        Ok(RistrettoPoint(ExternalPoint::vartime_multiscalar_mul(
            scalars.iter().map(|s| s.0),
            points.iter().map(|g| g.0),
        )))
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<RistrettoScalar> for RistrettoPoint {
    type Output = Result<Self, FastCryptoError>;

    fn div(self, rhs: RistrettoScalar) -> Self::Output {
        let inv = rhs.inverse()?;
        Ok(self * inv)
    }
}

impl Mul<RistrettoScalar> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn mul(self, rhs: RistrettoScalar) -> RistrettoPoint {
        RistrettoPoint(self.0 * rhs.0)
    }
}

impl GroupElement for RistrettoPoint {
    type ScalarType = RistrettoScalar;

    fn zero() -> RistrettoPoint {
        RistrettoPoint(ExternalPoint::identity())
    }

    fn generator() -> Self {
        RistrettoPoint(RISTRETTO_BASEPOINT_POINT)
    }
}

impl HashToGroupElement for RistrettoPoint {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        Self::from_uniform_bytes(&Sha512::digest(msg).digest)
    }
}

impl ToFromByteArray<RISTRETTO_POINT_BYTE_LENGTH> for RistrettoPoint {
    fn from_byte_array(bytes: &[u8; RISTRETTO_POINT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        Option::from(ExternalPoint::from_bytes(bytes).map(RistrettoPoint)).ok_or(InvalidInput)
    }

    fn to_byte_array(&self) -> [u8; RISTRETTO_POINT_BYTE_LENGTH] {
        self.0.compress().0
    }
}

impl FromTrustedByteArray<RISTRETTO_POINT_BYTE_LENGTH> for RistrettoPoint {
    fn from_trusted_byte_array(
        bytes: &[u8; RISTRETTO_POINT_BYTE_LENGTH],
    ) -> FastCryptoResult<Self> {
        // Note that the external crate does not distinguish between from_bytes and from_bytes_unchecked:
        // https://github.com/dalek-cryptography/curve25519-dalek/blob/11f5375375d3d52c153049f18bd8b1b7669c2565/curve25519-dalek/src/ristretto.rs#L1221-L1224
        Option::from(ExternalPoint::from_bytes_unchecked(bytes).map(RistrettoPoint))
            .ok_or(InvalidInput)
    }
}

serialize_deserialize_with_to_from_byte_array!(RistrettoPoint);

/// Represents a scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Add, Sub, Neg, Div, GroupOpsExtend, Zeroize)]
pub struct RistrettoScalar(pub(crate) ExternalScalar);

impl RistrettoScalar {
    /// Construct a [RistrettoScalar] by reducing a 64-byte little-endian integer modulo the group order.
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        RistrettoScalar(ExternalScalar::from_bytes_mod_order_wide(bytes))
    }

    /// Construct a [RistrettoScalar] by reducing a 32-byte little-endian integer modulo the group order.
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        RistrettoScalar(ExternalScalar::from_bytes_mod_order(*bytes))
    }
}

impl From<u128> for RistrettoScalar {
    fn from(value: u128) -> RistrettoScalar {
        RistrettoScalar(ExternalScalar::from(value))
    }
}

impl From<u64> for RistrettoScalar {
    fn from(value: u64) -> RistrettoScalar {
        RistrettoScalar(ExternalScalar::from(value))
    }
}

impl Mul<RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    fn mul(self, rhs: RistrettoScalar) -> RistrettoScalar {
        RistrettoScalar(self.0 * rhs.0)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<RistrettoScalar> for RistrettoScalar {
    type Output = Result<RistrettoScalar, FastCryptoError>;

    fn div(self, rhs: RistrettoScalar) -> Result<RistrettoScalar, FastCryptoError> {
        let inv = rhs.inverse()?;
        Ok(self * inv)
    }
}

impl GroupElement for RistrettoScalar {
    type ScalarType = Self;

    fn zero() -> Self {
        RistrettoScalar(ExternalScalar::ZERO)
    }
    fn generator() -> Self {
        RistrettoScalar(ExternalScalar::ONE)
    }
}

impl Scalar for RistrettoScalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        Self(ExternalScalar::random(rng))
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        if self.0.is_zero().into() {
            return Err(InvalidInput);
        }
        Ok(RistrettoScalar(self.0.invert()))
    }
}

impl HashToGroupElement for RistrettoScalar {
    fn hash_to_group_element(bytes: &[u8]) -> Self {
        Self::from_bytes_mod_order_wide(&Sha512::digest(bytes).digest)
    }
}

impl FiatShamirChallenge for RistrettoScalar {
    fn fiat_shamir_reduction_to_group_element(msg: &[u8]) -> Self {
        Self::hash_to_group_element(msg)
    }
}

impl ToFromByteArray<RISTRETTO_SCALAR_BYTE_LENGTH> for RistrettoScalar {
    fn from_byte_array(
        bytes: &[u8; RISTRETTO_SCALAR_BYTE_LENGTH],
    ) -> Result<Self, FastCryptoError> {
        Ok(RistrettoScalar(
            ExternalScalar::from_canonical_bytes(*bytes)
                .into_option()
                .ok_or(InvalidInput)?,
        ))
    }

    fn to_byte_array(&self) -> [u8; RISTRETTO_SCALAR_BYTE_LENGTH] {
        self.0.to_bytes()
    }
}

impl FromTrustedByteArray<RISTRETTO_SCALAR_BYTE_LENGTH> for RistrettoScalar {
    fn from_trusted_byte_array(
        bytes: &[u8; RISTRETTO_SCALAR_BYTE_LENGTH],
    ) -> FastCryptoResult<Self> {
        Ok(Self::from_bytes_mod_order(bytes))
    }
}

serialize_deserialize_with_to_from_byte_array!(RistrettoScalar);
