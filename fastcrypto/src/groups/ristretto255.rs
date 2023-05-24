// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of the [ristretto255 group](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-03.html) which is a group of
//! prime order 2^{252} + 27742317777372353535851937790883648493 built over Curve25519.

use crate::error::FastCryptoResult;
use crate::groups::{GroupElement, HashToGroupElement, MultiScalarMul, Scalar};
use crate::hash::Sha512;
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use crate::{
    error::FastCryptoError, hash::HashFunction, serialize_deserialize_with_to_from_byte_array,
};
use curve25519_dalek_ng;
use curve25519_dalek_ng::constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek_ng::ristretto::CompressedRistretto as ExternalCompressedRistrettoPoint;
use curve25519_dalek_ng::ristretto::RistrettoPoint as ExternalRistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as ExternalRistrettoScalar;
use curve25519_dalek_ng::traits::{Identity, VartimeMultiscalarMul};
use derive_more::{Add, Div, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;
use serde::{de, Deserialize};
use std::ops::{Div, Mul};

const RISTRETTO_POINT_BYTE_LENGTH: usize = 32;
const RISTRETTO_SCALAR_BYTE_LENGTH: usize = 32;

/// Represents a point in the Ristretto group for Curve25519.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct RistrettoPoint(ExternalRistrettoPoint);

impl RistrettoPoint {
    /// Construct a RistrettoPoint from the given data using an Ristretto-flavoured Elligator 2 map.
    /// If the input bytes are uniformly distributed, the resulting point will be uniformly
    /// distributed over the Ristretto group.
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        RistrettoPoint::from(ExternalRistrettoPoint::from_uniform_bytes(bytes))
    }

    /// Construct a RistrettoPoint from the given data using a given hash function.
    pub fn map_to_point<H: HashFunction<64>>(bytes: &[u8]) -> Self {
        Self::from_uniform_bytes(&H::digest(bytes).digest)
    }

    /// Return this point in compressed form.
    pub fn compress(&self) -> [u8; 32] {
        self.0.compress().0
    }

    /// Return this point in compressed form.
    pub fn decompress(bytes: &[u8; 32]) -> Result<Self, FastCryptoError> {
        RistrettoPoint::try_from(bytes.as_slice())
    }
}

impl MultiScalarMul for RistrettoPoint {
    fn multi_scalar_mul(scalars: &[Self::ScalarType], points: &[Self]) -> FastCryptoResult<Self> {
        if scalars.len() != points.len() {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(RistrettoPoint(
            ExternalRistrettoPoint::vartime_multiscalar_mul(
                scalars.iter().map(|s| s.0),
                points.iter().map(|g| g.0),
            ),
        ))
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
        RistrettoPoint::from(self.0 * rhs.0)
    }
}

impl GroupElement for RistrettoPoint {
    type ScalarType = RistrettoScalar;

    fn zero() -> RistrettoPoint {
        RistrettoPoint::from(ExternalRistrettoPoint::identity())
    }

    fn generator() -> Self {
        RistrettoPoint::from(RISTRETTO_BASEPOINT_POINT)
    }
}

impl TryFrom<&[u8]> for RistrettoPoint {
    type Error = FastCryptoError;

    /// Decode a ristretto point in compressed binary form.
    fn try_from(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let point = ExternalCompressedRistrettoPoint::from_slice(bytes);
        let decompressed_point = point.decompress().ok_or(FastCryptoError::InvalidInput)?;
        Ok(RistrettoPoint::from(decompressed_point))
    }
}

impl HashToGroupElement for RistrettoPoint {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        RistrettoPoint::map_to_point::<Sha512>(msg)
    }
}

impl ToFromByteArray<RISTRETTO_POINT_BYTE_LENGTH> for RistrettoPoint {
    fn from_byte_array(bytes: &[u8; RISTRETTO_POINT_BYTE_LENGTH]) -> Result<Self, FastCryptoError> {
        Self::try_from(bytes.as_slice())
    }

    fn to_byte_array(&self) -> [u8; RISTRETTO_POINT_BYTE_LENGTH] {
        self.compress()
    }
}

serialize_deserialize_with_to_from_byte_array!(RistrettoPoint);

/// Represents a scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, Div, GroupOpsExtend)]
pub struct RistrettoScalar(ExternalRistrettoScalar);

impl RistrettoScalar {
    /// The order of the base point.
    pub fn group_order() -> RistrettoScalar {
        RistrettoScalar(BASEPOINT_ORDER)
    }

    /// Construct a [RistrettoScalar] by reducing a 64-byte little-endian integer modulo the group order.
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        RistrettoScalar(ExternalRistrettoScalar::from_bytes_mod_order_wide(bytes))
    }

    /// Construct a [RistrettoScalar] by reducing a 32-byte little-endian integer modulo the group order.
    pub fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        RistrettoScalar(ExternalRistrettoScalar::from_bytes_mod_order(*bytes))
    }
}

impl From<u64> for RistrettoScalar {
    fn from(value: u64) -> RistrettoScalar {
        RistrettoScalar(ExternalRistrettoScalar::from(value))
    }
}

impl Mul<RistrettoScalar> for RistrettoScalar {
    type Output = RistrettoScalar;

    fn mul(self, rhs: RistrettoScalar) -> RistrettoScalar {
        RistrettoScalar::from(self.0 * rhs.0)
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
        RistrettoScalar::from(ExternalRistrettoScalar::zero())
    }
    fn generator() -> Self {
        RistrettoScalar::from(ExternalRistrettoScalar::one())
    }
}

impl Scalar for RistrettoScalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        Self(ExternalRistrettoScalar::random(rng))
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        if self.0 == ExternalRistrettoScalar::zero() {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(RistrettoScalar::from(self.0.invert()))
    }
}

impl HashToGroupElement for RistrettoScalar {
    fn hash_to_group_element(bytes: &[u8]) -> Self {
        Self::from_bytes_mod_order_wide(&Sha512::digest(bytes).digest)
    }
}

impl ToFromByteArray<RISTRETTO_SCALAR_BYTE_LENGTH> for RistrettoScalar {
    fn from_byte_array(
        bytes: &[u8; RISTRETTO_SCALAR_BYTE_LENGTH],
    ) -> Result<Self, FastCryptoError> {
        Ok(RistrettoScalar(
            ExternalRistrettoScalar::from_canonical_bytes(*bytes)
                .ok_or(FastCryptoError::InvalidInput)?,
        ))
    }

    fn to_byte_array(&self) -> [u8; RISTRETTO_SCALAR_BYTE_LENGTH] {
        self.0.to_bytes()
    }
}

serialize_deserialize_with_to_from_byte_array!(RistrettoScalar);
