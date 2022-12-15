// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of the [ristretto255 group](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-03.html) which is a group of
//! prime order 2^{252} + 27742317777372353535851937790883648493 built over Curve25519.

use crate::groups::{GroupElement, Scalar};
use crate::traits::AllowedRng;
use crate::{error::FastCryptoError, hash::HashFunction};
use curve25519_dalek_ng;
use curve25519_dalek_ng::constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek_ng::ristretto::CompressedRistretto as ExternalCompressedRistrettoPoint;
use curve25519_dalek_ng::ristretto::RistrettoPoint as ExternalRistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as ExternalRistrettoScalar;
use curve25519_dalek_ng::traits::Identity;
use derive_more::{Add, Div, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;
use serde::{de, Deserialize, Serialize};
use std::ops::{Div, Mul};

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

impl std::ops::Mul<RistrettoScalar> for RistrettoPoint {
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

impl Serialize for RistrettoPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.compress();
        serializer.serialize_bytes(bytes.as_bytes())
    }
}

impl<'de> Deserialize<'de> for RistrettoPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes = Vec::deserialize(deserializer)?;
        RistrettoPoint::try_from(&bytes[..]).map_err(|e| de::Error::custom(e.to_string()))
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

/// Represents a scalar.
#[derive(
    Clone,
    Copy,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    From,
    Add,
    Sub,
    Neg,
    Div,
    GroupOpsExtend,
)]
pub struct RistrettoScalar(ExternalRistrettoScalar);

impl RistrettoScalar {
    /// Attempt to create a new scalar from the given bytes in canonical representation.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Result<RistrettoScalar, FastCryptoError> {
        ExternalRistrettoScalar::from_canonical_bytes(bytes)
            .map_or(Err(FastCryptoError::InvalidInput), |r| {
                Ok(RistrettoScalar(r))
            })
    }

    /// Create a scalar from the low 255 bits of the given 256-bit integer.
    pub fn from_bits(value: [u8; 32]) -> RistrettoScalar {
        RistrettoScalar(ExternalRistrettoScalar::from_bits(value))
    }

    /// The order of the base point.
    pub fn group_order() -> RistrettoScalar {
        RistrettoScalar(BASEPOINT_ORDER)
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

impl Div<RistrettoScalar> for RistrettoScalar {
    type Output = Result<RistrettoScalar, FastCryptoError>;

    fn div(self, rhs: RistrettoScalar) -> Result<RistrettoScalar, FastCryptoError> {
        if rhs.0 == ExternalRistrettoScalar::zero() {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(RistrettoScalar::from(self.0 * rhs.0.invert()))
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
        RistrettoScalar::from(ExternalRistrettoScalar::random(rng))
    }
}
