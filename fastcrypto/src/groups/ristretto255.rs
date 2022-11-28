// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of the [ristretto255 group](https://www.ietf.org/archive/id/draft-irtf-cfrg-ristretto255-decaf448-03.html) which is a group of
//! prime order 2^{252} + 27742317777372353535851937790883648493 built over Curve25519.

use crate::groups::AdditiveGroupElement;
use crate::{error::FastCryptoError, hash::HashFunction};
use curve25519_dalek_ng;
use curve25519_dalek_ng::constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek_ng::ristretto::CompressedRistretto as ExternalCompressedRistrettoPoint;
use curve25519_dalek_ng::ristretto::RistrettoPoint as ExternalRistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as ExternalRistrettoScalar;
use curve25519_dalek_ng::traits::Identity;
use derive_more::{Add, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;
use serde::{de, Deserialize, Serialize};
use std::ops::{Add, Mul, Sub};

/// Represents a point in the Ristretto group for Curve25519.
#[derive(Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
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

    /// Returns the base point of the Ristretto group.
    pub fn base_point() -> RistrettoPoint {
        RistrettoPoint::from(RISTRETTO_BASEPOINT_POINT)
    }

    /// The order of the base point.
    pub fn base_point_order() -> RistrettoScalar {
        RistrettoScalar(BASEPOINT_ORDER)
    }

    /// Return this point in compressed form.
    pub fn compress(&self) -> [u8; 32] {
        self.0.compress().0
    }
}

impl Mul<RistrettoScalar> for RistrettoPoint {
    type Output = RistrettoPoint;

    fn mul(self, rhs: RistrettoScalar) -> RistrettoPoint {
        RistrettoPoint::from(self.0 * rhs.0)
    }
}

impl AdditiveGroupElement for RistrettoPoint {
    type Scalar = RistrettoScalar;

    fn identity() -> RistrettoPoint {
        RistrettoPoint::from(ExternalRistrettoPoint::identity())
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
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
}

impl From<u64> for RistrettoScalar {
    fn from(value: u64) -> RistrettoScalar {
        RistrettoScalar(ExternalRistrettoScalar::from(value))
    }
}
