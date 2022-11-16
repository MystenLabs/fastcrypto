// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of the [ristretto255 group](https://ristretto.group/) which is a group of
//! prime order 2^{252} + 27742317777372353535851937790883648493 built over Curve25519.

use curve25519_dalek_ng;
use curve25519_dalek_ng::traits::Identity;
use once_cell::sync::OnceCell;
use serde::{de, Deserialize, Serialize};

use crate::{
    error::FastCryptoError, groups::AdditiveGroup, hash::HashFunction, traits::ToFromBytes,
};

/// Implementation of the [ristretto255 group](https://ristretto.group/) which is a group of
/// prime order 2^{252} + 27742317777372353535851937790883648493 built over Curve25519.
pub struct Ristretto255 {}

impl Ristretto255 {
    /// Returns the base point of the Ristretto group.
    pub fn base_point() -> RistrettoPoint {
        RistrettoPoint {
            point: curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT,
            bytes: OnceCell::new(),
        }
    }

    /// The order of the base point.
    pub fn base_point_order() -> RistrettoScalar {
        RistrettoScalar(curve25519_dalek_ng::constants::BASEPOINT_ORDER)
    }
}

impl AdditiveGroup for Ristretto255 {
    type Element = RistrettoPoint;
    type Scalar = RistrettoScalar;

    fn identity() -> RistrettoPoint {
        RistrettoPoint {
            point: curve25519_dalek_ng::ristretto::RistrettoPoint::identity(),
            bytes: OnceCell::new(),
        }
    }

    fn add(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint {
            point: a.point + b.point,
            bytes: OnceCell::new(),
        }
    }

    fn neg(a: &RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint {
            point: -a.point,
            bytes: OnceCell::new(),
        }
    }

    fn mul(scalar: &RistrettoScalar, element: &RistrettoPoint) -> RistrettoPoint {
        RistrettoPoint {
            point: scalar.0 * element.point,
            bytes: OnceCell::new(),
        }
    }
}

/// Represents a scalar.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RistrettoScalar(curve25519_dalek_ng::scalar::Scalar);

impl RistrettoScalar {
    /// Attempt to create a new scalar from the given bytes in canonical representation.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Result<RistrettoScalar, FastCryptoError> {
        curve25519_dalek_ng::scalar::Scalar::from_canonical_bytes(bytes)
            .map_or(Err(FastCryptoError::InvalidInput), |r| {
                Ok(RistrettoScalar(r))
            })
    }

    /// Create a scalar from the low 255 bits of the given 256-bit integer.
    pub fn from_bits(value: [u8; 32]) -> RistrettoScalar {
        RistrettoScalar(curve25519_dalek_ng::scalar::Scalar::from_bits(value))
    }
}

impl From<u64> for RistrettoScalar {
    fn from(value: u64) -> RistrettoScalar {
        RistrettoScalar(curve25519_dalek_ng::scalar::Scalar::from(value))
    }
}

/// Represents a point in the Ristretto group for Curve25519.
#[derive(Debug)]
pub struct RistrettoPoint {
    point: curve25519_dalek_ng::ristretto::RistrettoPoint,
    bytes: OnceCell<[u8; 32]>,
}

impl RistrettoPoint {
    /// Construct a RistrettoPoint from the given data using an Ristretto-flavoured Elligator 2 map.
    /// If the input bytes are uniformly distributed, the resulting point will be uniformly
    /// distributed over the Ristretto group.
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        RistrettoPoint {
            point: curve25519_dalek_ng::ristretto::RistrettoPoint::from_uniform_bytes(bytes),
            bytes: OnceCell::new(),
        }
    }

    /// Construct a RistrettoPoint from the given data using a given hash function.
    pub fn map_to_point<H: HashFunction<64>>(bytes: &[u8]) -> Self {
        Self::from_uniform_bytes(&H::digest(bytes).digest)
    }
}

impl AsRef<[u8]> for RistrettoPoint {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init(|| self.point.compress().to_bytes())
    }
}

impl ToFromBytes for RistrettoPoint {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != 32 {
            return Err(FastCryptoError::InputLengthWrong(32));
        }
        let point = curve25519_dalek_ng::ristretto::CompressedRistretto::from_slice(bytes);
        let decompressed_point = point.decompress().ok_or(FastCryptoError::InvalidInput)?;

        Ok(RistrettoPoint {
            point: decompressed_point,
            bytes: OnceCell::new(),
        })
    }
}

impl Serialize for RistrettoPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.as_ref();
        serializer.serialize_bytes(bytes)
    }
}

impl<'de> Deserialize<'de> for RistrettoPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes = Vec::deserialize(deserializer)?;
        RistrettoPoint::from_bytes(&bytes[..]).map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl PartialEq for RistrettoPoint {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
    }
}

impl Eq for RistrettoPoint {}

impl PartialOrd for RistrettoPoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for RistrettoPoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl_group!(RistrettoScalar, RistrettoPoint, Ristretto255);
