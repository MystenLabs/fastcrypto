// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the Secp256r1 (aka P-256) curve. This is a 256-bit Weirstrass curve of prime order.
//! See "SEC 2: Recommended Elliptic Curve Domain Parameters" for details."

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::{Doubling, GroupElement, Scalar as ScalarTrait};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use ark_ec::Group;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_secp256r1::{Fr, Projective};
use ark_serialize::CanonicalSerialize;
use derive_more::{Add, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;
use std::ops::{Div, Mul};

/// A point on the Secp256r1 curve in projective coordinates.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct ProjectivePoint(pub(crate) Projective);

/// A field element in the prime field of the same order as the curve.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct Scalar(pub(crate) Fr);

impl Doubling for ProjectivePoint {
    fn double(&self) -> Self {
        ProjectivePoint::from(self.0.double())
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0 * rhs.0)
    }
}

impl Div<Scalar> for ProjectivePoint {
    type Output = Result<ProjectivePoint, FastCryptoError>;

    fn div(self, rhs: Scalar) -> Result<ProjectivePoint, FastCryptoError> {
        Ok(self * rhs.inverse()?)
    }
}

impl GroupElement for Scalar {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Scalar(Fr::zero())
    }

    fn generator() -> Self {
        Scalar(Fr::one())
    }
}

impl Div<Scalar> for Scalar {
    type Output = Result<Scalar, FastCryptoError>;

    fn div(self, rhs: Scalar) -> Result<Scalar, FastCryptoError> {
        Ok(self * rhs.inverse()?)
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Scalar(Fr::from(value))
    }
}

impl ScalarTrait for Scalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar(Fr::from_be_bytes_mod_order(&bytes))
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        Ok(Scalar(
            self.0.inverse().ok_or(FastCryptoError::InvalidInput)?,
        ))
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, rhs: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self.0 * rhs.0)
    }
}

impl GroupElement for ProjectivePoint {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self(Projective::zero())
    }

    fn generator() -> Self {
        Self(Projective::generator())
    }
}

impl ToFromByteArray<32> for Scalar {
    fn from_byte_array(bytes: &[u8; 32]) -> Result<Self, FastCryptoError> {
        Ok(Scalar(Fr::from_le_bytes_mod_order(bytes)))
    }

    fn to_byte_array(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.0.serialize_uncompressed(&mut bytes[..]).unwrap();
        bytes
    }
}
