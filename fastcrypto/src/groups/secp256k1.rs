// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::{FiatShamirChallenge, FromTrustedByteArray, HashToGroupElement, MultiScalarMul};
use crate::{
    error::{FastCryptoError, FastCryptoResult},
    generate_bytes_representation,
    groups::{GroupElement, Scalar as ScalarType},
    serde_helpers::{BytesRepresentation, ToFromByteArray},
    serialize_deserialize_with_to_from_byte_array,
    traits::AllowedRng,
};
use elliptic_curve::{
    bigint::{Encoding, NonZero, U512},
    group::GroupEncoding,
    scalar::FromUintUnchecked,
    Curve,
};
use fastcrypto_derive::GroupOpsExtend;
use k256::{
    elliptic_curve::{
        hash2curve::{hash_to_field, ExpandMsgXmd, FromOkm, MapToCurve},
        PrimeField,
    },
    FieldElement, ProjectivePoint as SecpProjectivePoint, Scalar as SecpScalar, Secp256k1, U256,
};
use serde::{de, Deserialize};
use sha2::{Digest, Sha256, Sha512};
use std::ops::{Add, Div, Mul, Neg, Sub};
use zeroize::Zeroize;

#[derive(Clone, Copy, Eq, PartialEq, GroupOpsExtend, Debug)]
#[repr(transparent)]
pub struct ProjectivePoint(SecpProjectivePoint);

#[derive(Clone, Copy, Eq, PartialEq, GroupOpsExtend, Debug)]
pub struct Scalar(SecpScalar);

pub const PROJECTIVE_POINT_BYTE_LENGTH: usize = 33;
pub const SCALAR_BYTE_LENGTH: usize = 32;

impl Div<Scalar> for Scalar {
    type Output = FastCryptoResult<Self>;

    fn div(self, rhs: Self) -> Self::Output {
        let inv: Option<SecpScalar> = rhs.0.invert().into();
        let inv = inv.ok_or(FastCryptoError::InvalidInput)?;
        Ok(Scalar(self.0.mul(inv)))
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.negate())
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl FromTrustedByteArray<SCALAR_BYTE_LENGTH> for Scalar {
    fn from_trusted_byte_array(bytes: &[u8; SCALAR_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        let mut padded_bytes = [0u8; 48];
        padded_bytes[16..48].copy_from_slice(bytes);

        Ok(Scalar(SecpScalar::from_okm(padded_bytes.as_slice().into())))
    }
}

impl ToFromByteArray<SCALAR_BYTE_LENGTH> for Scalar {
    fn from_byte_array(bytes: &[u8; SCALAR_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        Self::from_trusted_byte_array(bytes)
    }

    fn to_byte_array(&self) -> [u8; SCALAR_BYTE_LENGTH] {
        self.0.to_bytes().into()
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);

impl From<u128> for Scalar {
    fn from(value: u128) -> Self {
        Self(SecpScalar::from_u128(value))
    }
}

impl GroupElement for Scalar {
    type ScalarType = Self;

    fn zero() -> Self {
        Self(SecpScalar::ZERO)
    }

    fn generator() -> Self {
        Scalar(SecpScalar::ONE)
    }
}

impl ScalarType for Scalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        let mut buffer = [0u8; 48];
        rng.fill_bytes(&mut buffer);
        reduce_mod_uniform_buffer(&buffer)
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        if self.0 == SecpScalar::ZERO {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self(self.0.invert().expect("checked above")))
    }
}

fn reduce_mod_uniform_buffer(buffer: &[u8]) -> Scalar {
    match buffer_to_scalar_mod_r(buffer) {
        Ok(scalar) => scalar,
        Err(_) => panic!("Invalid input length"),
    }
}

fn buffer_to_scalar_mod_r(buffer: &[u8]) -> FastCryptoResult<Scalar> {
    let hash = Sha512::digest(buffer);

    let mut order_bytes_padded = [0u8; 64];
    order_bytes_padded[32..64].copy_from_slice(&Secp256k1::ORDER.to_be_bytes());

    let mut n = U512::from_be_slice(&hash);
    n = n.rem(&NonZero::from_uint(U512::from_be_slice(
        &order_bytes_padded,
    )));

    Ok(Scalar(SecpScalar::from_uint_unchecked(
        U256::from_be_slice(&n.to_be_bytes()[32..64]),
    )))
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl FiatShamirChallenge for Scalar {
    fn fiat_shamir_reduction_to_group_element(uniform_buffer: &[u8]) -> Self {
        reduce_mod_uniform_buffer(uniform_buffer)
    }
}

impl GroupElement for ProjectivePoint {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self(SecpProjectivePoint::IDENTITY)
    }

    fn generator() -> Self {
        Self(SecpProjectivePoint::GENERATOR)
    }
}

impl Div<Scalar> for ProjectivePoint {
    type Output = FastCryptoResult<Self>;

    fn div(self, rhs: Scalar) -> Self::Output {
        let inv: Option<SecpScalar> = rhs.0.invert().into();
        let inv = inv.ok_or(FastCryptoError::InvalidInput)?;
        Ok(Self(self.0.mul(inv)))
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl Sub for ProjectivePoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl Add for ProjectivePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl Neg for ProjectivePoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl MultiScalarMul for ProjectivePoint {
    fn multi_scalar_mul(scalars: &[Self::ScalarType], points: &[Self]) -> FastCryptoResult<Self> {
        if scalars.len() != points.len() || scalars.is_empty() {
            return Err(FastCryptoError::InvalidInput);
        }

        let mut result = SecpProjectivePoint::IDENTITY;

        for (scalar, point) in scalars.iter().zip(points.iter()) {
            if scalar.0.is_zero().into() || point.0 == SecpProjectivePoint::IDENTITY {
                continue;
            }

            let scalar_mul = point.0.mul(scalar.0);

            result += scalar_mul;
        }

        Ok(ProjectivePoint(result))
    }
}

impl FromTrustedByteArray<PROJECTIVE_POINT_BYTE_LENGTH> for ProjectivePoint {
    fn from_trusted_byte_array(
        bytes: &[u8; PROJECTIVE_POINT_BYTE_LENGTH],
    ) -> FastCryptoResult<Self> {
        Ok(ProjectivePoint(
            SecpProjectivePoint::from_bytes(bytes.as_slice().into())
                .expect("trusted input should be a valid point"),
        ))
    }
}

impl ToFromByteArray<PROJECTIVE_POINT_BYTE_LENGTH> for ProjectivePoint {
    fn from_byte_array(bytes: &[u8; PROJECTIVE_POINT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        Self::from_trusted_byte_array(bytes)
    }

    fn to_byte_array(&self) -> [u8; PROJECTIVE_POINT_BYTE_LENGTH] {
        self.0.to_bytes().into()
    }
}

impl HashToGroupElement for ProjectivePoint {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        let domain = "secp256k1_XMD:SHA-256_SSWU_RO_".as_bytes();
        let mut u = [FieldElement::ZERO];
        hash_to_field::<ExpandMsgXmd<Sha256>, FieldElement>(&[msg], &[domain], &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        Self(u[0].map_to_curve())
    }
}

serialize_deserialize_with_to_from_byte_array!(ProjectivePoint);
generate_bytes_representation!(
    ProjectivePoint,
    PROJECTIVE_POINT_BYTE_LENGTH,
    ProjectivePointAsBytes
);
