// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, Div, Mul, Neg, Sub};

use crate::serde_helpers::BytesRepresentation;
use elliptic_curve::bigint::{Encoding, Integer, NonZero, Zero, U384, U512};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::scalar::FromUintUnchecked;
use elliptic_curve::Curve;
use fastcrypto_derive::GroupOpsExtend;
use k256::elliptic_curve::hash2curve::FromOkm;
use k256::elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd, MapToCurve};
use k256::elliptic_curve::PrimeField;
use k256::Secp256k1;
use k256::{FieldElement, ProjectivePoint, Scalar, U256};
use serde::{de, Deserialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::groups::{GroupElement, Scalar as ScalarType};
use crate::serde_helpers::ToFromByteArray;
use crate::{
    error::{FastCryptoError, FastCryptoResult},
    traits::AllowedRng,
};
use crate::{generate_bytes_representation, serialize_deserialize_with_to_from_byte_array};

use super::{FiatShamirChallenge, FromTrustedByteArray, HashToGroupElement, MultiScalarMul};

/// Elements of the group G_1 in BLS 12-381.
#[derive(Clone, Copy, Eq, PartialEq, GroupOpsExtend, Debug)]
#[repr(transparent)]
pub struct MyProjectivePoint(ProjectivePoint);

#[derive(Clone, Copy, Eq, PartialEq, GroupOpsExtend, Debug)]
pub struct MyScalar(Scalar);

impl Div<MyScalar> for MyScalar {
    type Output = FastCryptoResult<Self>;

    fn div(self, rhs: Self) -> Self::Output {
        let inv = rhs.0.invert().unwrap();
        Ok(MyScalar(self.0.mul(inv)))
    }
}

impl Mul<MyScalar> for MyScalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.mul(&rhs.0))
    }
}

impl Neg for MyScalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.negate())
    }
}

impl Sub for MyScalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl Add for MyScalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

pub const SCALAR_BYTE_LENGTH: usize = 32;
impl FromTrustedByteArray<SCALAR_BYTE_LENGTH> for MyScalar {
    fn from_trusted_byte_array(bytes: &[u8; SCALAR_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        let mut padded_bytes = [0u8; 48];
        padded_bytes[16..48].copy_from_slice(bytes);

        Ok(MyScalar(Scalar::from_okm(padded_bytes.as_slice().into())))
    }
}

impl ToFromByteArray<SCALAR_BYTE_LENGTH> for MyScalar {
    fn from_byte_array(bytes: &[u8; SCALAR_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        Self::from_trusted_byte_array(bytes)
    }

    fn to_byte_array(&self) -> [u8; SCALAR_BYTE_LENGTH] {
        self.0.to_bytes().into()
    }
}

serialize_deserialize_with_to_from_byte_array!(MyScalar);

impl From<u128> for MyScalar {
    fn from(value: u128) -> Self {
        Self(Scalar::from_u128(value))
    }
}

impl GroupElement for MyScalar {
    type ScalarType = Self;

    fn zero() -> Self {
        Self(Scalar::ZERO)
    }

    fn generator() -> Self {
        MyScalar(Scalar::ONE)
    }
}

impl ScalarType for MyScalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        let mut buffer = [0u8; 48];
        rng.fill_bytes(&mut buffer);
        reduce_mod_uniform_buffer(&buffer)
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        if self.0 == Scalar::ZERO {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self(self.0.invert().unwrap()))
    }
}

/// Reduce a big-endian integer of arbitrary size modulo the scalar field size and return the scalar.
/// If the input bytes are uniformly distributed, the output will be uniformly distributed in the
/// scalar field.
///
/// The input buffer must be at least 48 bytes long to ensure that there is only negligible bias in
/// the output.
fn reduce_mod_uniform_buffer(buffer: &[u8]) -> MyScalar {
    match buffer_to_scalar_mod_r(buffer) {
        Ok(scalar) => scalar,
        Err(_) => panic!("Invalid input length"),
    }
}

/// Similar to `reduce_mod_uniform_buffer`, returns a result of scalar, and does not panic on invalid length.
fn buffer_to_scalar_mod_r(buffer: &[u8]) -> FastCryptoResult<MyScalar> {
    let hash = Sha512::digest(buffer);

    let mut order_bytes_padded = [0u8; 64];
    order_bytes_padded[32..64].copy_from_slice(&Secp256k1::ORDER.to_be_bytes());

    let mut n = U512::from_be_slice(&hash);
    n = n.rem(&NonZero::from_uint(U512::from_be_slice(
        &order_bytes_padded,
    )));

    Ok(MyScalar(Scalar::from_uint_unchecked(U256::from_be_slice(
        &n.to_be_bytes()[32..64],
    ))))
}

impl Zeroize for MyScalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl FiatShamirChallenge for MyScalar {
    fn fiat_shamir_reduction_to_group_element(uniform_buffer: &[u8]) -> Self {
        reduce_mod_uniform_buffer(uniform_buffer)
    }
}

impl GroupElement for MyProjectivePoint {
    type ScalarType = MyScalar;

    fn zero() -> Self {
        Self(ProjectivePoint::default())
    }

    fn generator() -> Self {
        Self(ProjectivePoint::GENERATOR)
    }
}

impl Div<MyScalar> for MyProjectivePoint {
    type Output = FastCryptoResult<Self>;

    fn div(self, rhs: MyScalar) -> Self::Output {
        let inv = rhs.0.invert().unwrap();
        Ok(Self(self.0.mul(inv)))
    }
}

impl Mul<MyScalar> for MyProjectivePoint {
    type Output = Self;

    fn mul(self, rhs: MyScalar) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl Sub for MyProjectivePoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.sub(rhs.0))
    }
}

impl Add for MyProjectivePoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl Neg for MyProjectivePoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl MultiScalarMul for MyProjectivePoint {
    fn multi_scalar_mul(scalars: &[Self::ScalarType], points: &[Self]) -> FastCryptoResult<Self> {
        // Input validation
        if scalars.len() != points.len() || scalars.is_empty() {
            return Err(FastCryptoError::GeneralError(String::from(
                "Invalid input: Scalars and points must have the same non-zero length",
            )));
        }

        // Initialize the result to the identity element
        let mut result = ProjectivePoint::IDENTITY;

        // Iterate over the scalars and points
        for (scalar, point) in scalars.iter().zip(points.iter()) {
            // Skip zero scalars or identity points
            if scalar.0.is_zero().into() || point.0 == ProjectivePoint::IDENTITY {
                continue;
            }

            // Perform scalar multiplication
            let scalar_mul = point.0.mul(scalar.0);

            // Accumulate the result
            result += scalar_mul;
        }

        Ok(MyProjectivePoint(result))
    }
}

pub const PROJECTIVE_POINT_BYTE_LENGTH: usize = 33;

impl FromTrustedByteArray<PROJECTIVE_POINT_BYTE_LENGTH> for MyProjectivePoint {
    fn from_trusted_byte_array(
        bytes: &[u8; PROJECTIVE_POINT_BYTE_LENGTH],
    ) -> FastCryptoResult<Self> {
        Ok(MyProjectivePoint(
            ProjectivePoint::from_bytes(bytes.as_slice().into()).unwrap(),
        ))
    }
}

impl ToFromByteArray<PROJECTIVE_POINT_BYTE_LENGTH> for MyProjectivePoint {
    fn from_byte_array(bytes: &[u8; PROJECTIVE_POINT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        Self::from_trusted_byte_array(bytes)
    }

    fn to_byte_array(&self) -> [u8; PROJECTIVE_POINT_BYTE_LENGTH] {
        let mut bytes = [0u8; PROJECTIVE_POINT_BYTE_LENGTH];
        self.0.to_bytes().into()
    }
}

impl HashToGroupElement for MyProjectivePoint {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        let domain = "FOOBAR".as_bytes();
        let mut u = [FieldElement::ZERO];
        hash_to_field::<ExpandMsgXmd<Sha256>, FieldElement>(&[msg], &[domain], &mut u)
            .expect("should never return error according to error cases described in ExpandMsgXmd");
        Self(u[0].map_to_curve())
    }
}

serialize_deserialize_with_to_from_byte_array!(MyProjectivePoint);
generate_bytes_representation!(
    MyProjectivePoint,
    PROJECTIVE_POINT_BYTE_LENGTH,
    MyProjectivePointAsBytes
);
