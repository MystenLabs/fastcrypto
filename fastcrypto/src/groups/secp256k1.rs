// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the Secp256k1 (aka K-256) curve.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::multiplier::ToLittleEndianBytes;
use crate::groups::{
    Doubling, GroupElement, HashToGroupElement, MultiScalarMul, Scalar as ScalarTrait,
};
use crate::serde_helpers::ToFromByteArray;
use crate::serialize_deserialize_with_to_from_byte_array;
use crate::traits::AllowedRng;
use ark_ec::{Group, ScalarMul, VariableBaseMSM};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_secp256k1::{Affine, Fq, Fr, Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derive_more::{Add, From, Neg, Sub};
use fastcrypto_derive::GroupOpsExtend;
use k256::elliptic_curve::bigint::{ArrayDecoding, ArrayEncoding};
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Group as GroupTrait;
use k256::Secp256k1;
use serde::{de, Deserialize};
use std::ops::{Div, Mul};

/// Size of a serialized scalar in bytes.
pub const SCALAR_SIZE_IN_BYTES: usize = 32;

/// Size of a serialized point in bytes. This uses compressed serialization.
pub const POINT_SIZE_IN_BYTES: usize = 33;

/// A point on the Secp256k1 curve in projective coordinates.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct ProjectivePoint(pub(crate) Projective);

impl GroupElement for ProjectivePoint {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self(Projective::zero())
    }

    fn generator() -> Self {
        Self(Projective::generator())
    }
}

impl Doubling for ProjectivePoint {
    fn double(self) -> Self {
        ProjectivePoint::from(self.0.double())
    }
}

impl Mul<Scalar> for ProjectivePoint {
    type Output = ProjectivePoint;

    fn mul(self, rhs: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self.0 * rhs.0)
    }
}

impl Div<Scalar> for ProjectivePoint {
    type Output = Result<ProjectivePoint, FastCryptoError>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Scalar) -> Result<ProjectivePoint, FastCryptoError> {
        Ok(self * rhs.inverse()?)
    }
}

impl ToFromByteArray<POINT_SIZE_IN_BYTES> for ProjectivePoint {
    fn from_byte_array(bytes: &[u8; POINT_SIZE_IN_BYTES]) -> Result<Self, FastCryptoError> {
        Ok(ProjectivePoint(
            Projective::deserialize_compressed(bytes.as_slice())
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }

    fn to_byte_array(&self) -> [u8; POINT_SIZE_IN_BYTES] {
        let mut bytes = [0u8; POINT_SIZE_IN_BYTES];
        self.0
            .serialize_compressed(&mut bytes[..])
            .expect("Is always 33 bytes");
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(ProjectivePoint);

impl MultiScalarMul for ProjectivePoint {
    fn multi_scalar_mul(
        scalars: &[Self::ScalarType],
        points: &[Self],
    ) -> Result<Self, FastCryptoError> {
        // Fail early if the lengths do not match
        if scalars.len() != points.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let scalars = scalars.iter().map(|s| s.0).collect::<Vec<_>>();
        Projective::msm(
            &Projective::batch_convert_to_mul_base(
                points.iter().map(|p| p.0).collect::<Vec<_>>().as_slice(),
            ),
            &scalars,
        )
        .map_err(|_| FastCryptoError::GeneralOpaqueError)
        .map(ProjectivePoint)
    }
}
impl From<&k256::ProjectivePoint> for ProjectivePoint {
    fn from(from: &k256::ProjectivePoint) -> Self {
        if from.is_identity().into() {
            return ProjectivePoint(Projective::zero());
        }

        let encoded_point = from.to_encoded_point(false);
        let x = convert_fq(encoded_point.x().expect("Uncompressed and not identity"));
        let y = convert_fq(encoded_point.y().expect("Uncompressed and not identity"));

        ProjectivePoint(Projective::from(Affine::new(x, y)))
    }
}

/// Convert a representation of a field element in the k256 crate to a field element [Fq] in the arkworks library.
fn convert_fq(fq: &k256::FieldBytes) -> Fq {
    // Invert endianness to match arkworks representation
    Fq::deserialize_uncompressed(fq.into_uint_le().to_be_byte_array().as_slice()).unwrap()
}

/// The hash domain separation tag used for hashing to group elements in Secp256k1.
pub const HASH_DST: &[u8; 11] = b"FASTCRYPTO_";

impl HashToGroupElement for ProjectivePoint {
    fn hash_to_group_element(msg: &[u8]) -> Self {
        // This uses the hash-to-curve construction from https://datatracker.ietf.org/doc/rfc9380/.

        let mut input = HASH_DST.to_vec();
        input.extend_from_slice(msg);

        // The call to `hash_from_bytes` will panic if the expected output is too big (always two field elements in this case)
        // or if the output of the hash function (sha256) is too big. So since these are fixed, we can safely unwrap.
        ProjectivePoint::from(
            &Secp256k1::hash_from_bytes::<ExpandMsgXmd<sha2::Sha256>>(
                &[&input],
                b"secp256k1_XMD:SHA-256_SSWU_RO_",
            )
            .unwrap(),
        )
    }
}

/// A field element in the prime field of the same order as the curve.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Neg, GroupOpsExtend)]
pub struct Scalar(pub(crate) Fr);

impl GroupElement for Scalar {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Scalar(Fr::zero())
    }

    fn generator() -> Self {
        Scalar(Fr::one())
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0 * rhs.0)
    }
}

impl Div<Scalar> for Scalar {
    type Output = Result<Scalar, FastCryptoError>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Scalar) -> Result<Scalar, FastCryptoError> {
        Ok(self * rhs.inverse()?)
    }
}

impl From<u128> for Scalar {
    fn from(value: u128) -> Self {
        Scalar(Fr::from(value))
    }
}

impl ScalarTrait for Scalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        Scalar(Fr::rand(rng))
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        Ok(Scalar(
            self.0.inverse().ok_or(FastCryptoError::InvalidInput)?,
        ))
    }
}

impl ToFromByteArray<SCALAR_SIZE_IN_BYTES> for Scalar {
    fn from_byte_array(bytes: &[u8; SCALAR_SIZE_IN_BYTES]) -> Result<Self, FastCryptoError> {
        Ok(Scalar(
            Fr::deserialize_uncompressed(bytes.as_slice())
                .map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }

    fn to_byte_array(&self) -> [u8; SCALAR_SIZE_IN_BYTES] {
        let mut bytes = [0u8; SCALAR_SIZE_IN_BYTES];
        self.0
            .serialize_uncompressed(&mut bytes[..])
            .expect("Byte array not large enough");
        bytes
    }
}

impl ToLittleEndianBytes for Scalar {
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_byte_array().to_vec()
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);
