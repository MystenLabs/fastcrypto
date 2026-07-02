// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of the [ristretto255 group](https://www.rfc-editor.org/rfc/rfc9496.html) which is a group of
//! prime order 2^{252} + 27742317777372353535851937790883648493 built over Curve25519.

use crate::error::FastCryptoError::InvalidInput;
use crate::error::FastCryptoResult;
use crate::groups::{
    Doubling, FiatShamirChallenge, FromTrustedByteArray, GroupElement, HashToGroupElement,
    MultiScalarMul, Scalar,
};
use crate::hash::{Blake2b256, ReverseWrapper, Sha512};
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
use derive_more::{Add, From, Mul, Neg, Sub};
use elliptic_curve::group::GroupEncoding;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use elliptic_curve::{Field, Group};
use fastcrypto_derive::GroupOpsExtend;
use std::ops::{Div, Mul};
use zeroize::Zeroize;

pub const RISTRETTO_POINT_BYTE_LENGTH: usize = 32;
pub const RISTRETTO_SCALAR_BYTE_LENGTH: usize = 32;
pub const DST: &[u8] = b"ristretto255_XMD:SHA-512_R255MAP_RO_";

/// Represents a point in the Ristretto group for Curve25519.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Add, Sub, Neg, GroupOpsExtend)]
pub struct RistrettoPoint(pub(crate) ExternalPoint);

impl RistrettoPoint {
    /// Construct a RistrettoPoint from the given data using a Ristretto-flavoured Elligator 2 map.
    /// If the input bytes are uniformly distributed, the resulting point will be uniformly
    /// distributed over the Ristretto group.
    ///
    /// This is called `ristretto255_map` in RFC 9380 and is defined in [RFC 9496, Section 4.3.4](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.4).
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        RistrettoPoint(ExternalPoint::from_uniform_bytes(bytes))
    }

    /// Implementation of `hash_to_ristretto255` using the `ristretto255_XMD:SHA-512_R255MAP_RO_` suite,
    /// following the specifications in [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html#appendix-B).
    pub fn hash_to_ristretto255(msg: &[u8]) -> Self {
        Self::hash_to_ristretto255_with_dst(&[msg], DST)
    }

    /// Map a message to a [RistrettoPoint] following [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html#appendix-B)
    /// using `expand_message_xmd` with SHA-512 and the given domain separation tag.
    pub fn hash_to_ristretto255_with_dst(msgs: &[&[u8]], dst: &[u8]) -> Self {
        let mut bytes = [0u8; 64];
        // expand_message only errors if the output length is out of bounds, which it is not here
        // since it is a constant, so we can safely unwrap.
        ExpandMsgXmd::<<Sha512 as ReverseWrapper>::Variant>::expand_message(msgs, &[dst], 64)
            .unwrap()
            .fill_bytes(&mut bytes);
        Self::from_uniform_bytes(&bytes)
    }
}

impl Doubling for RistrettoPoint {
    fn double(self) -> Self {
        Self(self.0.double())
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
        rhs.inverse().map(|inv| self * inv)
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
        RistrettoPoint(<curve25519_dalek::RistrettoPoint as Identity>::identity())
    }

    fn generator() -> Self {
        RistrettoPoint(RISTRETTO_BASEPOINT_POINT)
    }
}

impl HashToGroupElement for RistrettoPoint {
    /// Hash the message using SHA-512 without any DST and derive a point as defined in [Self::from_uniform_bytes].
    fn hash_to_group_element(msg: &[u8]) -> Self {
        Self::from_uniform_bytes(&Sha512::digest(msg).digest)
    }
}

impl ToFromByteArray<RISTRETTO_POINT_BYTE_LENGTH> for RistrettoPoint {
    fn from_byte_array(bytes: &[u8; RISTRETTO_POINT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        ExternalPoint::from_bytes(bytes)
            .map(RistrettoPoint)
            .into_option()
            .ok_or(InvalidInput)
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
        ExternalPoint::from_bytes_unchecked(bytes)
            .map(RistrettoPoint)
            .into_option()
            .ok_or(InvalidInput)
    }
}

serialize_deserialize_with_to_from_byte_array!(RistrettoPoint);

/// Represents a scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, From, Add, Sub, Mul, Neg, GroupOpsExtend, Zeroize)]
#[mul(forward)]
#[from(forward)]
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

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<RistrettoScalar> for RistrettoScalar {
    type Output = Result<RistrettoScalar, FastCryptoError>;

    fn div(self, rhs: RistrettoScalar) -> Result<RistrettoScalar, FastCryptoError> {
        rhs.inverse().map(|inv| self * inv)
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
        // Matches Contra's Move/TS Fiat-Shamir construction.
        let mut digest = Blake2b256::digest(msg).digest;
        digest[RISTRETTO_SCALAR_BYTE_LENGTH - 1] = 0;
        Self::from_byte_array(&digest).expect("Top byte is zero so the scalar is always canonical")
    }
}

impl ToFromByteArray<RISTRETTO_SCALAR_BYTE_LENGTH> for RistrettoScalar {
    fn from_byte_array(
        bytes: &[u8; RISTRETTO_SCALAR_BYTE_LENGTH],
    ) -> Result<Self, FastCryptoError> {
        ExternalScalar::from_canonical_bytes(*bytes)
            .into_option()
            .ok_or(InvalidInput)
            .map(RistrettoScalar)
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
