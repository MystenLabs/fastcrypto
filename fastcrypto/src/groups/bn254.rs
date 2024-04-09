// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::ops::{Div, Mul};

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::{Pairing as ArkworksPairing, PairingOutput};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derive_more::{Add, Neg, Sub};
use once_cell::sync::OnceCell;
use serde::{de, Deserialize};

use fastcrypto_derive::GroupOpsExtend;

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::{FromTrustedByteArray, GroupElement, Pairing, Scalar as ScalarType};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use crate::{groups, serialize_deserialize_with_to_from_byte_array};

/// Elements of the group G_1 in BN254.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend)]
#[repr(transparent)]
pub struct G1Element(G1Projective);

/// Elements of the group G_2 in BN254.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend)]
#[repr(transparent)]
pub struct G2Element(G2Projective);

/// Elements of the subgroup G_T of F_q^{12} in BN254. Note that it is written in additive notation here.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend)]
pub struct GTElement(PairingOutput<Bn254>);

/// This represents a scalar modulo r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// which is the order of the groups G1, G2 and GT. Note that r is a 254 bit prime.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Add, Sub, Neg, GroupOpsExtend)]
pub struct Scalar(Fr);

pub const SCALAR_LENGTH: usize = 32;
pub const G1_ELEMENT_BYTE_LENGTH: usize = 32;
pub const G2_ELEMENT_BYTE_LENGTH: usize = 64;
pub const GT_ELEMENT_BYTE_LENGTH: usize = 384;

impl Div<Self> for Scalar {
    type Output = FastCryptoResult<Self>;

    fn div(self, rhs: Self) -> FastCryptoResult<Self> {
        if rhs.0.is_zero() {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self(self.0.div(rhs.0)))
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl GroupElement for Scalar {
    type ScalarType = Scalar;

    fn zero() -> Self {
        Self(Fr::zero())
    }

    fn generator() -> Self {
        Self(Fr::one())
    }
}

impl GroupElement for G1Element {
    type ScalarType = Scalar;

    fn zero() -> Self {
        G1Element(G1Projective::zero())
    }

    fn generator() -> Self {
        G1Element(G1Projective::generator())
    }
}

impl Div<Scalar> for G1Element {
    type Output = FastCryptoResult<Self>;

    fn div(self, rhs: Scalar) -> Self::Output {
        let inverse = rhs.inverse()?;
        Ok(self.mul(inverse))
    }
}

impl Mul<Scalar> for G1Element {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl ToFromByteArray<32> for G1Element {
    fn from_byte_array(bytes: &[u8; 32]) -> Result<Self, FastCryptoError> {
        let point = G1Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        // Arkworks only checks the infinty flag, but we require all-zeros to have unique serialization
        if point.is_zero() && bytes[0..31].iter().any(|x| !x.is_zero()) {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(Self(G1Projective::from(point)))
    }

    fn to_byte_array(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(G1Element);

impl FromTrustedByteArray<32> for G1Element {
    fn from_trusted_byte_array(bytes: &[u8; 32]) -> FastCryptoResult<Self> {
        G1Projective::deserialize_compressed_unchecked(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(G1Element)
    }
}

impl GroupElement for G2Element {
    type ScalarType = Scalar;

    fn zero() -> Self {
        G2Element(G2Projective::zero())
    }

    fn generator() -> Self {
        G2Element(G2Projective::generator())
    }
}

impl Div<Scalar> for G2Element {
    type Output = FastCryptoResult<Self>;

    fn div(self, rhs: Scalar) -> Self::Output {
        let inverse = rhs.inverse()?;
        Ok(self.mul(inverse))
    }
}

impl Mul<Scalar> for G2Element {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl ToFromByteArray<64> for G2Element {
    fn from_byte_array(bytes: &[u8; 64]) -> Result<Self, FastCryptoError> {
        let point = G2Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        // Arkworks only checks the infinty flag, but we require all-zeros to have unique serialization
        if point.is_zero() && bytes[0..63].iter().any(|x| !x.is_zero()) {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(Self(G2Projective::from(point)))
    }

    fn to_byte_array(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(G2Element);

impl FromTrustedByteArray<64> for G2Element {
    fn from_trusted_byte_array(bytes: &[u8; 64]) -> FastCryptoResult<Self> {
        G2Projective::deserialize_compressed_unchecked(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(G2Element)
    }
}

impl From<u128> for Scalar {
    fn from(value: u128) -> Self {
        Self(Fr::from(value))
    }
}

impl groups::Scalar for Scalar {
    fn rand<R: AllowedRng>(rng: &mut R) -> Self {
        Self(Fr::rand(rng))
    }

    fn inverse(&self) -> FastCryptoResult<Self> {
        Ok(Self(self.0.inverse().ok_or(FastCryptoError::InvalidInput)?))
    }
}

impl ToFromByteArray<32> for Scalar {
    fn from_byte_array(bytes: &[u8; Self::BYTE_LENGTH]) -> Result<Self, FastCryptoError> {
        // Arkworks uses little-endian byte order for serialization, but we use big-endian.
        let mut reversed = *bytes;
        reversed.reverse();
        Fr::deserialize_compressed(reversed.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(Scalar)
    }

    fn to_byte_array(&self) -> [u8; Self::BYTE_LENGTH] {
        let mut bytes = [0u8; Self::BYTE_LENGTH];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        // Arkworks uses little-endian byte order for serialization, but we use big-endian.
        bytes.reverse();
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);

impl Pairing for G1Element {
    type Other = G2Element;
    type Output = GTElement;

    fn pairing(&self, other: &Self::Other) -> <Self as Pairing>::Output {
        GTElement(Bn254::pairing(self.0, other.0))
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<Scalar> for GTElement {
    type Output = FastCryptoResult<GTElement>;

    fn div(self, rhs: Scalar) -> Self::Output {
        let inverse = rhs.inverse()?;
        Ok(self * inverse)
    }
}

impl Mul<Scalar> for GTElement {
    type Output = GTElement;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0.mul(rhs.0))
    }
}

impl GroupElement for GTElement {
    type ScalarType = Scalar;

    fn zero() -> Self {
        GTElement(PairingOutput::zero())
    }

    fn generator() -> Self {
        static G: OnceCell<PairingOutput<Bn254>> = OnceCell::new();
        Self(*G.get_or_init(Self::compute_generator))
    }
}

impl GTElement {
    fn compute_generator() -> PairingOutput<Bn254> {
        G1Element::generator().pairing(&G2Element::generator()).0
    }
}

impl FromTrustedByteArray<384> for GTElement {
    fn from_trusted_byte_array(bytes: &[u8; 384]) -> FastCryptoResult<Self> {
        PairingOutput::<Bn254>::deserialize_compressed_unchecked(bytes.as_ref())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(GTElement)
    }
}

impl ToFromByteArray<384> for GTElement {
    fn from_byte_array(bytes: &[u8; 384]) -> Result<Self, FastCryptoError> {
        PairingOutput::<Bn254>::deserialize_compressed(bytes.as_ref())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(GTElement)
    }

    fn to_byte_array(&self) -> [u8; 384] {
        let mut bytes = [0u8; 384];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(GTElement);
