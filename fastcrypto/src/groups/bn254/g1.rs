// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Div, Mul};

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::bn254::Scalar;
use crate::groups::bn254::{G1Element, G1_ELEMENT_BYTE_LENGTH};
use crate::groups::{FromTrustedByteArray, GroupElement, MultiScalarMul, Scalar as ScalarType};
use crate::serde_helpers::ToFromByteArray;
use crate::serialize_deserialize_with_to_from_byte_array;
use ark_bn254::{G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de, Deserialize};

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

impl ToFromByteArray<G1_ELEMENT_BYTE_LENGTH> for G1Element {
    fn from_byte_array(bytes: &[u8; G1_ELEMENT_BYTE_LENGTH]) -> Result<Self, FastCryptoError> {
        let point = G1Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        // Arkworks only checks the infinity flag, but we require all-zeros to have unique serialization
        if point.is_zero()
            && bytes[0..G1_ELEMENT_BYTE_LENGTH - 1]
                .iter()
                .any(|x| !x.is_zero())
        {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(Self(G1Projective::from(point)))
    }

    fn to_byte_array(&self) -> [u8; G1_ELEMENT_BYTE_LENGTH] {
        let mut bytes = [0u8; G1_ELEMENT_BYTE_LENGTH];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        bytes
    }
}

impl FromTrustedByteArray<G1_ELEMENT_BYTE_LENGTH> for G1Element {
    fn from_trusted_byte_array(bytes: &[u8; G1_ELEMENT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        G1Projective::deserialize_compressed_unchecked(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(G1Element)
    }
}

serialize_deserialize_with_to_from_byte_array!(G1Element);

impl MultiScalarMul for G1Element {
    fn multi_scalar_mul(scalars: &[Self::ScalarType], points: &[Self]) -> FastCryptoResult<Self> {
        if scalars.len() != points.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        if scalars.is_empty() {
            return Ok(Self::zero());
        }
        Ok(Self(G1Projective::msm_unchecked(
            &points.iter().map(|x| x.0.into_affine()).collect::<Vec<_>>(),
            &scalars.iter().map(|x| x.0).collect::<Vec<_>>(),
        )))
    }
}
