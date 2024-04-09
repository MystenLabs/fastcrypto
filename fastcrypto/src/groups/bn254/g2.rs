// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::bn254::G2Element;
use crate::groups::bn254::{Scalar, G2_ELEMENT_BYTE_LENGTH};
use crate::groups::{FromTrustedByteArray, GroupElement, Scalar as ScalarType};
use crate::serde_helpers::ToFromByteArray;
use crate::serialize_deserialize_with_to_from_byte_array;
use ark_bn254::{G2Affine, G2Projective};
use ark_ec::{AffineRepr, Group};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de, Deserialize};
use std::ops::{Div, Mul};

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

impl ToFromByteArray<G2_ELEMENT_BYTE_LENGTH> for G2Element {
    fn from_byte_array(bytes: &[u8; G2_ELEMENT_BYTE_LENGTH]) -> Result<Self, FastCryptoError> {
        let point = G2Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)?;

        // Arkworks only checks the infinty flag, but we require all-zeros to have unique serialization
        if point.is_zero()
            && bytes[0..G2_ELEMENT_BYTE_LENGTH - 1]
                .iter()
                .any(|x| !x.is_zero())
        {
            return Err(FastCryptoError::InvalidInput);
        }

        Ok(Self(G2Projective::from(point)))
    }

    fn to_byte_array(&self) -> [u8; G2_ELEMENT_BYTE_LENGTH] {
        let mut bytes = [0u8; G2_ELEMENT_BYTE_LENGTH];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        bytes
    }
}

impl FromTrustedByteArray<G2_ELEMENT_BYTE_LENGTH> for G2Element {
    fn from_trusted_byte_array(bytes: &[u8; G2_ELEMENT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        G2Projective::deserialize_compressed_unchecked(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(G2Element)
    }
}

serialize_deserialize_with_to_from_byte_array!(G2Element);
