// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::bn254::G2Element;
use crate::groups::bn254::{G1Element, GTElement};
use crate::groups::bn254::{Scalar, GT_ELEMENT_BYTE_LENGTH};
use crate::groups::{FromTrustedByteArray, GroupElement, Pairing, Scalar as ScalarType};
use crate::serde_helpers::ToFromByteArray;
use crate::serialize_deserialize_with_to_from_byte_array;
use ark_bn254::Bn254;
use ark_ec::pairing::PairingOutput;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use once_cell::sync::OnceCell;
use serde::{de, Deserialize};
use std::ops::{Div, Mul};

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

impl FromTrustedByteArray<GT_ELEMENT_BYTE_LENGTH> for GTElement {
    fn from_trusted_byte_array(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> FastCryptoResult<Self> {
        PairingOutput::<Bn254>::deserialize_compressed_unchecked(bytes.as_ref())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(GTElement)
    }
}

impl ToFromByteArray<GT_ELEMENT_BYTE_LENGTH> for GTElement {
    fn from_byte_array(bytes: &[u8; GT_ELEMENT_BYTE_LENGTH]) -> Result<Self, FastCryptoError> {
        PairingOutput::<Bn254>::deserialize_compressed(bytes.as_ref())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(GTElement)
    }

    fn to_byte_array(&self) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
        let mut bytes = [0u8; GT_ELEMENT_BYTE_LENGTH];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(GTElement);
