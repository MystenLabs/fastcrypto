// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Div, Mul};

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::bn254::{Scalar, SCALAR_LENGTH};
use crate::groups::GroupElement;
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use crate::{groups, serialize_deserialize_with_to_from_byte_array};
use ark_bn254::Fr;
use ark_ff::{Field, One, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de, Deserialize};

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

impl ToFromByteArray<SCALAR_LENGTH> for Scalar {
    fn from_byte_array(bytes: &[u8; SCALAR_LENGTH]) -> Result<Self, FastCryptoError> {
        // Note that arkworks uses little-endian byte order for serialization here.
        Fr::deserialize_compressed(bytes.as_slice())
            .map_err(|_| FastCryptoError::InvalidInput)
            .map(Scalar)
    }

    fn to_byte_array(&self) -> [u8; SCALAR_LENGTH] {
        // Note that arkworks uses little-endian byte order for serialization here.
        let mut bytes = [0u8; SCALAR_LENGTH];
        self.0
            .serialize_compressed(bytes.as_mut_slice())
            .expect("Never fails");
        bytes
    }
}

serialize_deserialize_with_to_from_byte_array!(Scalar);
