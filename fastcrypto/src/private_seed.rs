// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::FastCryptoError,
    traits::{FromUniformBytes, ToFromBytes},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Private key/seed of any/fixed size.
///
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrivateSeed<const RECOMMENDED_LENGTH: usize, const FIXED_LENGTH_ONLY: bool> {
    bytes: Vec<u8>,
}

impl<const N: usize, const B: bool> FromUniformBytes<N> for PrivateSeed<N, B> {}

impl<const N: usize, const B: bool> AsRef<[u8]> for PrivateSeed<N, B> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<const RECOMMENDED_LENGTH: usize, const FIXED_LENGTH_ONLY: bool> ToFromBytes
    for PrivateSeed<RECOMMENDED_LENGTH, FIXED_LENGTH_ONLY>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if FIXED_LENGTH_ONLY && bytes.len() != RECOMMENDED_LENGTH {
            return Err(FastCryptoError::InputLengthWrong(RECOMMENDED_LENGTH));
        }
        Ok(Self {
            bytes: bytes.into(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}
