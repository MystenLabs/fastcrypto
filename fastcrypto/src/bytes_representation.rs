// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use serde::de::DeserializeOwned;
use serde::{de, Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;

/// Basic wrapper that stores a bincode serialized version of object T.
/// To be used in external interfaces instead of the internal object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BytesRepresentation<T, const N: usize, const B64_SERIALIZATION: bool> {
    bytes: [u8; N],
    phantom: PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned, const N: usize, const B64_SERIALIZATION: bool> From<&T> for BytesRepresentation<T, N, B64_SERIALIZATION> {
    fn from(value: &T) -> Self {
        // Serialize would fail only if (T, N) is an invalid pair of values, meaning that the type
        // itself is invalid and therefore the caller has nothing to do with it in runtime.
        let buffer = bincode::serialize(value).unwrap();
        Self {
            bytes: buffer.try_into().unwrap(), // As explained above, this would fail only if (T, N) is an invalid pair of values.
            phantom: Default::default(),
        }
    }
}

impl<T: Serialize + DeserializeOwned, const N: usize, const B64_SERIALIZATION: bool> BytesRepresentation<T, N, B64_SERIALIZATION> {
    fn bytes_to_type(bytes: &[u8]) -> Result<T, FastCryptoError> {
        bincode::deserialize(bytes).map_err(|_| FastCryptoError::InvalidInput)
    }

    pub fn to_type(&self) -> T {
        // We always check that the byte array represent a valid object before we set it, thus we
        // will always be able to deserialize it.
        Self::bytes_to_type(&self.bytes).unwrap()
    }
}

impl<T, const N: usize, const B64_SERIALIZATION: bool> AsRef<[u8]> for BytesRepresentation<T, N, B64_SERIALIZATION> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

// Define our own serialize/deserialize functions instead of using #[serde_as(as = "Base64")]
// so we could serialize a flat object (i.e., "1234" instead of "{ bytes: 1234 }").
impl<T, const N: usize, const B64_SERIALIZATION: bool> Serialize for BytesRepresentation<T, N, B64_SERIALIZATION> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Base64::encode(self.bytes).serialize(serializer)
    }
}

impl<'de, T: Serialize + DeserializeOwned, const N: usize, const B64_SERIALIZATION: bool> Deserialize<'de>
    for BytesRepresentation<T, N, B64_SERIALIZATION>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let decoded =
            Base64::decode(&s).map_err(|_| de::Error::custom("Base64 decoding failed"))?;
        if decoded.len() != N {
            return Err(de::Error::custom(format!(
                "Invalid buffer length {}, expecting {}",
                decoded.len(),
                N
            )));
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(&decoded[..N]);
        Self::bytes_to_type(&bytes)
            .map_err(|_| de::Error::custom("Deserialization resulted in an invalid object"))?;
        Ok(Self {
            bytes,
            phantom: Default::default(),
        })
    }
}
