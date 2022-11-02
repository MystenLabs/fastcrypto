// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Encodings of binary data such as Base64 and Hex.
//!
//! # Example
//! ```rust
//! # use fastcrypto::encoding::*;
//! assert_eq!(Hex::encode("Hello world!"), "0x48656c6c6f20776f726c6421");
//! assert_eq!(Base64::encode("Hello world!"), "SGVsbG8gd29ybGQh");
//! ```

use base64ct::Encoding as _;
use eyre::{eyre, Result};
use schemars::JsonSchema;
use serde;
use serde::de::{Deserializer, Error};
use serde::ser::Serializer;
use serde::Deserialize;
use serde::Serialize;
use serde_with::{DeserializeAs, SerializeAs};
use std::fmt::Debug;

#[inline]
fn to_custom_error<'de, D, E>(e: E) -> D::Error
where
    E: Debug,
    D: Deserializer<'de>,
{
    Error::custom(format!("byte deserialization failed, cause by: {:?}", e))
}

/// Trait representing a general binary-to-string encoding.
pub trait Encoding {
    /// Decode this encoding into bytes.
    fn decode(s: &str) -> Result<Vec<u8>>;
    /// Encode bytes into a string.
    fn encode<T: AsRef<[u8]>>(data: T) -> String;
}

/// Base64 encoding.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, JsonSchema)]
#[serde(try_from = "String")]
pub struct Base64(String);

impl TryFrom<String> for Base64 {
    type Error = eyre::Report;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Make sure the value is valid base64 string.
        Base64::decode(&value)?;
        Ok(Self(value))
    }
}

impl Base64 {
    /// Decodes this Base64 encoding to bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, eyre::Report> {
        Self::decode(&self.0)
    }
    /// Encodes bytes as a Base64.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Self::encode(bytes))
    }
    /// Get a string representation of this Base64 encoding.
    pub fn encoded(&self) -> String {
        self.0.clone()
    }
}

/// Hex string encoding.
#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
pub struct Hex(String);

impl Hex {
    /// Create a hex encoding from a string.
    #[cfg(test)]
    pub fn from_string(s: &str) -> Self {
        Hex(s.to_string())
    }
    /// Decodes this hex encoding to bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, eyre::Report> {
        Self::decode(&self.0)
    }
    /// Encodes bytes as a hex string.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Self::encode(bytes))
    }
}

impl Encoding for Hex {
    fn decode(s: &str) -> Result<Vec<u8>, eyre::Report> {
        decode_bytes_hex(s)
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        format!("0x{}", encode_bytes_hex(&data))
    }
}

impl Encoding for Base64 {
    fn decode(s: &str) -> Result<Vec<u8>, eyre::Report> {
        base64ct::Base64::decode_vec(s).map_err(|e| eyre!(e))
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        base64ct::Base64::encode_string(data.as_ref())
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for Base64 {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode(&s).map_err(to_custom_error::<'de, D, _>)
    }
}

impl<T> SerializeAs<T> for Base64
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::encode(value).serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for Hex {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode(&s).map_err(to_custom_error::<'de, D, _>)
    }
}

impl<T> SerializeAs<T> for Hex
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Self::encode(value).serialize(serializer)
    }
}

/// Encodes bytes as a hex string using lower case characters.
pub fn encode_bytes_hex<B: AsRef<[u8]>>(bytes: B) -> String {
    hex::encode(bytes.as_ref())
}

/// Decodes a hex string to bytes. Both upper and lower case characters are allowed in the hex string.
pub fn decode_bytes_hex<T: for<'a> TryFrom<&'a [u8]>>(s: &str) -> Result<T> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let value = hex::decode(s)?;
    T::try_from(&value[..]).map_err(|_| eyre!("byte deserialization failed"))
}
