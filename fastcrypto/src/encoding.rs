// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Encodings of binary data such as Base64 and Hex.
//!
//! # Example
//! ```rust
//! # use fastcrypto::encoding::*;
//! assert_eq!(Hex::encode("Hello world!"), "48656c6c6f20776f726c6421");
//! assert_eq!(encode_with_format("Hello world!"), "0x48656c6c6f20776f726c6421");
//! assert_eq!(Base64::encode("Hello world!"), "SGVsbG8gd29ybGQh");
//! assert_eq!(Base58::encode("Hello world!"), "2NEpo7TZRhna7vSvL");
//! ```

use std::fmt::Debug;

use base64ct::Encoding as _;
use bech32::{FromBase32, Variant};
use schemars::JsonSchema;
use serde;
use serde::de::{Deserializer, Error};
use serde::ser::Serializer;
use serde::Deserialize;
use serde::Serialize;
use serde_with::{DeserializeAs, SerializeAs};

use crate::error::FastCryptoError::InvalidInput;
use crate::error::{FastCryptoError, FastCryptoResult};

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
    fn decode(s: &str) -> FastCryptoResult<Vec<u8>>;
    /// Encode bytes into a string.
    fn encode<T: AsRef<[u8]>>(data: T) -> String;
}

/// Base64 encoding
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, JsonSchema)]
#[serde(try_from = "String")]
pub struct Base64(String);

impl TryFrom<String> for Base64 {
    type Error = FastCryptoError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Make sure the value is valid base64 string.
        Base64::decode(&value)?;
        Ok(Self(value))
    }
}

impl Base64 {
    /// Decodes this Base64 encoding to bytes.
    pub fn to_vec(&self) -> FastCryptoResult<Vec<u8>> {
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
    pub fn to_vec(&self) -> FastCryptoResult<Vec<u8>> {
        Self::decode(&self.0)
    }
    /// Encodes bytes as a hex string.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(encode_with_format(bytes))
    }
}

impl Encoding for Hex {
    fn decode(s: &str) -> FastCryptoResult<Vec<u8>> {
        decode_bytes_hex(s)
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        hex::encode(data.as_ref())
    }
}

impl Encoding for Base64 {
    fn decode(s: &str) -> FastCryptoResult<Vec<u8>> {
        base64ct::Base64::decode_vec(s).map_err(|_| InvalidInput)
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

impl<'de, const N: usize> DeserializeAs<'de, [u8; N]> for Base64 {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Vec<u8> = Base64::deserialize_as(deserializer)?;
        if value.len() != N {
            return Err(Error::custom(format!(
                "invalid array length {}, expecting {}",
                value.len(),
                N
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&value[..N]);
        Ok(array)
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

impl<'de, const N: usize> DeserializeAs<'de, [u8; N]> for Hex {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Vec<u8> = Hex::deserialize_as(deserializer)?;
        if value.len() != N {
            return Err(Error::custom(format!(
                "invalid array length {}, expecting {}",
                value.len(),
                N
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&value[..N]);
        Ok(array)
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
        encode_with_format(value).serialize(serializer)
    }
}

/// Encodes bytes as a 0x prefixed hex string using lower case characters.
pub fn encode_with_format<B: AsRef<[u8]>>(bytes: B) -> String {
    format!("0x{}", hex::encode(bytes.as_ref()))
}

/// Decodes a hex string to bytes. Both upper and lower case characters are allowed in the hex string.
pub fn decode_bytes_hex<T: for<'a> TryFrom<&'a [u8]>>(s: &str) -> FastCryptoResult<T> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let value = hex::decode(s).map_err(|_| InvalidInput)?;
    T::try_from(&value[..]).map_err(|_| InvalidInput)
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, JsonSchema)]
#[serde(try_from = "String")]
pub struct Base58(String);

impl TryFrom<String> for Base58 {
    type Error = FastCryptoError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Make sure the value is valid base58 string.
        bs58::decode(&value).into_vec().map_err(|_| InvalidInput)?;
        Ok(Self(value))
    }
}

impl Encoding for Base58 {
    fn decode(s: &str) -> FastCryptoResult<Vec<u8>> {
        bs58::decode(s).into_vec().map_err(|_| InvalidInput)
    }

    fn encode<T: AsRef<[u8]>>(data: T) -> String {
        bs58::encode(data).into_string()
    }
}

impl<'de> DeserializeAs<'de, Vec<u8>> for Base58 {
    fn deserialize_as<D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::decode(&s).map_err(to_custom_error::<'de, D, _>)
    }
}

impl<T> SerializeAs<T> for Base58
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

impl<'de, const N: usize> DeserializeAs<'de, [u8; N]> for Base58 {
    fn deserialize_as<D>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Vec<u8> = Base58::deserialize_as(deserializer)?;
        if value.len() != N {
            return Err(Error::custom(format!(
                "invalid array length {}, expecting {}",
                value.len(),
                N
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&value[..N]);
        Ok(array)
    }
}

/// Bech32 encoding
pub struct Bech32(String);

impl Bech32 {
    /// Decodes the Bech32 string to bytes, validating the given human readable part (hrp). See spec: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    /// # Example:
    /// ```
    /// use fastcrypto::encoding::Bech32;
    /// let bytes = Bech32::decode("split1qqqqsk5gh5","split").unwrap();
    /// assert_eq!(bytes, vec![0, 0]);
    /// ```
    pub fn decode(s: &str, hrp: &str) -> FastCryptoResult<Vec<u8>> {
        let (parsed, data, variant) = bech32::decode(s).map_err(|_| InvalidInput)?;
        if parsed != hrp || variant != Variant::Bech32 {
            Err(InvalidInput)
        } else {
            Vec::<u8>::from_base32(&data).map_err(|_| InvalidInput)
        }
    }

    /// Encodes bytes into a Bech32 encoded string, with the given human readable part (hrp). See spec: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    /// # Example:
    /// ```
    /// use fastcrypto::encoding::Bech32;
    /// let str = Bech32::encode(vec![0, 0],"split").unwrap();
    /// assert_eq!(str, "split1qqqqsk5gh5".to_string());
    /// ```
    pub fn encode<T: AsRef<[u8]>>(data: T, hrp: &str) -> FastCryptoResult<String> {
        use bech32::ToBase32;
        bech32::encode(hrp, data.to_base32(), Variant::Bech32).map_err(|_| InvalidInput)
    }
}
