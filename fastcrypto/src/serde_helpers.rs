// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding as _;
use serde::{
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
};
use serde_with::{serde_as, Bytes, DeserializeAs, SerializeAs};
use std::fmt::Debug;

use crate::error::FastCryptoError;
use crate::{
    encoding::{Base64, Encoding},
    traits::{KeyPair, SigningKey, ToFromBytes, VerifyingKey},
};

fn to_custom_error<'de, D, E>(e: E) -> D::Error
where
    E: Debug,
    D: Deserializer<'de>,
{
    Error::custom(format!("byte deserialization failed, cause by: {:?}", e))
}

macro_rules! define_bls_signature {
    () => {
        pub struct BlsSignature;

        impl SerializeAs<blst::Signature> for BlsSignature {
            fn serialize_as<S>(source: &blst::Signature, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if serializer.is_human_readable() {
                    Base64::encode(source.to_bytes()).serialize(serializer)
                } else {
                    // Serialise to Bytes
                    Bytes::serialize_as(&source.serialize(), serializer)
                }
            }
        }

        impl<'de> DeserializeAs<'de, blst::Signature> for BlsSignature {
            fn deserialize_as<D>(deserializer: D) -> Result<blst::Signature, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes = if deserializer.is_human_readable() {
                    let s = String::deserialize(deserializer)?;
                    base64ct::Base64::decode_vec(&s).map_err(to_custom_error::<'de, D, _>)?
                } else {
                    Bytes::deserialize_as(deserializer)?
                };
                blst::Signature::deserialize(&bytes).map_err(to_custom_error::<'de, D, _>)
            }
        }
    };
} // macro_rules! define_bls_signature

pub mod min_sig {
    use super::*;
    use blst::min_sig as blst;
    define_bls_signature!();
}

pub mod min_pk {
    use super::*;
    use blst::min_pk as blst;
    define_bls_signature!();
}

pub fn keypair_decode_base64<T: KeyPair>(value: &str) -> Result<T, eyre::Report> {
    let bytes =
        base64ct::Base64::decode_vec(value).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
    let sk_length = <<T as KeyPair>::PrivKey as SigningKey>::LENGTH;
    let pk_length = <<T as KeyPair>::PubKey as VerifyingKey>::LENGTH;
    if bytes.len() != pk_length + sk_length {
        return Err(eyre::eyre!("Invalid keypair length"));
    }
    let secret = <T as KeyPair>::PrivKey::from_bytes(&bytes[..sk_length])?;
    // Read only sk bytes for privkey, and derive pubkey from privkey and returns keypair
    Ok(secret.into())
}

pub struct Ed25519Signature;

impl SerializeAs<ed25519_consensus::Signature> for Ed25519Signature {
    fn serialize_as<S>(
        source: &ed25519_consensus::Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // Serialise to Base64 encoded String
            Base64::encode(source.to_bytes()).serialize(serializer)
        } else {
            // Serialise to Bytes
            Bytes::serialize_as(&source.to_bytes(), serializer)
        }
    }
}

impl<'de> DeserializeAs<'de, ed25519_consensus::Signature> for Ed25519Signature {
    fn deserialize_as<D>(deserializer: D) -> Result<ed25519_consensus::Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            base64ct::Base64::decode_vec(&s).map_err(to_custom_error::<'de, D, _>)?
        } else {
            Bytes::deserialize_as(deserializer)?
        };
        ed25519_consensus::Signature::try_from(bytes.as_slice())
            .map_err(to_custom_error::<'de, D, _>)
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// Serialization of objects as bytes.
// - for is_human_readable() serializers it returns base64 encoded bytes.
// - else, it returns the bytes as a fixed size array.
//
// Objects that do not store a cached version of the serialized object should implement
// [ToFromByteArray] and call [serialize_deserialize_with_to_from_byte_array].
// Objects that do store a cached version should implement [ToFromBytes] and call
// [serialize_deserialize_from_encode_decode_base64].
//

// Serde treats arrays larger than 32 as variable length arrays, and then add the length as a prefix.
// Since we want a fixed sized representation, we wrap it in this helper struct and use serde_as.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SerializationHelper<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

pub trait ToFromByteArray<const LENGTH: usize>: Sized {
    const BYTE_LENGTH: usize = LENGTH;
    fn from_byte_array(bytes: &[u8; LENGTH]) -> Result<Self, FastCryptoError>;
    fn to_byte_array(&self) -> [u8; LENGTH];
}

#[macro_export]
macro_rules! serialize_deserialize_with_to_from_byte_array {
    ($type:ty) => {
        impl ::serde::Serialize for $type {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use $crate::encoding::Base64;
                use $crate::encoding::Encoding;
                use $crate::serde_helpers::SerializationHelper;

                let bytes = &self.to_byte_array();
                match serializer.is_human_readable() {
                    true => Base64::encode(bytes).serialize(serializer),
                    false => SerializationHelper::<{ <$type>::BYTE_LENGTH }>(*bytes)
                        .serialize(serializer),
                }
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $type {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use $crate::encoding::Base64;
                use $crate::encoding::Encoding;
                use $crate::serde_helpers::SerializationHelper;

                let bytes = match deserializer.is_human_readable() {
                    true => {
                        let s = String::deserialize(deserializer)?;
                        let decoded = Base64::decode(&s)
                            .map_err(|_| de::Error::custom("Base64 decoding failed"))?;
                        if decoded.len() != { <$type>::BYTE_LENGTH } {
                            return Err(de::Error::custom(format!(
                                "Invalid buffer length {}, expecting {}",
                                decoded.len(),
                                { <$type>::BYTE_LENGTH }
                            )));
                        }
                        let mut bytes = [0u8; { <$type>::BYTE_LENGTH }];
                        bytes.copy_from_slice(&decoded[..{ <$type>::BYTE_LENGTH }]);
                        bytes
                    }
                    false => {
                        let helper: SerializationHelper<{ <$type>::BYTE_LENGTH }> =
                            Deserialize::deserialize(deserializer)?;
                        helper.0
                    }
                };
                Self::from_byte_array(&bytes)
                    .map_err(|_| de::Error::custom("Failed in reconstructing the object"))
            }
        }
    };
}

// TODO: use base64 only when is_human_readable(), else use SerializationHelper.
#[macro_export]
macro_rules! serialize_deserialize_with_to_from_bytes {
    ($type:ty) => {
        impl ::serde::Serialize for $type {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.encode_base64())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $type {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                Self::decode_base64(&s).map_err(::serde::de::Error::custom)
            }
        }
    };
}
