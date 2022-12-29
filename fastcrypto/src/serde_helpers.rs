// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding as _;
use serde::{
    de,
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
};
use serde_with::{serde_as, Bytes, DeserializeAs, SerializeAs};
use std::fmt::Debug;
use schemars::JsonSchema;

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

///
/// Serialization of internal types.
///
/// Every type's serialization should work as following:
/// - Return base64 encoded bytes for is_human_readable() serializers.
/// - Else, return the bytes as a fixed size array. This should be the canonical representation of
///   the object (e.g., as defined in RFCs).
///
/// Types that do store a *cached* version of the serialized object should implement [ToFromBytes]
/// and call [serialize_deserialize_with_to_from_bytes].
///
/// Types that do *not* store a cached version of the serialized object should implement
/// [ToFromByteArray] and call [serialize_deserialize_with_to_from_byte_array].
///
/// Note that in theory internal types should not be exposed via APIs and thus never be serialized
/// with is_human_readable(). Instead, external types should be used (see
/// [generate_bytes_representation]).
///

// Serde treats arrays larger than 32 as variable length arrays, and adds the length as a prefix.
// Since we want a fixed size representation, we wrap it in this helper struct and use serde_as.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SerializationHelper<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

pub trait ToFromByteArray<const LENGTH: usize>: Sized {
    const BYTE_LENGTH: usize = LENGTH;
    fn from_byte_array(bytes: &[u8; LENGTH]) -> Result<Self, FastCryptoError>;
    fn to_byte_array(&self) -> [u8; LENGTH];
}

/// Macro for generating Serialize/Deserialize for a type that implements [ToFromByteArray].
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
                        decoded.try_into().unwrap()
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
/// Macro for generating Serialize/Deserialize for a type that implements [ToFromBytes].
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

///
/// External types.
///
/// [BytesRepresentation] is a basic wrapper for storing bincode serialized objects.
///
/// To be used in external interfaces instead of the internal types.
/// - Derive by calling [generate_bytes_representation].
/// - Uses Base64 when serialized with a human readable serializer, and raw bytes otherwise.
///
/// Note that in theory external types should not be stored and only be serialized with
/// is_human_readable(). For storage and usage, internal types should be used (see above).
///


// schemars is used for guiding JsonSchema.
#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct BytesRepresentation<const N: usize>(#[schemars(with = "Base64")] pub [u8; N]);

/// Macro for generating a new alias for BytesRepresentation with the given $length, and From
/// functions for both directions.
/// - $type - the source type.
/// - $length - byte length of the source type when serialized using bincode.
/// - $new_type - the alias name.
///
// TODO: Can we deduce $new_type from $type?
#[macro_export]
macro_rules! generate_bytes_representation {
    ($type:ty, $length:tt, $new_type:ident) => {

        pub type $new_type = BytesRepresentation<$length>;

        impl TryFrom<&BytesRepresentation<$length>> for $type {
            type Error = FastCryptoError;

            fn try_from(value: &BytesRepresentation<$length>) -> Result<Self, Self::Error> {
                let o: $type =
                    bincode::deserialize(&value.0).map_err(|_| FastCryptoError::InvalidInput)?;
                Ok(o)
            }
        }

        impl From<&$type> for BytesRepresentation<$length> {
            fn from(value: &$type) -> Self {
                let buffer = bincode::serialize(value).unwrap();
                let buffer_len = buffer.len();
                Self(
                    // The following error should happen only in case the object was defined with
                    // the wrong length, thus cannot be handled in runtime.
                    buffer.try_into().expect(
                        format!(
                            "BytesRepresentation of length {} defined with invalid serialized length {}",
                            $length, buffer_len
                        )
                        .as_ref(),
                    ),
                )
            }
        }
    };
}

impl<const N: usize> Serialize for BytesRepresentation<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match serializer.is_human_readable() {
            true => Base64::encode(self.0).serialize(serializer),
            false => SerializationHelper::<N>(self.0).serialize(serializer),
        }
    }
}

impl<'de, const N: usize> Deserialize<'de> for BytesRepresentation<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let bytes: [u8; N] = match deserializer.is_human_readable() {
            true => {
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
                decoded.try_into().unwrap()
            }
            false => {
                let helper: SerializationHelper<N> = Deserialize::deserialize(deserializer)?;
                helper.0
            }
        };
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::bls12381::{G1Element, G1ElementAsBytes, G1_ELEMENT_BYTE_LENGTH};
    use crate::groups::GroupElement;

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Dummy<T> {
        key: T,
    }

    #[test]
    fn test_serializations() {
        let g1 = G1Element::generator();
        let b64 = G1ElementAsBytes::from(&g1);
        let d1 = Dummy::<G1ElementAsBytes> { key: b64 };
        // Test that we are not adding extra fields.
        assert_eq!(
            serde_json::to_string(&d1).unwrap(),
            r#"{"key":"l/HTpzGX15QmlWOMT6msD8NojE+XdLkFoU46PxcbrFhsVeg/+Xoa7/s68ArbIsa7"}"#
        );
        // Test that we don't add extra bytes on top of the actual serialized data.
        let ser = bincode::serialize(&d1).unwrap();
        assert_eq!(G1_ELEMENT_BYTE_LENGTH, ser.len());
        // Check we can go back correctly.
        let d2: Dummy<G1ElementAsBytes> = bincode::deserialize(&ser).unwrap();
        let g2 = G1Element::try_from(&d2.key).unwrap();
        assert_eq!(g1, g2);
    }
}
