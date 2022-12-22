// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding as _;
use serde::{
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
};
use serde_with::{Bytes, DeserializeAs, SerializeAs};
use std::fmt::Debug;

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
