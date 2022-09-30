// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::FastCryptoError, hash::HashFunction, pubkey_bytes::PublicKeyBytes,
    serde_helpers::keypair_decode_base64,
};
use base64ct::{Base64, Encoding};
use eyre::eyre;
use rand::Rng;
use serde::{
    de::{self},
    Deserialize, Serialize,
};
use serde_with::serde_as;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

use signature::{Signature, Signer, Verifier};

use crate::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
    VerifyingKey,
};

///
/// Define Structs
///

const PRIVATE_KEY_LENGTH: usize = 16;
const PUBLIC_KEY_LENGTH: usize = 16;
const SIGNATURE_LENGTH: usize = 1;

#[readonly::make]
#[derive(Default, Debug, Clone)]
pub struct ZeroPublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

pub type ZeroPublicKeyBytes = PublicKeyBytes<ZeroPublicKey, { PUBLIC_KEY_LENGTH }>;

#[derive(Default, Debug)]
pub struct ZeroPrivateKey(pub [u8; PRIVATE_KEY_LENGTH]);

// There is a strong requirement for this specific impl. in Fab benchmarks
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")] // necessary so as not to deser under a != type
pub struct ZeroKeyPair {
    name: ZeroPublicKey,
    secret: ZeroPrivateKey,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ZeroSignature(pub [u8; SIGNATURE_LENGTH]);

#[serde_as]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ZeroAggregateSignature(pub Vec<ZeroSignature>);

///
/// Implement SigningKey
///

impl AsRef<[u8]> for ZeroPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToFromBytes for ZeroPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes_fixed: [u8; PUBLIC_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InputLengthWrong(PUBLIC_KEY_LENGTH))?;
        Ok(Self(bytes_fixed))
    }
}

impl std::hash::Hash for ZeroPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for ZeroPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ZeroPublicKey {}

impl PartialOrd for ZeroPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}
impl Ord for ZeroPublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl Display for ZeroPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for ZeroPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for ZeroPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Verifier<ZeroSignature> for ZeroPublicKey {
    fn verify(&self, _msg: &[u8], signature: &ZeroSignature) -> Result<(), signature::Error> {
        // These signatures are valid if the first byte is zero and invalid otherwise. This allows for negative tests.
        if signature.0[0] == 0 {
            return Ok(());
        }
        Err(signature::Error::new())
    }
}

impl<'a> From<&'a ZeroPrivateKey> for ZeroPublicKey {
    fn from(secret: &'a ZeroPrivateKey) -> Self {
        let result = crate::hash::Sha256::digest(secret.0.as_ref());
        let bytes: [u8; PUBLIC_KEY_LENGTH] = result.as_ref()[0..PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|_| FastCryptoError::GeneralError)
            .unwrap();
        ZeroPublicKey(bytes)
    }
}

impl VerifyingKey for ZeroPublicKey {
    type PrivKey = ZeroPrivateKey;
    type Sig = ZeroSignature;

    const LENGTH: usize = PUBLIC_KEY_LENGTH;

    fn verify_batch_empty_fail(
        _msg: &[u8],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report> {
        if pks
            .iter()
            .zip(sigs.iter())
            .map(|(pk, sig)| pk.verify(_msg, sig))
            .all(|v| v.is_ok())
        {
            return Ok(());
        }
        Err(eyre!("Verification failed!"))
    }
}

///
/// Implement Authenticator
///

impl AsRef<[u8]> for ZeroSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::hash::Hash for ZeroSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for ZeroSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ZeroSignature {}

impl Signature for ZeroSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        let bytes_fixed: [u8; SIGNATURE_LENGTH] =
            bytes.try_into().map_err(|_| signature::Error::new())?;
        Ok(Self(bytes_fixed))
    }
}

impl Display for ZeroSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

impl Authenticator for ZeroSignature {
    type PubKey = ZeroPublicKey;
    type PrivKey = ZeroPrivateKey;
    const LENGTH: usize = 0;
}

///
/// Implement SigningKey
///

impl AsRef<[u8]> for ZeroPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToFromBytes for ZeroPrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes: [u8; PRIVATE_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InputLengthWrong(PRIVATE_KEY_LENGTH))?;
        Ok(ZeroPrivateKey(bytes))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for ZeroPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for ZeroPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl SigningKey for ZeroPrivateKey {
    type PubKey = ZeroPublicKey;
    type Sig = ZeroSignature;
    const LENGTH: usize = PRIVATE_KEY_LENGTH;
}

// Valid signatures begin with a zero byte and have size SIGNATURE_LENGTH. By default we just create a signature with all zeros.
impl Signer<ZeroSignature> for ZeroPrivateKey {
    fn try_sign(&self, _msg: &[u8]) -> Result<ZeroSignature, signature::Error> {
        Ok(ZeroSignature([0; SIGNATURE_LENGTH]))
    }
}

///
/// Implement KeyPair
///

impl From<ZeroPrivateKey> for ZeroKeyPair {
    fn from(secret: ZeroPrivateKey) -> Self {
        let pk: ZeroPublicKey = (&secret).into();
        ZeroKeyPair { name: pk, secret }
    }
}

impl EncodeDecodeBase64 for ZeroKeyPair {
    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        keypair_decode_base64(value)
    }

    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(self.secret.as_ref());
        bytes.extend_from_slice(self.name.as_ref());
        base64ct::Base64::encode_string(&bytes[..])
    }
}

impl KeyPair for ZeroKeyPair {
    type PubKey = ZeroPublicKey;
    type PrivKey = ZeroPrivateKey;
    type Sig = ZeroSignature;

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        ZeroKeyPair {
            name: ZeroPublicKey(self.name.0),
            secret: ZeroPrivateKey(self.secret.0),
        }
    }

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        self.secret
    }

    fn generate<R: rand::CryptoRng + rand::RngCore>(_rng: &mut R) -> Self {
        let sk_bytes: [u8; PUBLIC_KEY_LENGTH] = rand::thread_rng().gen();
        let sk = ZeroPrivateKey(sk_bytes);
        sk.into()
    }
}

impl Signer<ZeroSignature> for ZeroKeyPair {
    fn try_sign(&self, _msg: &[u8]) -> Result<ZeroSignature, signature::Error> {
        Ok(ZeroSignature([0; SIGNATURE_LENGTH]))
    }
}

impl FromStr for ZeroKeyPair {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|_| FastCryptoError::GeneralError)?;
        Ok(kp)
    }
}

///
/// Implement AggregateAuthenticator
///

// Don't try to use this externally
impl AsRef<[u8]> for ZeroAggregateSignature {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl Display for ZeroAggregateSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

// see [#34](https://github.com/MystenLabs/narwhal/issues/34)

impl AggregateAuthenticator for ZeroAggregateSignature {
    type PrivKey = ZeroPrivateKey;
    type PubKey = ZeroPublicKey;
    type Sig = ZeroSignature;

    /// Parse a key from its byte representation
    fn aggregate(signatures: Vec<Self::Sig>) -> Result<Self, FastCryptoError> {
        Ok(ZeroAggregateSignature(signatures))
    }

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), FastCryptoError> {
        self.0.push(signature);
        Ok(())
    }

    fn add_aggregate(&mut self, signatures: Self) -> Result<(), FastCryptoError> {
        self.0.extend(signatures.0);
        Ok(())
    }

    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        msg: &[u8],
    ) -> Result<(), FastCryptoError> {
        if pks
            .iter()
            .zip(self.0.iter())
            .map(|(pk, sig)| pk.verify(msg, sig))
            .all(|v| v.is_ok())
        {
            return Ok(());
        }
        Err(FastCryptoError::GeneralError)
    }

    fn batch_verify<'a>(
        sigs: &[&Self],
        pks: Vec<impl ExactSizeIterator<Item = &'a Self::PubKey>>,
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> {
        if sigs.len() != pks.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let mut pks_iter = pks.into_iter();

        for (msg, sig) in messages.iter().zip(sigs.iter().map(|sig| &sig.0)) {
            for (j, key) in pks_iter.next().unwrap().enumerate() {
                if key.verify(msg, &sig[j]).is_err() {
                    return Err(FastCryptoError::GeneralError);
                }
            }
        }
        Ok(())
    }
}

///
/// Implement VerifyingKeyBytes
///

impl TryFrom<ZeroPublicKeyBytes> for ZeroPublicKey {
    type Error = FastCryptoError;

    fn try_from(bytes: ZeroPublicKeyBytes) -> Result<ZeroPublicKey, Self::Error> {
        ZeroPublicKey::from_bytes(bytes.as_ref())
    }
}

impl From<&ZeroPublicKey> for ZeroPublicKeyBytes {
    fn from(pk: &ZeroPublicKey) -> ZeroPublicKeyBytes {
        ZeroPublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}
