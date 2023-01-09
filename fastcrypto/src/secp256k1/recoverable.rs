// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
#[cfg(test)]
use crate::hash::HashFunction;
#[cfg(test)]
use crate::hash::Keccak256;
use crate::pubkey_bytes::PublicKeyBytes;
use crate::secp256k1::{
    Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
};
use crate::secp256r1::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE};
use crate::serde_helpers::keypair_decode_base64;
use crate::serialize_deserialize_from_encode_decode_base64;
use crate::traits::{
    AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, RecoverableSignature, SigningKey,
    ToFromBytes, VerifyingKey,
};
use derive_more::Display;
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::OnceCell;
use rust_secp256k1::ecdsa::{RecoverableSignature as ExternalRecoverableSignature, RecoveryId};
use rust_secp256k1::hashes::sha256;
use rust_secp256k1::{constants, Message, Secp256k1};
use serde::{de, Deserialize, Serialize};
use signature::{Error, Signature, Signer, Verifier};
use std::borrow::Borrow;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

pub const RECOVERABLE_SIGNATURE_SIZE: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// Secp256k1 ecdsa "public key" for recoverable signatures.
#[readonly::make]
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Display, Hash)]
pub struct Secp256k1RecoverablePublicKey(pub(crate) Secp256k1PublicKey);

/// Binary representation of an instance of [Secp256k1PublicKey].
pub type Secp256k1RecoverablePublicKeyBytes =
    PublicKeyBytes<Secp256k1RecoverablePublicKey, { Secp256k1PublicKey::LENGTH }>;

/// Secp256k1 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256k1RecoverablePrivateKey(pub(crate) Secp256k1PrivateKey);

/// Secp256k1 ecdsa recoverable signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature {
    pub sig: ExternalRecoverableSignature,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
}

/// Secp256k1 public/private key pair.
#[derive(Debug)]
pub struct Secp256k1RecoverableKeyPair {
    pub name: Secp256k1RecoverablePublicKey,
    pub secret: Secp256k1RecoverablePrivateKey,
}

//
// Secp256k1RecoverablePublicKey
//
impl ToFromBytes for Secp256k1RecoverablePublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256k1RecoverablePublicKey(
            Secp256k1PublicKey::from_bytes(bytes)?,
        ))
    }
}

impl AsRef<[u8]> for Secp256k1RecoverablePublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Verifier<Secp256k1RecoverableSignature> for Secp256k1RecoverablePublicKey {
    fn verify(&self, msg: &[u8], signature: &Secp256k1RecoverableSignature) -> Result<(), Error> {
        let recovered = signature.recover(msg).map_err(|_| Error::new())?;
        if recovered != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

impl<'a> From<&'a Secp256k1RecoverablePrivateKey> for Secp256k1RecoverablePublicKey {
    fn from(sk: &'a Secp256k1RecoverablePrivateKey) -> Self {
        Secp256k1RecoverablePublicKey(Secp256k1PublicKey::from(&sk.0))
    }
}

impl From<Secp256k1PublicKey> for Secp256k1RecoverablePublicKey {
    fn from(pk: Secp256k1PublicKey) -> Self {
        Secp256k1RecoverablePublicKey(pk)
    }
}

impl VerifyingKey for Secp256k1RecoverablePublicKey {
    type PrivKey = Secp256k1RecoverablePrivateKey;
    type Sig = Secp256k1RecoverableSignature;
    const LENGTH: usize = PUBLIC_KEY_SIZE;
}

serialize_deserialize_from_encode_decode_base64!(Secp256k1RecoverablePublicKey);

impl Secp256k1RecoverablePublicKey {
    pub fn verify_hashed(
        &self,
        hashed_msg: &[u8],
        signature: &Secp256k1RecoverableSignature,
    ) -> Result<(), signature::Error> {
        let message = Message::from_slice(hashed_msg).map_err(|_| signature::Error::new())?;
        let recovered = signature
            .recover_hashed(message.as_ref())
            .map_err(|_| Error::new())?;
        if recovered != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

impl TryFrom<Secp256k1RecoverablePublicKeyBytes> for Secp256k1RecoverablePublicKey {
    type Error = signature::Error;

    fn try_from(
        bytes: Secp256k1RecoverablePublicKeyBytes,
    ) -> Result<Secp256k1RecoverablePublicKey, Self::Error> {
        Secp256k1RecoverablePublicKey::from_bytes(bytes.as_ref()).map_err(|_| Self::Error::new())
    }
}

impl From<&Secp256k1RecoverablePublicKey> for Secp256k1RecoverablePublicKeyBytes {
    fn from(pk: &Secp256k1RecoverablePublicKey) -> Self {
        Secp256k1RecoverablePublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

//
// Secp256k1RecoverableSignature
//
impl TryFrom<(&Secp256k1Signature, u8)> for Secp256k1RecoverableSignature {
    type Error = FastCryptoError;
    fn try_from((signature, rec_id): (&Secp256k1Signature, u8)) -> Result<Self, FastCryptoError> {
        let recovery_id =
            RecoveryId::from_i32(rec_id as i32).map_err(|_| FastCryptoError::InvalidInput)?;
        let sig = ExternalRecoverableSignature::from_compact(signature.as_ref(), recovery_id)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Secp256k1RecoverableSignature {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

impl Serialize for Secp256k1RecoverableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Secp256k1RecoverableSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        <Secp256k1RecoverableSignature as Signature>::from_bytes(&data)
            .map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl<S: Borrow<Secp256k1RecoverableSignature>> From<S> for Secp256k1Signature {
    fn from(recoverable_signature: S) -> Self {
        Secp256k1Signature {
            sig: recoverable_signature.borrow().sig.to_standard(),
            bytes: OnceCell::new(), // TODO: May use the first 64 bytes of an existing serialization
        }
    }
}

impl Signature for Secp256k1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 65 {
            return Err(signature::Error::new());
        }
        RecoveryId::from_i32(bytes[64] as i32)
            .and_then(|rec_id| {
                ExternalRecoverableSignature::from_compact(&bytes[..64], rec_id).map(|sig| {
                    Secp256k1RecoverableSignature {
                        sig,
                        bytes: OnceCell::new(),
                    }
                })
            })
            .map_err(|_| signature::Error::new())
    }
}

impl Authenticator for Secp256k1RecoverableSignature {
    type PubKey = Secp256k1RecoverablePublicKey;
    type PrivKey = Secp256k1RecoverablePrivateKey;
    const LENGTH: usize = RECOVERABLE_SIGNATURE_SIZE;
}

impl RecoverableSignature for Secp256k1RecoverableSignature {
    type BasePubKey = Secp256k1PublicKey;

    fn recover(&self, msg: &[u8]) -> Result<Secp256k1PublicKey, FastCryptoError> {
        match self
            .sig
            .recover(&Message::from_hashed_data::<sha256::Hash>(msg))
        {
            Ok(pubkey) => Secp256k1PublicKey::from_bytes(pubkey.serialize().as_slice()),
            Err(_) => Err(FastCryptoError::GeneralError),
        }
    }
}

impl Secp256k1RecoverableSignature {
    /// Recover the public key given an already hashed digest.
    pub fn recover_hashed(&self, digest: &[u8]) -> Result<Secp256k1PublicKey, FastCryptoError> {
        let message = Message::from_slice(digest).map_err(|_| FastCryptoError::InvalidInput)?;
        match self.sig.recover(&message) {
            Ok(pubkey) => Secp256k1PublicKey::from_bytes(pubkey.serialize().as_slice()),
            Err(_) => Err(FastCryptoError::GeneralError),
        }
    }

    /// Get the recovery id for this recoverable signature.
    pub fn recovery_id(&self) -> u8 {
        self.as_ref()[RECOVERABLE_SIGNATURE_SIZE - 1]
    }
}

impl AsRef<[u8]> for Secp256k1RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        let mut bytes = [0u8; RECOVERABLE_SIGNATURE_SIZE];
        let (recovery_id, sig) = self.sig.serialize_compact();
        bytes[..64].copy_from_slice(&sig);
        bytes[64] = recovery_id.to_i32() as u8;
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(bytes))
            .expect("OnceCell invariant violated")
    }
}

impl Hash for Secp256k1RecoverableSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl Display for Secp256k1RecoverableSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl Default for Secp256k1RecoverableSignature {
    fn default() -> Self {
        <Secp256k1RecoverableSignature as Signature>::from_bytes(&[1u8; RECOVERABLE_SIGNATURE_SIZE])
            .unwrap()
    }
}

//
// Secp256k1RecoverablePrivateKey
//
impl ToFromBytes for Secp256k1RecoverablePrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256k1RecoverablePrivateKey(
            Secp256k1PrivateKey::from_bytes(bytes)?,
        ))
    }
}

impl AsRef<[u8]> for Secp256k1RecoverablePrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SigningKey for Secp256k1RecoverablePrivateKey {
    type PubKey = Secp256k1RecoverablePublicKey;
    type Sig = Secp256k1RecoverableSignature;
    const LENGTH: usize = PRIVATE_KEY_SIZE;
}

serialize_deserialize_from_encode_decode_base64!(Secp256k1RecoverablePrivateKey);

//
// Secp256k1KeyPair
//
impl Secp256k1KeyPair {
    // This test is used in the proptest because the k256 lib uses keccak256 as hash function.
    #[cfg(test)]
    pub fn try_sign_as_recoverable_keccak256(
        &self,
        msg: &[u8],
    ) -> Result<Secp256k1RecoverableSignature, signature::Error> {
        let secp = Secp256k1::signing_only();

        let message =
            rust_secp256k1::Message::from_slice(Keccak256::digest(msg).digest.as_ref()).unwrap();

        // Creates a 65-bytes signature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Ok(Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
            bytes: OnceCell::new(),
        })
    }
}

impl From<Secp256k1RecoverablePrivateKey> for Secp256k1RecoverableKeyPair {
    fn from(secret: Secp256k1RecoverablePrivateKey) -> Self {
        let name = Secp256k1RecoverablePublicKey::from(&secret);
        Secp256k1RecoverableKeyPair { name, secret }
    }
}

impl Signer<Secp256k1RecoverableSignature> for Secp256k1RecoverableKeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<Secp256k1RecoverableSignature, Error> {
        let secp = Secp256k1::signing_only();

        let message = Message::from_hashed_data::<sha256::Hash>(msg);

        // Creates a 65-bytes signature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Ok(Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.0.privkey),
            bytes: OnceCell::new(),
        })
    }
}

impl EncodeDecodeBase64 for Secp256k1RecoverableKeyPair {
    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(self.secret.as_ref());
        bytes.extend_from_slice(self.name.as_ref());
        Base64::encode(&bytes[..])
    }

    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        keypair_decode_base64(value)
    }
}

impl FromStr for Secp256k1RecoverableKeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl From<Secp256k1KeyPair> for Secp256k1RecoverableKeyPair {
    fn from(kp: Secp256k1KeyPair) -> Self {
        Secp256k1RecoverableKeyPair {
            name: Secp256k1RecoverablePublicKey(kp.name.clone()),
            secret: Secp256k1RecoverablePrivateKey::from_bytes(kp.secret.as_ref()).unwrap(),
        }
    }
}

impl KeyPair for Secp256k1RecoverableKeyPair {
    type PubKey = Secp256k1RecoverablePublicKey;
    type PrivKey = Secp256k1RecoverablePrivateKey;
    type Sig = Secp256k1RecoverableSignature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        self.secret
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256k1RecoverableKeyPair {
            name: self.name.clone(),
            secret: Secp256k1RecoverablePrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let kp = Secp256k1KeyPair::generate(rng);
        Secp256k1RecoverableKeyPair::from(kp)
    }
}
