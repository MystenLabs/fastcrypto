// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [EDDSA signature scheme](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) over the [secp256k1 curve](http://www.secg.org/sec2-v2.pdf).
//!
//! Messages can be signed and the signature can be verified again:
//! # Example
//! ```rust
//! # use fastcrypto::secp256k1::*;
//! # use fastcrypto::{traits::{KeyPair, Signer}, Verifier};
//! use rand::thread_rng;
//! let kp = Secp256k1KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert!(kp.public().verify(message, &signature).is_ok());
//! ```

use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    pubkey_bytes::PublicKeyBytes,
    serde_helpers::keypair_decode_base64,
    traits::{
        AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
        VerifyingKey,
    },
};
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::{Lazy, OnceCell};
use rust_secp256k1::{
    constants,
    ecdsa::{RecoverableSignature, RecoveryId},
    All, Message, PublicKey, Secp256k1, SecretKey,
};
use serde::{de, Deserialize, Serialize};
use signature::{Signature, Signer, Verifier};
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};
use zeroize::Zeroize;

pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(rust_secp256k1::Secp256k1::new);

/// Secp256k1 public key.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1PublicKey {
    pub pubkey: PublicKey,
    pub bytes: OnceCell<[u8; constants::PUBLIC_KEY_SIZE]>,
}

/// Binary representation of an instance of [Secp256k1PublicKey].
pub type Secp256k1PublicKeyBytes =
    PublicKeyBytes<Secp256k1PublicKey, { Secp256k1PublicKey::LENGTH }>;

/// Secp256k1 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256k1PrivateKey {
    pub privkey: SecretKey,
    pub bytes: OnceCell<[u8; constants::SECRET_KEY_SIZE]>,
}

/// Length of a compact signature followed by one extra byte for recovery id, used to recover the public key from a signature.
pub const RECOVERABLE_SIGNATURE_SIZE: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// Secp256k1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1Signature {
    pub sig: RecoverableSignature,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
}

impl std::hash::Hash for Secp256k1PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialOrd for Secp256k1PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for Secp256k1PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl PartialEq for Secp256k1PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl Eq for Secp256k1PublicKey {}

impl VerifyingKey for Secp256k1PublicKey {
    type PrivKey = Secp256k1PrivateKey;
    type Sig = Secp256k1Signature;
    const LENGTH: usize = constants::PUBLIC_KEY_SIZE;
}

impl Verifier<Secp256k1Signature> for Secp256k1PublicKey {
    fn verify(&self, msg: &[u8], signature: &Secp256k1Signature) -> Result<(), signature::Error> {
        // k256 defaults to keccak256 as digest to hash message for sign/verify, thus use this hash function to match in proptest.
        #[cfg(test)]
        let message =
            Message::from_slice(<sha3::Keccak256 as digest::Digest>::digest(msg).as_slice())
                .unwrap();

        #[cfg(not(test))]
        let message = Message::from_hashed_data::<rust_secp256k1::hashes::sha256::Hash>(msg);

        // If pubkey recovered from signature matches original pubkey, verifies signature.
        // To ensure non-malleability of v, signature.verify_ecdsa() is not used since it will verify using only [r, s] without considering v.
        match signature.sig.recover(&message) {
            Ok(recovered_key) if self.as_bytes() == recovered_key.serialize().as_slice() => Ok(()),
            _ => Err(signature::Error::new()),
        }
    }
}

impl Secp256k1PublicKey {
    pub fn verify_hashed(
        &self,
        hased_msg: &[u8],
        signature: &Secp256k1Signature,
    ) -> Result<(), signature::Error> {
        match Message::from_slice(hased_msg) {
            Ok(message) => match signature.sig.recover(&message) {
                Ok(recovered_key) if self.as_bytes() == recovered_key.serialize().as_slice() => {
                    Ok(())
                }
                _ => Err(signature::Error::new()),
            },
            _ => Err(signature::Error::new()),
        }
    }

    /// util function to parse wycheproof test key from DER format.
    #[cfg(test)]
    pub fn from_uncompressed(uncompressed: &[u8]) -> Self {
        let pubkey = PublicKey::from_slice(uncompressed).unwrap();
        Self {
            pubkey,
            bytes: OnceCell::new(),
        }
    }
}

impl AsRef<[u8]> for Secp256k1PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.pubkey.serialize()))
            .expect("OnceCell invariant violated")
    }
}

impl ToFromBytes for Secp256k1PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match PublicKey::from_slice(bytes) {
            Ok(pubkey) => Ok(Secp256k1PublicKey {
                pubkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl Default for Secp256k1PublicKey {
    fn default() -> Self {
        Secp256k1PublicKey::from_bytes(&[0u8; constants::PUBLIC_KEY_SIZE]).unwrap()
    }
}

impl Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for Secp256k1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for Secp256k1PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl<'a> From<&'a Secp256k1PrivateKey> for Secp256k1PublicKey {
    fn from(secret: &'a Secp256k1PrivateKey) -> Self {
        Secp256k1PublicKey {
            pubkey: secret.privkey.public_key(&SECP256K1),
            bytes: OnceCell::new(),
        }
    }
}

impl SigningKey for Secp256k1PrivateKey {
    type PubKey = Secp256k1PublicKey;
    type Sig = Secp256k1Signature;
    const LENGTH: usize = constants::SECRET_KEY_SIZE;
}

impl ToFromBytes for Secp256k1PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match SecretKey::from_slice(bytes) {
            Ok(privkey) => Ok(Secp256k1PrivateKey {
                privkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for Secp256k1PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for Secp256k1PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for Secp256k1PrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.privkey.secret_bytes()))
            .expect("OnceCell invariant violated")
    }
}

impl Serialize for Secp256k1Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Secp256k1Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        <Secp256k1Signature as Signature>::from_bytes(&data)
            .map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl Signature for Secp256k1Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        if bytes.len() != 65 {
            return Err(signature::Error::new());
        }
        RecoveryId::from_i32(bytes[64] as i32)
            .and_then(|rec_id| {
                RecoverableSignature::from_compact(&bytes[..64], rec_id).map(|sig| {
                    Secp256k1Signature {
                        sig,
                        bytes: OnceCell::new(),
                    }
                })
            })
            .map_err(|_| signature::Error::new())
    }
}

impl Authenticator for Secp256k1Signature {
    type PubKey = Secp256k1PublicKey;
    type PrivKey = Secp256k1PrivateKey;
    const LENGTH: usize = RECOVERABLE_SIGNATURE_SIZE;
}

impl AsRef<[u8]> for Secp256k1Signature {
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

impl std::hash::Hash for Secp256k1Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for Secp256k1Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for Secp256k1Signature {}

impl Display for Secp256k1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl Default for Secp256k1Signature {
    fn default() -> Self {
        <Secp256k1Signature as Signature>::from_bytes(&[1u8; RECOVERABLE_SIGNATURE_SIZE]).unwrap()
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
/// Secp256k1 public/private key pair.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")] // necessary so as not to deser under a != type
pub struct Secp256k1KeyPair {
    pub name: Secp256k1PublicKey,
    pub secret: Secp256k1PrivateKey,
}

impl EncodeDecodeBase64 for Secp256k1KeyPair {
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

impl KeyPair for Secp256k1KeyPair {
    type PubKey = Secp256k1PublicKey;
    type PrivKey = Secp256k1PrivateKey;
    type Sig = Secp256k1Signature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        Secp256k1PrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256k1KeyPair {
            name: self.name.clone(),
            secret: Secp256k1PrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let (privkey, pubkey) = SECP256K1.generate_keypair(rng);

        Secp256k1KeyPair {
            name: Secp256k1PublicKey {
                pubkey,
                bytes: OnceCell::new(),
            },
            secret: Secp256k1PrivateKey {
                privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl FromStr for Secp256k1KeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl Signer<Secp256k1Signature> for Secp256k1KeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<Secp256k1Signature, signature::Error> {
        let secp = Secp256k1::signing_only();
        #[cfg(test)]
        let message =
            Message::from_slice(<sha3::Keccak256 as digest::Digest>::digest(msg).as_slice())
                .unwrap();

        #[cfg(not(test))]
        let message = Message::from_hashed_data::<rust_secp256k1::hashes::sha256::Hash>(msg);

        // Creates a 65-bytes sigature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Ok(Secp256k1Signature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
            bytes: OnceCell::new(),
        })
    }
}

impl TryFrom<Secp256k1PublicKeyBytes> for Secp256k1PublicKey {
    type Error = signature::Error;

    fn try_from(bytes: Secp256k1PublicKeyBytes) -> Result<Secp256k1PublicKey, Self::Error> {
        Secp256k1PublicKey::from_bytes(bytes.as_ref()).map_err(|_| Self::Error::new())
    }
}

impl From<&Secp256k1PublicKey> for Secp256k1PublicKeyBytes {
    fn from(pk: &Secp256k1PublicKey) -> Self {
        Secp256k1PublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

impl From<Secp256k1PrivateKey> for Secp256k1KeyPair {
    fn from(secret: Secp256k1PrivateKey) -> Self {
        let name = Secp256k1PublicKey::from(&secret);
        Secp256k1KeyPair { name, secret }
    }
}

impl Secp256k1Signature {
    /// Recover public key from signature
    pub fn recover(&self, hashed_msg: &[u8]) -> Result<Secp256k1PublicKey, FastCryptoError> {
        match Message::from_slice(hashed_msg) {
            Ok(message) => match self.sig.recover(&message) {
                Ok(pubkey) => Secp256k1PublicKey::from_bytes(pubkey.serialize().as_slice()),
                Err(_) => Err(FastCryptoError::GeneralError),
            },
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl zeroize::Zeroize for Secp256k1PrivateKey {
    fn zeroize(&mut self) {
        self.privkey = rust_secp256k1::ONE_KEY;
        self.bytes.take().zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Secp256k1PrivateKey {}

impl Drop for Secp256k1PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::Zeroize for Secp256k1KeyPair {
    fn zeroize(&mut self) {
        self.secret.zeroize()
    }
}

impl zeroize::ZeroizeOnDrop for Secp256k1KeyPair {}

impl Drop for Secp256k1KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
