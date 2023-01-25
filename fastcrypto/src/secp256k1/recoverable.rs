// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ECDSA signature scheme](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) over the [secp256k1 curve](http://www.secg.org/sec2-v2.pdf).
//!
//! Messages can be signed and the public key can be recovered from the signature:
//! # Example
//! ```rust
//! # use fastcrypto::secp256k1::recoverable::*;
//! # use fastcrypto::{traits::{KeyPair, Signer}, Verifier};
//! use rand::thread_rng;
//! let kp = Secp256k1RecoverableKeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert_eq!(signature.recover(message).unwrap(), kp.name);
//! ```

use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    serialize_deserialize_with_to_from_bytes,
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
pub struct Secp256k1RecoverablePublicKey {
    pub pubkey: PublicKey,
    pub bytes: OnceCell<[u8; constants::PUBLIC_KEY_SIZE]>,
}

/// Secp256k1 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay, PartialEq, Eq)]
pub struct Secp256k1RecoverablePrivateKey {
    pub privkey: SecretKey,
    pub bytes: OnceCell<[u8; constants::SECRET_KEY_SIZE]>,
}

/// Length of a compact signature followed by one extra byte for recovery id, used to recover the public key from a signature.
pub const RECOVERABLE_SIGNATURE_SIZE: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// The key pair bytes length used by helper is the same as the private key length. This is because only private key is serialized.
pub const SECP_256_K_1_KEY_PAIR_BYTE_LENGTH: usize = constants::SECRET_KEY_SIZE;
/// Secp256k1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature {
    pub sig: RecoverableSignature,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
}

impl std::hash::Hash for Secp256k1RecoverablePublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialOrd for Secp256k1RecoverablePublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for Secp256k1RecoverablePublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl PartialEq for Secp256k1RecoverablePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl Eq for Secp256k1RecoverablePublicKey {}

impl VerifyingKey for Secp256k1RecoverablePublicKey {
    type PrivKey = Secp256k1RecoverablePrivateKey;
    type Sig = Secp256k1RecoverableSignature;
    const LENGTH: usize = constants::PUBLIC_KEY_SIZE;
}

impl Verifier<Secp256k1RecoverableSignature> for Secp256k1RecoverablePublicKey {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Secp256k1RecoverableSignature,
    ) -> Result<(), signature::Error> {
        let message = hash_message(msg);
        self.verify_hashed(message.as_ref(), signature)
    }
}

impl Secp256k1RecoverablePublicKey {
    pub(crate) fn verify_hashed(
        &self,
        hashed_msg: &[u8],
        signature: &Secp256k1RecoverableSignature,
    ) -> Result<(), signature::Error> {
        // If pubkey recovered from signature matches original pubkey, verifies signature.
        // To ensure non-malleability of v, signature.verify_ecdsa() is not used since it will verify using only [r, s] without considering v.
        match Message::from_slice(hashed_msg) {
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

impl AsRef<[u8]> for Secp256k1RecoverablePublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.pubkey.serialize()))
            .expect("OnceCell invariant violated")
    }
}

impl ToFromBytes for Secp256k1RecoverablePublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match PublicKey::from_slice(bytes) {
            Ok(pubkey) => Ok(Secp256k1RecoverablePublicKey {
                pubkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl Default for Secp256k1RecoverablePublicKey {
    fn default() -> Self {
        // Return the generator for k256 (https://www.secg.org/sec2-v2.pdf)
        Secp256k1RecoverablePublicKey {
            pubkey: PublicKey::from_slice(hex::decode("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap().as_slice()).unwrap(),
            bytes: OnceCell::new(),
        }
    }
}

impl Display for Secp256k1RecoverablePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
serialize_deserialize_with_to_from_bytes!(Secp256k1RecoverablePublicKey);

impl<'a> From<&'a Secp256k1RecoverablePrivateKey> for Secp256k1RecoverablePublicKey {
    fn from(secret: &'a Secp256k1RecoverablePrivateKey) -> Self {
        Secp256k1RecoverablePublicKey {
            pubkey: secret.privkey.public_key(&SECP256K1),
            bytes: OnceCell::new(),
        }
    }
}

impl SigningKey for Secp256k1RecoverablePrivateKey {
    type PubKey = Secp256k1RecoverablePublicKey;
    type Sig = Secp256k1RecoverableSignature;
    const LENGTH: usize = constants::SECRET_KEY_SIZE;
}

impl ToFromBytes for Secp256k1RecoverablePrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match SecretKey::from_slice(bytes) {
            Ok(privkey) => Ok(Secp256k1RecoverablePrivateKey {
                privkey,
                bytes: OnceCell::new(),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
serialize_deserialize_with_to_from_bytes!(Secp256k1RecoverablePrivateKey);

impl AsRef<[u8]> for Secp256k1RecoverablePrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.privkey.secret_bytes()))
            .expect("OnceCell invariant violated")
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

impl Signature for Secp256k1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        if bytes.len() != 65 {
            return Err(signature::Error::new());
        }
        RecoveryId::from_i32(bytes[64] as i32)
            .and_then(|rec_id| {
                RecoverableSignature::from_compact(&bytes[..64], rec_id).map(|sig| {
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

impl std::hash::Hash for Secp256k1RecoverableSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for Secp256k1RecoverableSignature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Secp256k1RecoverableSignature {}

impl Display for Secp256k1RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl Default for Secp256k1RecoverableSignature {
    fn default() -> Self {
        <Secp256k1RecoverableSignature as Signature>::from_bytes(&[1u8; RECOVERABLE_SIGNATURE_SIZE])
            .unwrap()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Secp256k1RecoverableKeyPair {
    pub name: Secp256k1RecoverablePublicKey,
    pub secret: Secp256k1RecoverablePrivateKey,
}

/// The bytes form of the keypair always only contain the private key bytes
impl ToFromBytes for Secp256k1RecoverableKeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Secp256k1RecoverablePrivateKey::from_bytes(bytes).map(|secret| secret.into())
    }
}

serialize_deserialize_with_to_from_bytes!(Secp256k1RecoverableKeyPair);

impl AsRef<[u8]> for Secp256k1RecoverableKeyPair {
    fn as_ref(&self) -> &[u8] {
        self.secret.as_ref()
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
        Secp256k1RecoverablePrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256k1RecoverableKeyPair {
            name: self.name.clone(),
            secret: Secp256k1RecoverablePrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let (privkey, pubkey) = SECP256K1.generate_keypair(rng);

        Secp256k1RecoverableKeyPair {
            name: Secp256k1RecoverablePublicKey {
                pubkey,
                bytes: OnceCell::new(),
            },
            secret: Secp256k1RecoverablePrivateKey {
                privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl FromStr for Secp256k1RecoverableKeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

/// Hash a message using the default hash function.
fn hash_message(msg: &[u8]) -> Message {
    // k256 defaults to keccak256 as digest to hash message for sign/verify, thus use this hash function to match in proptest.
    #[cfg(test)]
    let message =
        Message::from_slice(<sha3::Keccak256 as digest::Digest>::digest(msg).as_slice()).unwrap();

    // Default hash function is sha256
    #[cfg(not(test))]
    let message = Message::from_hashed_data::<rust_secp256k1::hashes::sha256::Hash>(msg);

    message
}

impl Signer<Secp256k1RecoverableSignature> for Secp256k1RecoverableKeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<Secp256k1RecoverableSignature, signature::Error> {
        let secp = Secp256k1::signing_only();

        let message = hash_message(msg);

        // Creates a 65-bytes sigature of shape [r, s, v] where v can be 0 or 1.
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

impl Secp256k1RecoverableSignature {
    /// Recover public key from signature.
    pub fn recover(&self, msg: &[u8]) -> Result<Secp256k1RecoverablePublicKey, FastCryptoError> {
        let message = hash_message(msg);
        self.recover_hashed(message.as_ref())
    }

    /// Recover public key from signature and an already hashed message.
    pub(crate) fn recover_hashed(
        &self,
        hashed_msg: &[u8],
    ) -> Result<Secp256k1RecoverablePublicKey, FastCryptoError> {
        match Message::from_slice(hashed_msg) {
            Ok(message) => match self.sig.recover(&message) {
                Ok(pubkey) => {
                    Secp256k1RecoverablePublicKey::from_bytes(pubkey.serialize().as_slice())
                }
                Err(_) => Err(FastCryptoError::GeneralError),
            },
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl zeroize::Zeroize for Secp256k1RecoverablePrivateKey {
    fn zeroize(&mut self) {
        self.privkey = rust_secp256k1::ONE_KEY;
        self.bytes.take().zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Secp256k1RecoverablePrivateKey {}

impl Drop for Secp256k1RecoverablePrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::Zeroize for Secp256k1RecoverableKeyPair {
    fn zeroize(&mut self) {
        self.secret.zeroize()
    }
}

impl zeroize::ZeroizeOnDrop for Secp256k1RecoverableKeyPair {}

impl Drop for Secp256k1RecoverableKeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
