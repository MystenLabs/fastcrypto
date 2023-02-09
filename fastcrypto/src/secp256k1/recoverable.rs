// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ECDSA signature scheme](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) over the [secp256k1 curve](http://www.secg.org/sec2-v2.pdf).
//!
//! Messages can be signed and the public key can be recovered from the signature:
//! # Example
//! ```rust
//! # use fastcrypto::secp256k1::recoverable::*;
//! # use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
//! # use fastcrypto::secp256k1::Secp256k1KeyPair;
//! # use fastcrypto::traits::{RecoverableSignature, RecoverableSigner};
//! use rand::thread_rng;
//! let kp = Secp256k1KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign_recoverable(message);
//! assert_eq!(&signature.recover(message).unwrap(), kp.public());
//! ```

use crate::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use crate::traits::{RecoverableSigner, VerifyRecoverable};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    serialize_deserialize_with_to_from_bytes, traits,
    traits::{EncodeDecodeBase64, ToFromBytes},
};
use once_cell::sync::{Lazy, OnceCell};
use rust_secp256k1::{
    constants,
    ecdsa::{RecoverableSignature, RecoveryId},
    All, Message, Secp256k1,
};
use std::fmt::{self, Debug, Display};

pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(rust_secp256k1::Secp256k1::new);

/// Length of a compact signature followed by one extra byte for recovery id, used to recover the public key from a signature.
pub const SECP256K1_RECOVERABLE_SIGNATURE_SIZE: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// Secp256k1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature {
    pub sig: RecoverableSignature,
    pub bytes: OnceCell<[u8; SECP256K1_RECOVERABLE_SIGNATURE_SIZE]>,
}

serialize_deserialize_with_to_from_bytes!(
    Secp256k1RecoverableSignature,
    SECP256K1_RECOVERABLE_SIGNATURE_SIZE
);

impl ToFromBytes for Secp256k1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != SECP256K1_RECOVERABLE_SIGNATURE_SIZE {
            return Err(FastCryptoError::InputLengthWrong(
                SECP256K1_RECOVERABLE_SIGNATURE_SIZE,
            ));
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
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl AsRef<[u8]> for Secp256k1RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        let mut bytes = [0u8; SECP256K1_RECOVERABLE_SIGNATURE_SIZE];
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

impl Secp256k1RecoverableSignature {
    /// Convert a non-recoverable signature into a recoverable signature.
    pub fn try_from_nonrecoverable(
        signature: &Secp256k1Signature,
        pk: &Secp256k1PublicKey,
        message: &[u8],
    ) -> Result<Self, FastCryptoError> {
        // Secp256k1Signature::as_bytes is guaranteed to return SECP256K1_SIGNATURE_LENGTH = SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1 bytes.
        let mut recoverable_signature_bytes = [0u8; SECP256K1_RECOVERABLE_SIGNATURE_SIZE];
        recoverable_signature_bytes[0..SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1]
            .copy_from_slice(signature.as_ref());

        for recovery_id in 0..4 {
            recoverable_signature_bytes[SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1] = recovery_id;
            let recoverable_signature = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(
                &recoverable_signature_bytes,
            )?;
            if pk
                .verify_recoverable(message, &recoverable_signature)
                .is_ok()
            {
                return Ok(recoverable_signature);
            }
        }
        Err(FastCryptoError::InvalidInput)
    }

    /// Recover public key from signature and an already hashed message.
    pub fn recover_hashed(&self, hashed_msg: &[u8]) -> Result<Secp256k1PublicKey, FastCryptoError> {
        match Message::from_slice(hashed_msg) {
            Ok(message) => match self.sig.recover(&message) {
                Ok(pubkey) => Secp256k1PublicKey::from_bytes(pubkey.serialize().as_slice()),
                Err(_) => Err(FastCryptoError::GeneralOpaqueError),
            },
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl traits::RecoverableSignature for Secp256k1RecoverableSignature {
    type PubKey = Secp256k1PublicKey;
    type Signer = Secp256k1KeyPair;

    /// Recover public key from signature.
    fn recover(&self, msg: &[u8]) -> Result<Secp256k1PublicKey, FastCryptoError> {
        let message = hash_message(msg);
        self.recover_hashed(message.as_ref())
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

impl VerifyRecoverable for Secp256k1PublicKey {
    type Sig = Secp256k1RecoverableSignature;

    /// Verify a recoverable signature using the default hash function (SHA-256).
    fn verify_recoverable(
        &self,
        msg: &[u8],
        signature: &Secp256k1RecoverableSignature,
    ) -> Result<(), FastCryptoError> {
        let message = hash_message(msg);
        self.verify_recoverable_hashed(message.as_ref(), signature)
    }
}

impl Secp256k1PublicKey {
    /// Verify a recoverable signature over an already hashed message.
    pub fn verify_recoverable_hashed(
        &self,
        hashed_msg: &[u8],
        signature: &Secp256k1RecoverableSignature,
    ) -> Result<(), FastCryptoError> {
        // If pubkey recovered from signature matches original pubkey, verifies signature.
        // To ensure non-malleability of v, signature.verify_ecdsa() is not used since it will verify using only [r, s] without considering v.
        match Message::from_slice(hashed_msg) {
            Ok(message) => match signature.recover_hashed(message.as_ref()) {
                Ok(recovered_key) if self.as_bytes() == recovered_key.as_bytes() => Ok(()),
                _ => Err(FastCryptoError::InvalidSignature),
            },
            _ => Err(FastCryptoError::InvalidSignature),
        }
    }
}

impl RecoverableSigner for Secp256k1KeyPair {
    type PubKey = Secp256k1PublicKey;
    type Sig = Secp256k1RecoverableSignature;

    fn sign_recoverable(&self, msg: &[u8]) -> Secp256k1RecoverableSignature {
        let secp = Secp256k1::signing_only();

        let message = hash_message(msg);

        // Creates a 65-bytes sigature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
            bytes: OnceCell::new(),
        }
    }
}
