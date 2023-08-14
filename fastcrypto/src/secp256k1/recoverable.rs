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

use crate::hash::HashFunction;
use crate::secp256k1::{DefaultHash, Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use crate::traits::{RecoverableSignature, RecoverableSigner, VerifyRecoverable};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    impl_base64_display_fmt, serialize_deserialize_with_to_from_bytes,
    traits::{EncodeDecodeBase64, ToFromBytes},
};
use once_cell::sync::{Lazy, OnceCell};
pub use rust_secp256k1::ecdsa::Signature as Secp256k1Sig;
use rust_secp256k1::{
    constants,
    ecdsa::{RecoverableSignature as ExternalRecoverableSignature, RecoveryId},
    All, Message, Secp256k1,
};
use std::fmt::{self, Debug};

pub static SECP256K1: Lazy<Secp256k1<All>> = Lazy::new(rust_secp256k1::Secp256k1::new);

/// Length of a compact signature followed by one extra byte for recovery id, used to recover the public key from a signature.
pub const SECP256K1_RECOVERABLE_SIGNATURE_SIZE: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// Secp256k1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature {
    pub sig: ExternalRecoverableSignature,
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
        RecoveryId::from_i32(bytes[SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1] as i32)
            .and_then(|rec_id| {
                ExternalRecoverableSignature::from_compact(
                    &bytes[..(SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1)],
                    rec_id,
                )
                .map(|sig| Secp256k1RecoverableSignature {
                    sig,
                    bytes: OnceCell::new(),
                })
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl AsRef<[u8]> for Secp256k1RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| {
            let mut bytes = [0u8; SECP256K1_RECOVERABLE_SIGNATURE_SIZE];
            let (recovery_id, sig) = self.sig.serialize_compact();
            bytes[..(SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1)].copy_from_slice(&sig);
            bytes[SECP256K1_RECOVERABLE_SIGNATURE_SIZE - 1] = recovery_id.to_i32() as u8;
            bytes
        })
    }
}

impl std::hash::Hash for Secp256k1RecoverableSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for Secp256k1RecoverableSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for Secp256k1RecoverableSignature {}

impl_base64_display_fmt!(Secp256k1RecoverableSignature);

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
}

impl RecoverableSignature for Secp256k1RecoverableSignature {
    type PubKey = Secp256k1PublicKey;
    type Signer = Secp256k1KeyPair;
    type DefaultHash = DefaultHash;

    /// Recover public key from signature using the given hash function to hash the message.
    fn recover_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Result<Secp256k1PublicKey, FastCryptoError> {
        match Message::from_slice(&H::digest(msg).digest) {
            Ok(message) => match self.sig.recover(&message) {
                Ok(pubkey) => Secp256k1PublicKey::from_bytes(pubkey.serialize().as_slice()),
                Err(_) => Err(FastCryptoError::GeneralOpaqueError),
            },
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl RecoverableSigner for Secp256k1KeyPair {
    type PubKey = Secp256k1PublicKey;
    type Sig = Secp256k1RecoverableSignature;

    /// Create a new recoverable signature over the given message. The hash function `H` is used to hash the message.
    fn sign_recoverable_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Secp256k1RecoverableSignature {
        let secp = Secp256k1::signing_only();
        let message = Message::from_slice(H::digest(msg).as_ref()).unwrap();

        // Creates a 65-bytes sigature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
            bytes: OnceCell::new(),
        }
    }
}

impl VerifyRecoverable for Secp256k1PublicKey {
    type Sig = Secp256k1RecoverableSignature;
}
