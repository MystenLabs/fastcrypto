// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
#[cfg(test)]
use crate::hash::HashFunction;
#[cfg(test)]
use crate::hash::Keccak256;
use crate::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use crate::traits::{SignAsRecoverable, ToFromBytes};
use once_cell::sync::OnceCell;
use rust_secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use rust_secp256k1::hashes::sha256;
use rust_secp256k1::{constants, Message, Secp256k1};
use serde::{de, Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt;
use std::fmt::Display;

pub const RECOVERABLE_SIGNATURE_SIZE: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// Secp256k1 ecdsa recoverable signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature {
    pub sig: RecoverableSignature,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
}

impl TryFrom<(&Secp256k1Signature, u8)> for Secp256k1RecoverableSignature {
    type Error = FastCryptoError;
    fn try_from((signature, rec_id): (&Secp256k1Signature, u8)) -> Result<Self, FastCryptoError> {
        let recovery_id =
            RecoveryId::from_i32(rec_id as i32).map_err(|_| FastCryptoError::InvalidInput)?;
        let sig = RecoverableSignature::from_compact(signature.as_ref(), recovery_id)
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
        Secp256k1RecoverableSignature::from_bytes(&data)
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

impl ToFromBytes for Secp256k1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        RecoveryId::from_i32(bytes[64] as i32)
            .and_then(|rec_id| {
                RecoverableSignature::from_compact(&bytes[..64], rec_id).map(|sig| {
                    Secp256k1RecoverableSignature {
                        sig,
                        bytes: OnceCell::new(),
                    }
                })
            })
            .map_err(|_| FastCryptoError::GeneralError)
    }
}

impl crate::traits::RecoverableSignature for Secp256k1RecoverableSignature {
    type PubKey = Secp256k1PublicKey;

    fn recover(&self, msg: &[u8]) -> Result<Self::PubKey, FastCryptoError> {
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

impl std::hash::Hash for Secp256k1RecoverableSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl Display for Secp256k1RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl Default for Secp256k1RecoverableSignature {
    fn default() -> Self {
        Secp256k1RecoverableSignature::from_bytes(&[1u8; RECOVERABLE_SIGNATURE_SIZE]).unwrap()
    }
}

impl SignAsRecoverable for Secp256k1KeyPair {
    type RecoverableSig = Secp256k1RecoverableSignature;

    fn try_sign_as_recoverable(
        &self,
        msg: &[u8],
    ) -> Result<Secp256k1RecoverableSignature, signature::Error> {
        let secp = Secp256k1::signing_only();

        let message = Message::from_hashed_data::<sha256::Hash>(msg);

        // Creates a 65-bytes signature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Ok(Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
            bytes: OnceCell::new(),
        })
    }
}

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
