// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ECDSA signature scheme](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) over the
//! [secp256r1 NIST-P1 curve](https://www.secg.org/SEC2-Ver-1.0.pdf) where the public key can be recovered from a signature.
//! The nonce is generated deterministically according to [RFC6979](https://www.rfc-editor.org/rfc/rfc6979).
//!
//! Messages can be signed and the public key can be recovered from the signature:
//! # Example
//! ```rust
//! # use fastcrypto::secp256r1::recoverable::*;
//! # use fastcrypto::traits::{KeyPair, RecoverableSignature, RecoverableSigner};
//! # use fastcrypto::secp256r1::Secp256r1KeyPair;
//! use rand::thread_rng;
//! let kp = Secp256r1KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign_recoverable(message);
//! assert_eq!(kp.public(), &signature.recover(message).unwrap());
//! ```

use crate::hash::HashFunction;
use crate::secp256r1::{
    DefaultHash, Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1Signature,
    SECP256R1_SIGNATURE_LENTH,
};
use crate::serialize_deserialize_with_to_from_bytes;
use crate::traits::{RecoverableSignature, RecoverableSigner, VerifyRecoverable};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    traits::{EncodeDecodeBase64, ToFromBytes},
};
use ecdsa::elliptic_curve::bigint::Encoding as OtherEncoding;
use ecdsa::elliptic_curve::subtle::Choice;
use once_cell::sync::OnceCell;
use p256::ecdsa::{Signature as ExternalSignature, VerifyingKey};
use p256::elliptic_curve::bigint::ArrayEncoding;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::IsHigh;
use p256::elliptic_curve::{Curve, DecompressPoint};
use p256::{AffinePoint, FieldBytes, NistP256, ProjectivePoint, Scalar, U256};
use std::fmt::{self, Debug, Display};
use ecdsa::elliptic_curve::scalar::IsHigh;
use ecdsa::RecoveryId;
use eyre::ContextCompat;

pub const SECP256R1_RECOVERABLE_SIGNATURE_LENGTH: usize = SECP256R1_SIGNATURE_LENTH + 1;

/// Secp256r1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1RecoverableSignature {
    pub sig: ExternalSignature,
    pub bytes: OnceCell<[u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH]>,
    pub recovery_id: u8,
}

serialize_deserialize_with_to_from_bytes!(
    Secp256r1RecoverableSignature,
    SECP256R1_RECOVERABLE_SIGNATURE_LENGTH
);

impl ToFromBytes for Secp256r1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != SECP256R1_RECOVERABLE_SIGNATURE_LENGTH {
            return Err(FastCryptoError::InputLengthWrong(
                SECP256R1_RECOVERABLE_SIGNATURE_LENGTH,
            ));
        }
        ExternalSignature::try_from(&bytes[..SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1])
            .map(|sig| Secp256r1RecoverableSignature {
                sig,
                recovery_id: bytes[SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1],
                bytes: OnceCell::new(),
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl AsRef<[u8]> for Secp256r1RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let mut bytes = [0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH];
                bytes[..SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1]
                    .copy_from_slice(self.sig.to_bytes().as_slice());
                bytes[SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1] = self.recovery_id;
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

impl std::hash::Hash for Secp256r1RecoverableSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for Secp256r1RecoverableSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for Secp256r1RecoverableSignature {}

impl Display for Secp256r1RecoverableSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl Secp256r1RecoverableSignature {
    /// Recover the public key used to create this signature. This assumes the recovery id byte has been set. The hash function `H` is used to hash the message.
    ///
    /// An [FastCryptoError::GeneralOpaqueError] is returned if no public keys can be recovered.
    pub fn try_from_nonrecoverable(
        signature: &Secp256r1Signature,
        pk: &Secp256r1PublicKey,
        message: &[u8],
    ) -> Result<Self, FastCryptoError> {
        // Secp256r1Signature::as_bytes is guaranteed to return SECP256R1_SIGNATURE_LENGTH = SECP256R1_RECOVERABLE_SIGNATURE_SIZE - 1 bytes.
        let mut recoverable_signature_bytes = [0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH];
        recoverable_signature_bytes[0..SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1]
            .copy_from_slice(signature.as_ref());

        for recovery_id in 0..4 {
            recoverable_signature_bytes[SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1] = recovery_id;
            let recoverable_signature = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(
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

    /// util function to parse wycheproof test key from DER format.
    #[cfg(test)]
    pub(crate) fn from_uncompressed(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        ExternalSignature::try_from(bytes)
            .map(|sig| Secp256r1RecoverableSignature {
                sig,
                recovery_id: 0u8,
                bytes: OnceCell::new(),
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl RecoverableSigner for Secp256r1KeyPair {
    type PubKey = Secp256r1PublicKey;
    type Sig = Secp256r1RecoverableSignature;

    fn sign_recoverable_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Secp256r1RecoverableSignature {
        let (sig, recovery_id) = self.secret.privkey.sign_prehash_recoverable(H::digest(msg).as_ref()).unwrap();
        let normalized_signature = sig.normalize_s().unwrap_or(sig);
        Secp256r1RecoverableSignature {
            sig: normalized_signature,
            bytes: OnceCell::new(),
            recovery_id: recovery_id.to_byte(),
        }
    }
}

/// Get the x and y-coordinate from a given affine point.
fn get_coordinates(point: &ProjectivePoint) -> (Scalar, Scalar) {
    let encoded_point = point.to_encoded_point(false);

    // The encoded point is in uncompressed form, so we can safely get the y-coordinate here
    let x = encoded_point.x().unwrap();
    let y = encoded_point.y().unwrap();

    (
        Scalar::from_be_bytes_reduced(*x),
        Scalar::from_be_bytes_reduced(*y),
    )
}

impl RecoverableSignature for Secp256r1RecoverableSignature {
    type PubKey = Secp256r1PublicKey;
    type Signer = Secp256r1KeyPair;
    type DefaultHash = DefaultHash;

    fn recover_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Result<Secp256r1PublicKey, FastCryptoError> {
        let vk = VerifyingKey::recover_from_prehash(H::digest(msg).as_ref(), &self.sig, self.recovery_id.try_into().unwrap()).map_err(|_| FastCryptoError::InvalidSignature)?;

        Ok(Secp256r1PublicKey {
            pubkey: vk,
            bytes: OnceCell::new(),
        })
    }
}

impl VerifyRecoverable for Secp256r1PublicKey {
    type Sig = Secp256r1RecoverableSignature;
}
