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
//! # use fastcrypto::{traits::{KeyPair, RecoverableSignature, RecoverableSigner}, Verifier};
//! # use fastcrypto::secp256r1::Secp256r1KeyPair;
//! use rand::thread_rng;
//! let kp = Secp256r1KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign_recoverable(message);
//! assert_eq!(kp.public(), &signature.recover(message).unwrap());
//! ```

use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::secp256r1::{
    Secp256r1KeyPair, Secp256r1PublicKey, Secp256r1Signature, SECP256R1_SIGNATURE_LENTH,
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
use ecdsa::elliptic_curve::ScalarCore;
use ecdsa::RecoveryId;
use once_cell::sync::OnceCell;
use p256::ecdsa::Signature as ExternalSignature;
use p256::ecdsa::VerifyingKey as ExternalPublicKey;
use p256::elliptic_curve::bigint::ArrayEncoding;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::IsHigh;
use p256::elliptic_curve::{AffineXCoordinate, Curve, DecompressPoint, Field};
use p256::{AffinePoint, FieldBytes, NistP256, ProjectivePoint, Scalar, U256};
use signature::Signature;
use std::borrow::Borrow;
use std::fmt::{self, Debug, Display};

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

impl Signature for Secp256r1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        // TODO: Compatibility with signatures without recovery id
        if bytes.len() != SECP256R1_RECOVERABLE_SIGNATURE_LENGTH {
            return Err(signature::Error::new());
        }
        ExternalSignature::try_from(&bytes[..SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1])
            .map(|sig| Secp256r1RecoverableSignature {
                sig,
                recovery_id: bytes[SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1],
                bytes: OnceCell::new(),
            })
            .map_err(|_| signature::Error::new())
    }
}

impl AsRef<[u8]> for Secp256r1RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        let mut bytes = [0u8; SECP256R1_RECOVERABLE_SIGNATURE_LENGTH];
        bytes[..SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1]
            .copy_from_slice(self.sig.to_bytes().as_slice());
        bytes[SECP256R1_RECOVERABLE_SIGNATURE_LENGTH - 1] = self.recovery_id;
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(bytes))
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
    pub(crate) fn from_uncompressed(bytes: &[u8]) -> Result<Self, signature::Error> {
        ExternalSignature::try_from(bytes)
            .map(|sig| Secp256r1RecoverableSignature {
                sig,
                recovery_id: 0u8,
                bytes: OnceCell::new(),
            })
            .map_err(|_| signature::Error::new())
    }
}

impl RecoverableSigner for Secp256r1KeyPair {
    type PubKey = Secp256r1PublicKey;
    type Sig = Secp256r1RecoverableSignature;

    fn try_sign_recoverable(
        &self,
        msg: &[u8],
    ) -> Result<Secp256r1RecoverableSignature, FastCryptoError> {
        // Code copied from Sign.rs in k256@0.11.6

        // Hash message
        let z = FieldBytes::from(Sha256::digest(msg).digest);

        // Private key as scalar
        let x = U256::from_be_bytes(self.secret.privkey.as_nonzero_scalar().to_bytes().into());

        // Generate k deterministically according to RFC6979
        let k = rfc6979::generate_k::<sha2::Sha256, U256>(&x, &NistP256::ORDER, &z, &[]);
        let k = Scalar::from(ScalarCore::<NistP256>::new(*k).unwrap());

        if k.borrow().is_zero().into() {
            return Err(FastCryptoError::GeneralOpaqueError);
        }

        let z = Scalar::from_be_bytes_reduced(z);

        // Compute scalar inversion of 𝑘
        let k_inv =
            Option::<Scalar>::from(k.invert()).ok_or(FastCryptoError::GeneralOpaqueError)?;

        // Compute 𝑹 = 𝑘×𝑮
        let big_r = (ProjectivePoint::GENERATOR * k.borrow()).to_affine();

        // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = Scalar::from_be_bytes_reduced(big_r.x());

        let x = Scalar::from_be_bytes_reduced(x.to_be_byte_array());

        // Compute 𝒔 as a signature over 𝒓 and 𝒛.
        let s = k_inv * (z + (r * x));

        if s.is_zero().into() {
            return Err(FastCryptoError::GeneralOpaqueError);
        }

        let sig = ExternalSignature::from_scalars(r, s)
            .map_err(|_| FastCryptoError::GeneralOpaqueError)?;

        // Note: This line is introduced here because big_r.y is a private field.
        let y: Scalar = get_y_coordinate(&big_r);

        // Compute recovery id and normalize signature
        let is_r_odd = y.is_odd();
        let is_s_high = sig.s().is_high();
        let is_y_odd = is_r_odd ^ is_s_high;
        let sig_low = sig.normalize_s().unwrap_or(sig);
        let recovery_id = RecoveryId::new(is_y_odd.into(), false);

        Ok(Secp256r1RecoverableSignature {
            sig: sig_low,
            bytes: OnceCell::new(),
            recovery_id: recovery_id.to_byte(),
        })
    }
}

/// Get the y-coordinate from a given affine point.
fn get_y_coordinate(point: &AffinePoint) -> Scalar {
    let encoded_point = point.to_encoded_point(false);

    // The encoded point is in uncompressed form, so we can safely get the y-coordinate here
    let y = encoded_point.y().unwrap();

    Scalar::from_be_bytes_reduced(*y)
}

impl RecoverableSignature for Secp256r1RecoverableSignature {
    type PubKey = Secp256r1PublicKey;
    type Signer = Secp256r1KeyPair;

    /// Recover the public used to create this signature. This assumes the recovery id byte has been set.
    ///
    /// This is copied from `recover_verify_key_from_digest_bytes` in the k256@0.11.6 crate except for a few additions.
    ///
    /// An [FastCryptoError::GeneralOpaqueError] is returned if no public keys can be recovered.
    fn recover(&self, msg: &[u8]) -> Result<Secp256r1PublicKey, FastCryptoError> {
        let (r, s) = self.sig.split_scalars();
        let v = RecoveryId::from_byte(self.recovery_id).ok_or(FastCryptoError::InvalidInput)?;
        let z = Scalar::from_be_bytes_reduced(FieldBytes::from(Sha256::digest(msg).digest));

        // Note: This has been added because it does not seem to be done in k256
        let r_bytes = match v.is_x_reduced() {
            true => U256::from(r.as_ref())
                .wrapping_add(&NistP256::ORDER)
                .to_be_byte_array(),
            false => r.to_bytes(),
        };

        let big_r = AffinePoint::decompress(&r_bytes, Choice::from(v.is_y_odd() as u8));

        if big_r.is_some().into() {
            let big_r = ProjectivePoint::from(big_r.unwrap());
            let r_inv = r.invert().unwrap();
            let u1 = -(r_inv * z);
            let u2 = r_inv * *s;
            let pk = ((ProjectivePoint::GENERATOR * u1) + (big_r * u2)).to_affine();

            Ok(Secp256r1PublicKey {
                pubkey: ExternalPublicKey::from_affine(pk)
                    .map_err(|_| FastCryptoError::GeneralOpaqueError)?,
                bytes: OnceCell::new(),
            })
        } else {
            Err(FastCryptoError::GeneralOpaqueError)
        }
    }
}

impl VerifyRecoverable for Secp256r1PublicKey {
    type Sig = Secp256r1RecoverableSignature;
}
