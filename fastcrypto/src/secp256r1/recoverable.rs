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
use crate::secp256r1::conversion::{
    affine_pt_arkworks_to_p256, affine_pt_p256_to_arkworks, arkworks_fq_to_fr, fq_arkworks_to_p256,
    fr_arkworks_to_p256, fr_p256_to_arkworks,
};
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
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::Field;
use ecdsa::elliptic_curve::scalar::IsHigh;
use ecdsa::elliptic_curve::subtle::Choice;
use ecdsa::RecoveryId;
use once_cell::sync::OnceCell;
use p256::ecdsa::{Signature as ExternalSignature, VerifyingKey};
use p256::elliptic_curve::bigint::ArrayEncoding;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::point::DecompressPoint;
use p256::elliptic_curve::{Curve, FieldBytesEncoding, PrimeField};
use p256::{AffinePoint, FieldBytes, NistP256, Scalar, U256};
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
        // Hash message
        let z = FieldBytes::from(H::digest(msg).digest);

        // Private key as scalar
        let x = self.secret.privkey.as_nonzero_scalar().to_bytes();

        // Generate k deterministically according to RFC6979
        let k = fr_p256_to_arkworks(
            &Scalar::from_repr(rfc6979::generate_k::<sha2::Sha256, _>(
                &x,
                &NistP256::ORDER.encode_field_bytes(),
                &z,
                &[],
            ))
            .unwrap(),
        );
        let k_inv = k.inverse().expect("k should be non-zero");

        // Compute 𝑹 = 𝑘×𝑮
        let big_r = (ark_secp256r1::Projective::generator() * k).into_affine();

        // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = arkworks_fq_to_fr(big_r.x().expect("R is zero"));

        // Compute 𝒔 as a signature over 𝒓 and 𝒛.
        let x = fr_p256_to_arkworks(&Scalar::reduce_bytes(&x));
        let z = fr_p256_to_arkworks(&Scalar::reduce_bytes(&z));
        let s = k_inv * (z + (r * x));

        let s = fr_arkworks_to_p256(&s).to_bytes();
        let r = fr_arkworks_to_p256(&r).to_bytes();

        // This can only fail if either 𝒓 or 𝒔 are zero (see ecdsa-0.15.0/src/lib.rs) which is negligible.
        let sig = ExternalSignature::from_scalars(r, s).expect("r or s is zero");

        let y = fq_arkworks_to_p256(big_r.y().expect("R is zero"));

        // Compute recovery id and normalize signature
        let is_r_odd = y.is_odd();
        let is_s_high = sig.s().is_high();
        let is_y_odd = is_r_odd ^ is_s_high;
        let sig_low = sig.normalize_s().unwrap_or(sig);
        let recovery_id = RecoveryId::new(is_y_odd.into(), false);

        Secp256r1RecoverableSignature {
            sig: sig_low,
            bytes: OnceCell::new(),
            recovery_id: recovery_id.to_byte(),
        }
    }
}

impl RecoverableSignature for Secp256r1RecoverableSignature {
    type PubKey = Secp256r1PublicKey;
    type Signer = Secp256r1KeyPair;
    type DefaultHash = DefaultHash;

    fn recover_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
    ) -> Result<Secp256r1PublicKey, FastCryptoError> {
        // This is inspired by `recover_verify_key_from_digest_bytes` in the k256@0.11.6 crate with a few alterations.
        let (r, s) = self.sig.split_scalars();
        let v = RecoveryId::from_byte(self.recovery_id).ok_or(FastCryptoError::InvalidInput)?;

        // Note: This has been added because it does not seem to be done in k256
        let r_bytes = match v.is_x_reduced() {
            true => U256::from(r.as_ref())
                .wrapping_add(&NistP256::ORDER)
                .to_be_byte_array(),
            false => r.to_bytes(),
        };

        let big_r = AffinePoint::decompress(&r_bytes, Choice::from(v.is_y_odd() as u8));

        if big_r.is_some().into() {
            let big_r = affine_pt_p256_to_arkworks(&big_r.unwrap());

            let r_inv = fr_p256_to_arkworks(&r)
                .inverse()
                .expect("r should be non-zero");

            let z = fr_p256_to_arkworks(&Scalar::reduce_bytes(&FieldBytes::clone_from_slice(
                H::digest(msg).as_ref(),
            )));
            let s = fr_p256_to_arkworks(&s);

            let u1 = -(r_inv * z);
            let u2 = r_inv * s;
            let pk = affine_pt_arkworks_to_p256(
                &((ark_secp256r1::Affine::generator() * u1) + (big_r * u2)).into_affine(),
            );

            Ok(Secp256r1PublicKey {
                pubkey: VerifyingKey::from_affine(pk)
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
