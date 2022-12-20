// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ECDSA signature scheme](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) over the
//! [secp256r1 NIST-P1 curve](https://www.secg.org/SEC2-Ver-1.0.pdf). The nonce is generated deterministically according to [RFC6979](https://www.rfc-editor.org/rfc/rfc6979).
//!
//! Messages can be signed and the signature can be verified again:
//! # Example
//! ```rust
//! # use fastcrypto::secp256r1::*;
//! # use fastcrypto::{traits::{KeyPair, Signer}, Verifier};
//! use rand::thread_rng;
//! let kp = Secp256r1KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert!(kp.public().verify(message, &signature).is_ok());
//! ```

use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::serialize_deserialize_with_to_from_bytes;
use crate::traits::{RecoverableSignature, SignAsRecoverable};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    traits::{
        AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
        VerifyingKey,
    },
};
use ecdsa::elliptic_curve::bigint::Encoding as OtherEncoding;
use ecdsa::elliptic_curve::subtle::Choice;
use ecdsa::elliptic_curve::ScalarCore;
use ecdsa::RecoveryId;
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::OnceCell;
use p256::ecdsa::Signature as ExternalSignature;
use p256::ecdsa::SigningKey as ExternalSecretKey;
use p256::ecdsa::VerifyingKey as ExternalPublicKey;
use p256::elliptic_curve::bigint::ArrayEncoding;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::IsHigh;
use p256::elliptic_curve::{AffineXCoordinate, Curve, DecompressPoint, Field};
use p256::{AffinePoint, FieldBytes, NistP256, ProjectivePoint, Scalar, U256};
use serde::{de, Deserialize, Serialize};
use signature::{Error, Signature, Signer, Verifier};
use std::borrow::Borrow;
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};
use zeroize::Zeroize;

pub const PUBLIC_KEY_SIZE: usize = 33;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const RECOVERABLE_SIGNATURE_SIZE: usize = SIGNATURE_SIZE + 1;

/// The key pair bytes length used by helper is the same as the private key length. This is because only private key is serialized.
pub const SECP256R1_KEY_PAIR_BYTES_LENGTH: usize = PRIVATE_KEY_SIZE;
/// Secp256r1 public key.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1PublicKey {
    pub pubkey: ExternalPublicKey,
    pub bytes: OnceCell<[u8; PUBLIC_KEY_SIZE]>,
}

/// Secp256r1 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay, PartialEq, Eq)]
pub struct Secp256r1PrivateKey {
    pub privkey: ExternalSecretKey,
    pub bytes: OnceCell<[u8; PRIVATE_KEY_SIZE]>,
}

/// Secp256r1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1Signature {
    pub sig: ExternalSignature,
    pub bytes: OnceCell<[u8; SIGNATURE_SIZE]>,
}

/// Secp256r1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1RecoverableSignature {
    pub sig: ExternalSignature,
    pub recovery_id: RecoveryId,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
}

impl std::hash::Hash for Secp256r1PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialOrd for Secp256r1PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for Secp256r1PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl PartialEq for Secp256r1PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl Eq for Secp256r1PublicKey {}

impl VerifyingKey for Secp256r1PublicKey {
    type PrivKey = Secp256r1PrivateKey;
    type Sig = Secp256r1Signature;
    const LENGTH: usize = PUBLIC_KEY_SIZE;
}

impl Verifier<Secp256r1Signature> for Secp256r1PublicKey {
    fn verify(&self, msg: &[u8], signature: &Secp256r1Signature) -> Result<(), signature::Error> {
        // We enforce non malleability, eg. that the s value must be low. This is aligned with
        // the ECDSA implementation in the secp256k1 crate.
        if signature.sig.s().is_high().into() {
            return Err(signature::Error::new());
        }
        self.pubkey
            .verify(msg, &signature.sig)
            .map_err(|_| signature::Error::new())
    }
}

impl Secp256r1PublicKey {}

impl AsRef<[u8]> for Secp256r1PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.pubkey.as_ref().to_bytes().into()))
            .expect("OnceCell invariant violated")
    }
}

impl ToFromBytes for Secp256r1PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match ExternalPublicKey::try_from(bytes) {
            Ok(pubkey) => Ok(Secp256r1PublicKey {
                pubkey,
                // If the given bytes is in the right format (compressed), we keep them for next time to_bytes is called
                bytes: match <[u8; PUBLIC_KEY_SIZE]>::try_from(bytes) {
                    Ok(result) => OnceCell::with_value(result),
                    Err(_) => OnceCell::new(),
                },
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl Default for Secp256r1PublicKey {
    fn default() -> Self {
        // Default public key is just the generator for the group
        Secp256r1PublicKey {
            pubkey: ExternalPublicKey::from_affine(AffinePoint::GENERATOR).unwrap(),
            bytes: OnceCell::new(),
        }
    }
}

impl Display for Secp256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for Secp256r1PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for Secp256r1PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl<'a> From<&'a Secp256r1PrivateKey> for Secp256r1PublicKey {
    fn from(secret: &'a Secp256r1PrivateKey) -> Self {
        Secp256r1PublicKey {
            pubkey: ExternalPublicKey::from(&secret.privkey),
            bytes: OnceCell::new(),
        }
    }
}

impl SigningKey for Secp256r1PrivateKey {
    type PubKey = Secp256r1PublicKey;
    type Sig = Secp256r1Signature;
    const LENGTH: usize = PRIVATE_KEY_SIZE;
}

impl ToFromBytes for Secp256r1PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match ExternalSecretKey::try_from(bytes) {
            Ok(privkey) => Ok(Secp256r1PrivateKey {
                privkey,
                bytes: OnceCell::with_value(<[u8; 32]>::try_from(bytes).unwrap()),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for Secp256r1PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for Secp256r1PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for Secp256r1PrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| Ok(self.privkey.to_bytes().into()))
            .expect("OnceCell invariant violated")
    }
}

impl Serialize for Secp256r1Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Secp256r1Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        <Secp256r1Signature as Signature>::from_bytes(&data)
            .map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl Signature for Secp256r1Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(signature::Error::new());
        }

        let sig = <ExternalSignature as Signature>::from_bytes(bytes)?;

        Ok(Secp256r1Signature {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

impl Authenticator for Secp256r1Signature {
    type PubKey = Secp256r1PublicKey;
    type PrivKey = Secp256r1PrivateKey;
    const LENGTH: usize = SIGNATURE_SIZE;
}

impl AsRef<[u8]> for Secp256r1Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                Ok(<[u8; 64]>::try_from(self.sig.as_ref()).unwrap())
            })
            .expect("OnceCell invariant violated")
    }
}

impl std::hash::Hash for Secp256r1Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for Secp256r1Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for Secp256r1Signature {}

impl Display for Secp256r1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl Default for Secp256r1Signature {
    fn default() -> Self {
        // Return the signature (1,1)
        Secp256r1Signature {
            sig: ExternalSignature::from_scalars(Scalar::ONE.to_bytes(), Scalar::ONE.to_bytes())
                .unwrap(),
            bytes: OnceCell::new(),
        }
    }
}

impl Serialize for Secp256r1RecoverableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Secp256r1RecoverableSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        Secp256r1RecoverableSignature::from_bytes(&data)
            .map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl From<&Secp256r1RecoverableSignature> for Secp256r1Signature {
    fn from(recoverable_signature: &Secp256r1RecoverableSignature) -> Self {
        Secp256r1Signature {
            sig: recoverable_signature.sig,
            bytes: OnceCell::new(),
        }
    }
}

impl TryFrom<(&Secp256r1Signature, u8)> for Secp256r1RecoverableSignature {
    type Error = FastCryptoError;

    fn try_from((signature, rec_id): (&Secp256r1Signature, u8)) -> Result<Self, FastCryptoError> {
        let recovery_id = RecoveryId::from_byte(rec_id).ok_or(FastCryptoError::InvalidInput)?;
        Ok(Secp256r1RecoverableSignature {
            sig: signature.sig,
            recovery_id,
            bytes: OnceCell::new(),
        })
    }
}

impl ToFromBytes for Secp256r1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let sig =
            <ExternalSignature as Signature>::from_bytes(&bytes[..RECOVERABLE_SIGNATURE_SIZE - 1])
                .map_err(|_| FastCryptoError::InvalidInput)?;

        let recovery_id = RecoveryId::from_byte(bytes[RECOVERABLE_SIGNATURE_SIZE - 1])
            .ok_or(FastCryptoError::InvalidInput)?;

        Ok(Secp256r1RecoverableSignature {
            sig,
            recovery_id,
            bytes: OnceCell::new(),
        })
    }
}

impl RecoverableSignature for Secp256r1RecoverableSignature {
    type PubKey = Secp256r1PublicKey;

    fn recover(&self, msg: &[u8]) -> Result<Secp256r1PublicKey, FastCryptoError> {
        self.recover_hashed(&Sha256::digest(msg).digest)
    }
}

impl Secp256r1RecoverableSignature {
    /// Recover the public key given an already hashed digest.
    pub fn recover_hashed(&self, digest: &[u8; 32]) -> Result<Secp256r1PublicKey, FastCryptoError> {
        // This is copied from `recover_verify_key_from_digest_bytes` in the k256@0.11.6 crate except for a few additions.

        let (r, s) = self.sig.split_scalars();
        let z = Scalar::from_be_bytes_reduced(FieldBytes::from(*digest));

        // Note: This has been added because it does not seem to be done in k256
        let r_bytes = match self.recovery_id.is_x_reduced() {
            true => U256::from(r.as_ref())
                .wrapping_add(&NistP256::ORDER)
                .to_be_byte_array(),
            false => r.to_bytes(),
        };

        let big_r =
            AffinePoint::decompress(&r_bytes, Choice::from(self.recovery_id.is_y_odd() as u8));

        if big_r.is_some().into() {
            let big_r = ProjectivePoint::from(big_r.unwrap());
            let r_inv = r.invert().unwrap();
            let u1 = -(r_inv * z);
            let u2 = r_inv * *s;
            let pk = ((ProjectivePoint::GENERATOR * u1) + (big_r * u2)).to_affine();

            Ok(Secp256r1PublicKey {
                pubkey: ExternalPublicKey::from_affine(pk)
                    .map_err(|_| FastCryptoError::GeneralError)?,
                bytes: OnceCell::new(),
            })
        } else {
            Err(FastCryptoError::GeneralError)
        }
    }

    /// Get the recovery id for this recoverable signature.
    pub fn recovery_id(&self) -> u8 {
        self.as_ref()[RECOVERABLE_SIGNATURE_SIZE - 1]
    }
}

impl AsRef<[u8]> for Secp256r1RecoverableSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let mut bytes = [0u8; RECOVERABLE_SIGNATURE_SIZE];
                bytes[0..RECOVERABLE_SIGNATURE_SIZE - 1].copy_from_slice(self.sig.as_ref());
                bytes[RECOVERABLE_SIGNATURE_SIZE - 1] = self.recovery_id.to_byte();
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

impl Default for Secp256r1RecoverableSignature {
    fn default() -> Self {
        // Return the signature (1,1)
        Secp256r1RecoverableSignature {
            sig: ExternalSignature::from_scalars(Scalar::ONE.to_bytes(), Scalar::ONE.to_bytes())
                .unwrap(),
            recovery_id: RecoveryId::from_byte(0).unwrap(),
            bytes: OnceCell::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Secp256r1KeyPair {
    pub name: Secp256r1PublicKey,
    pub secret: Secp256r1PrivateKey,
}

/// The bytes form of the keypair always only contain the private key bytes
impl ToFromBytes for Secp256r1KeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Secp256r1PrivateKey::from_bytes(bytes).map(|secret| secret.into())
    }
}

serialize_deserialize_with_to_from_bytes!(Secp256r1KeyPair);

impl AsRef<[u8]> for Secp256r1KeyPair {
    fn as_ref(&self) -> &[u8] {
        self.secret.as_ref()
    }
}

impl KeyPair for Secp256r1KeyPair {
    type PubKey = Secp256r1PublicKey;
    type PrivKey = Secp256r1PrivateKey;
    type Sig = Secp256r1Signature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        Secp256r1PrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256r1KeyPair {
            name: self.name.clone(),
            secret: Secp256r1PrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let privkey = ExternalSecretKey::random(rng);
        let pubkey = ExternalPublicKey::from(&privkey);

        Secp256r1KeyPair {
            name: Secp256r1PublicKey {
                pubkey,
                bytes: OnceCell::new(),
            },
            secret: Secp256r1PrivateKey {
                privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl FromStr for Secp256r1KeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl Signer<Secp256r1Signature> for Secp256r1KeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<Secp256r1Signature, Error> {
        let sig = self.secret.privkey.try_sign(msg)?;
        let sig_low = sig.normalize_s().unwrap_or(sig);
        Ok(Secp256r1Signature {
            sig: sig_low,
            bytes: OnceCell::new(),
        })
    }
}

impl SignAsRecoverable for Secp256r1KeyPair {
    type RecoverableSig = Secp256r1RecoverableSignature;

    fn try_sign_as_recoverable(
        &self,
        msg: &[u8],
    ) -> Result<Secp256r1RecoverableSignature, signature::Error> {
        // Code copied from Sign.rs in k256@0.11.6

        // Hash message
        let z = FieldBytes::from(Sha256::digest(msg).digest);

        // Private key as scalar
        let x = U256::from_be_bytes(self.secret.privkey.as_nonzero_scalar().to_bytes().into());

        // Generate k deterministically according to RFC6979
        let k = rfc6979::generate_k::<sha2::Sha256, U256>(&x, &NistP256::ORDER, &z, &[]);
        let k = Scalar::from(ScalarCore::<NistP256>::new(*k).unwrap());

        if k.borrow().is_zero().into() {
            return Err(signature::Error::new());
        }

        let z = Scalar::from_be_bytes_reduced(z);

        // Compute scalar inversion of 𝑘
        let k_inv = Option::<Scalar>::from(k.invert()).ok_or_else(signature::Error::new)?;

        // Compute 𝑹 = 𝑘×𝑮
        let big_r = (ProjectivePoint::GENERATOR * k.borrow()).to_affine();

        // Lift x-coordinate of 𝑹 (element of base field) into a serialized big
        // integer, then reduce it into an element of the scalar field
        let r = Scalar::from_be_bytes_reduced(big_r.x());

        let x = Scalar::from_be_bytes_reduced(x.to_be_byte_array());

        // Compute 𝒔 as a signature over 𝒓 and 𝒛.
        let s = k_inv * (z + (r * x));

        if s.is_zero().into() {
            return Err(signature::Error::new());
        }

        let sig = ExternalSignature::from_scalars(r, s)?;

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
            recovery_id,
            bytes: OnceCell::new(),
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

impl From<Secp256r1PrivateKey> for Secp256r1KeyPair {
    fn from(secret: Secp256r1PrivateKey) -> Self {
        let name = Secp256r1PublicKey::from(&secret);
        Secp256r1KeyPair { name, secret }
    }
}

impl Secp256r1Signature {
    /// util function to parse wycheproof test key from DER format.
    #[cfg(test)]
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self, signature::Error> {
        <ExternalSignature as Signature>::from_bytes(bytes)
            .map(|sig| Secp256r1Signature {
                sig,
                bytes: OnceCell::new(),
            })
            .map_err(|_| signature::Error::new())
    }
}

impl zeroize::Zeroize for Secp256r1PrivateKey {
    fn zeroize(&mut self) {
        self.bytes.take().zeroize();
        // SigningKey from the p256 crate implements zeroize on drop, so we do not need to zeroize it here.
    }
}

impl Drop for Secp256r1PrivateKey {
    fn drop(&mut self) {
        self.bytes.take().zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for Secp256r1PrivateKey {}

impl zeroize::Zeroize for Secp256r1KeyPair {
    fn zeroize(&mut self) {
        self.secret.zeroize()
    }
}

impl zeroize::ZeroizeOnDrop for Secp256r1KeyPair {}

impl Drop for Secp256r1KeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
