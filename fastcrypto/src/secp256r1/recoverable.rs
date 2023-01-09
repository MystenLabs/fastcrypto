// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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
use serde::{de, Deserialize, Serialize};
use signature::{Error, Signature, Signer, Verifier};
use std::borrow::Borrow;
use std::fmt::{self, Debug, Display};
use std::str::FromStr;

use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::pubkey_bytes::PublicKeyBytes;
use crate::secp256r1::Secp256r1PublicKey;
use crate::secp256r1::Secp256r1Signature;
use crate::secp256r1::SIGNATURE_SIZE;
use crate::secp256r1::{Secp256r1KeyPair, Secp256r1PrivateKey};
use crate::serde_helpers::keypair_decode_base64;
use crate::traits::{
    AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, RecoverableSignature, SigningKey,
    VerifyingKey,
};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    serialize_deserialize_from_encode_decode_base64,
    traits::ToFromBytes,
};
use derive_more::Display;
use fastcrypto_derive::{SilentDebug, SilentDisplay};

pub const RECOVERABLE_SIGNATURE_SIZE: usize = SIGNATURE_SIZE + 1;

/// Secp256r1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1RecoverableSignature {
    pub sig: ExternalSignature,
    pub recovery_id: RecoveryId,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
}

#[readonly::make]
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Display, Hash)]
pub struct Secp256r1RecoverablePublicKey(pub(crate) Secp256r1PublicKey);

/// Binary representation of an instance of [Secp256r1RecoverablePublicKey].
pub type Secp256r1RecoverablePublicKeyBytes =
    PublicKeyBytes<Secp256r1RecoverablePublicKey, { Secp256r1PublicKey::LENGTH }>;

#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256r1RecoverablePrivateKey(pub(crate) Secp256r1PrivateKey);

/// Secp256r1 public/private key pair.
#[derive(Debug)]
pub struct Secp256r1RecoverableKeyPair {
    pub name: Secp256r1RecoverablePublicKey,
    pub secret: Secp256r1RecoverablePrivateKey,
}

//
// Secp256r1RecoverablePublicKey
//
impl ToFromBytes for Secp256r1RecoverablePublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256r1RecoverablePublicKey(
            Secp256r1PublicKey::from_bytes(bytes)?,
        ))
    }
}

impl AsRef<[u8]> for Secp256r1RecoverablePublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Verifier<Secp256r1RecoverableSignature> for Secp256r1RecoverablePublicKey {
    fn verify(&self, msg: &[u8], signature: &Secp256r1RecoverableSignature) -> Result<(), Error> {
        let recovered = signature.recover(msg).map_err(|_| Error::new())?;
        if recovered != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

impl<'a> From<&'a Secp256r1RecoverablePrivateKey> for Secp256r1RecoverablePublicKey {
    fn from(_: &'a Secp256r1RecoverablePrivateKey) -> Self {
        todo!()
    }
}

serialize_deserialize_from_encode_decode_base64!(Secp256r1RecoverablePublicKey);

impl VerifyingKey for Secp256r1RecoverablePublicKey {
    type PrivKey = Secp256r1RecoverablePrivateKey;
    type Sig = Secp256r1RecoverableSignature;
    const LENGTH: usize = Secp256r1PublicKey::LENGTH;
}

impl TryFrom<Secp256r1RecoverablePublicKeyBytes> for Secp256r1RecoverablePublicKey {
    type Error = signature::Error;

    fn try_from(
        bytes: Secp256r1RecoverablePublicKeyBytes,
    ) -> Result<Secp256r1RecoverablePublicKey, Self::Error> {
        Secp256r1RecoverablePublicKey::from_bytes(bytes.as_ref()).map_err(|_| Self::Error::new())
    }
}

impl From<&Secp256r1RecoverablePublicKey> for Secp256r1RecoverablePublicKeyBytes {
    fn from(pk: &Secp256r1RecoverablePublicKey) -> Self {
        Secp256r1RecoverablePublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

impl From<Secp256r1PublicKey> for Secp256r1RecoverablePublicKey {
    fn from(pk: Secp256r1PublicKey) -> Self {
        Secp256r1RecoverablePublicKey(pk)
    }
}

impl Secp256r1RecoverablePublicKey {
    pub fn verify_hashed(
        &self,
        hashed_msg: &[u8],
        signature: &Secp256r1RecoverableSignature,
    ) -> Result<(), Error> {
        let digest: &[u8; 32] = hashed_msg.try_into().map_err(|_| Error::new())?;
        let recovered = signature.recover_hashed(digest).map_err(|_| Error::new())?;
        if recovered != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

//
// Secp256r1RecoverableSignature
//
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
        <Secp256r1RecoverableSignature as Signature>::from_bytes(&data)
            .map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl<S: Borrow<Secp256r1RecoverableSignature>> From<S> for Secp256r1Signature {
    fn from(recoverable_signature: S) -> Self {
        Secp256r1Signature {
            sig: recoverable_signature.borrow().sig,
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

impl Authenticator for Secp256r1RecoverableSignature {
    type PubKey = Secp256r1RecoverablePublicKey;
    type PrivKey = Secp256r1RecoverablePrivateKey;
    const LENGTH: usize = RECOVERABLE_SIGNATURE_SIZE;
}

impl Signature for Secp256r1RecoverableSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let sig =
            <ExternalSignature as Signature>::from_bytes(&bytes[..RECOVERABLE_SIGNATURE_SIZE - 1])
                .map_err(|_| signature::Error::new())?;

        let recovery_id = RecoveryId::from_byte(bytes[RECOVERABLE_SIGNATURE_SIZE - 1])
            .ok_or_else(signature::Error::new)?;

        Ok(Secp256r1RecoverableSignature {
            sig,
            recovery_id,
            bytes: OnceCell::new(),
        })
    }
}

impl RecoverableSignature for Secp256r1RecoverableSignature {
    type BasePubKey = Secp256r1PublicKey;

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
        self.recovery_id.to_byte()
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

//
// Secp256r1RecoverablePrivateKey
//
impl ToFromBytes for Secp256r1RecoverablePrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256r1RecoverablePrivateKey(
            Secp256r1PrivateKey::from_bytes(bytes)?,
        ))
    }
}

impl AsRef<[u8]> for Secp256r1RecoverablePrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl SigningKey for Secp256r1RecoverablePrivateKey {
    type PubKey = Secp256r1RecoverablePublicKey;
    type Sig = Secp256r1RecoverableSignature;
    const LENGTH: usize = Secp256r1PrivateKey::LENGTH;
}

serialize_deserialize_from_encode_decode_base64!(Secp256r1RecoverablePrivateKey);

//
// Secp256r1RecoverableKeyPair
//
impl From<Secp256r1RecoverablePrivateKey> for Secp256r1RecoverableKeyPair {
    fn from(secret: Secp256r1RecoverablePrivateKey) -> Self {
        let name = Secp256r1RecoverablePublicKey::from(&secret);
        Secp256r1RecoverableKeyPair { name, secret }
    }
}

impl Signer<Secp256r1RecoverableSignature> for Secp256r1RecoverableKeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<Secp256r1RecoverableSignature, Error> {
        // Code copied from Sign.rs in k256@0.11.6

        // Hash message
        let z = FieldBytes::from(Sha256::digest(msg).digest);

        // Private key as scalar
        let x = U256::from_be_bytes(self.secret.0.privkey.as_nonzero_scalar().to_bytes().into());

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

impl EncodeDecodeBase64 for Secp256r1RecoverableKeyPair {
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

impl FromStr for Secp256r1RecoverableKeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl KeyPair for Secp256r1RecoverableKeyPair {
    type PubKey = Secp256r1RecoverablePublicKey;
    type PrivKey = Secp256r1RecoverablePrivateKey;
    type Sig = Secp256r1RecoverableSignature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        self.secret
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256r1RecoverableKeyPair {
            name: self.name.clone(),
            secret: Secp256r1RecoverablePrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let kp = Secp256r1KeyPair::generate(rng);
        Secp256r1RecoverableKeyPair {
            name: Secp256r1RecoverablePublicKey(kp.name.clone()),
            secret: Secp256r1RecoverablePrivateKey::from_bytes(kp.secret.as_ref()).unwrap(),
        }
    }
}
