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
use std::marker::PhantomData;
use std::str::FromStr;

use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::secp256r1::Secp256r1PublicKey;
use crate::secp256r1::Secp256r1Signature;
use crate::secp256r1::SIGNATURE_SIZE;
use crate::secp256r1::{Secp256r1KeyPair, Secp256r1PrivateKey};
use crate::serde_helpers::keypair_decode_base64;
use crate::traits::{
    AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, PublicKeyDigest, RecoverableSignature,
    SigningKey, VerifyingKey,
};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    traits::ToFromBytes,
};
use fastcrypto_derive::{SilentDebug, SilentDisplay};

pub const RECOVERABLE_SIGNATURE_SIZE: usize = SIGNATURE_SIZE + 1;

/// Secp256r1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1RecoverableSignature<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> {
    pub sig: ExternalSignature,
    pub recovery_id: RecoveryId,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
    digest_type: PhantomData<D>,
}

#[readonly::make]
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Secp256r1RecoverablePublicKey<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>>(
    pub D::Digest,
);

#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256r1RecoverablePrivateKey<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>>(
    pub(crate) Secp256r1PrivateKey,
    PhantomData<D>,
);

/// Secp256r1 public/private key pair.
#[derive(Debug)]
pub struct Secp256r1RecoverableKeyPair<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> {
    pub name: Secp256r1RecoverablePublicKey<D>,
    pub secret: Secp256r1RecoverablePrivateKey<D>,
}

//
// Secp256r1RecoverablePublicKey
//
impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Display for Secp256r1RecoverablePublicKey<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0.as_ref())
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> ToFromBytes
    for Secp256r1RecoverablePublicKey<D>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256r1RecoverablePublicKey(
            D::Digest::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> AsRef<[u8]>
    for Secp256r1RecoverablePublicKey<D>
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static>
    Verifier<Secp256r1RecoverableSignature<D>> for Secp256r1RecoverablePublicKey<D>
{
    fn verify(
        &self,
        msg: &[u8],
        signature: &Secp256r1RecoverableSignature<D>,
    ) -> Result<(), Error> {
        let recovered = signature.recover(msg).map_err(|_| Error::new())?;
        if D::digest(&recovered) != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

impl<'a, D: PublicKeyDigest<BasePK = Secp256r1PublicKey>>
    From<&'a Secp256r1RecoverablePrivateKey<D>> for Secp256r1RecoverablePublicKey<D>
{
    fn from(sk: &'a Secp256r1RecoverablePrivateKey<D>) -> Self {
        Self::from(Secp256r1PublicKey::from(&sk.0))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> ::serde::Serialize
    for Secp256r1RecoverablePublicKey<D>
{
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de, Di: PublicKeyDigest<BasePK = Secp256r1PublicKey>> ::serde::Deserialize<'de>
    for Secp256r1RecoverablePublicKey<Di>
{
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::decode_base64(&s).map_err(::serde::de::Error::custom)
    }
}
impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static> VerifyingKey
    for Secp256r1RecoverablePublicKey<D>
{
    type PrivKey = Secp256r1RecoverablePrivateKey<D>;
    type Sig = Secp256r1RecoverableSignature<D>;
    const LENGTH: usize = Secp256r1PublicKey::LENGTH;
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> From<Secp256r1PublicKey>
    for Secp256r1RecoverablePublicKey<D>
{
    fn from(pk: Secp256r1PublicKey) -> Self {
        Secp256r1RecoverablePublicKey(D::digest(&pk))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Secp256r1RecoverablePublicKey<D> {
    pub fn verify_hashed(
        &self,
        hashed_msg: &[u8],
        signature: &Secp256r1RecoverableSignature<D>,
    ) -> Result<(), Error> {
        let digest: &[u8; 32] = hashed_msg.try_into().map_err(|_| Error::new())?;
        let recovered = signature.recover_hashed(digest).map_err(|_| Error::new())?;
        if D::digest(&recovered) != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

//
// Secp256r1RecoverableSignature
//
impl<'a, D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> From<&'a Secp256r1RecoverableSignature<D>>
    for Secp256r1Signature
{
    fn from(s: &'a Secp256r1RecoverableSignature<D>) -> Self {
        Secp256r1Signature {
            sig: s.clone().sig,
            bytes: OnceCell::new(), // TODO: May use the first 64 bytes of an existing serialization
        }
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Serialize
    for Secp256r1RecoverableSignature<D>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

impl<'de, Di: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Deserialize<'de>
    for Secp256r1RecoverableSignature<Di>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        <Secp256r1RecoverableSignature<Di> as Signature>::from_bytes(&data)
            .map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> TryFrom<(&Secp256r1Signature, u8)>
    for Secp256r1RecoverableSignature<D>
{
    type Error = FastCryptoError;

    fn try_from((signature, rec_id): (&Secp256r1Signature, u8)) -> Result<Self, FastCryptoError> {
        let recovery_id = RecoveryId::from_byte(rec_id).ok_or(FastCryptoError::InvalidInput)?;
        Ok(Secp256r1RecoverableSignature {
            sig: signature.sig,
            recovery_id,
            bytes: OnceCell::new(),
            digest_type: PhantomData::default(),
        })
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static> Authenticator
    for Secp256r1RecoverableSignature<D>
{
    type PubKey = Secp256r1RecoverablePublicKey<D>;
    type PrivKey = Secp256r1RecoverablePrivateKey<D>;
    const LENGTH: usize = RECOVERABLE_SIGNATURE_SIZE;
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Signature
    for Secp256r1RecoverableSignature<D>
{
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
            digest_type: PhantomData::default(),
        })
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static> RecoverableSignature
    for Secp256r1RecoverableSignature<D>
{
    type BasePubKey = Secp256r1PublicKey;

    fn recover(&self, msg: &[u8]) -> Result<Secp256r1PublicKey, FastCryptoError> {
        self.recover_hashed(&Sha256::digest(msg).digest)
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Secp256r1RecoverableSignature<D> {
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

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> AsRef<[u8]>
    for Secp256r1RecoverableSignature<D>
{
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

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> std::hash::Hash
    for Secp256r1RecoverableSignature<D>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> PartialEq
    for Secp256r1RecoverableSignature<D>
{
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Eq for Secp256r1RecoverableSignature<D> {}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Display for Secp256r1RecoverableSignature<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Default for Secp256r1RecoverableSignature<D> {
    fn default() -> Self {
        // Return the signature (1,1)
        Secp256r1RecoverableSignature {
            sig: ExternalSignature::from_scalars(Scalar::ONE.to_bytes(), Scalar::ONE.to_bytes())
                .unwrap(),
            recovery_id: RecoveryId::from_byte(0).unwrap(),
            bytes: OnceCell::new(),
            digest_type: PhantomData::default(),
        }
    }
}

//
// Secp256r1RecoverablePrivateKey
//
impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> ToFromBytes
    for Secp256r1RecoverablePrivateKey<D>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256r1RecoverablePrivateKey(
            Secp256r1PrivateKey::from_bytes(bytes)?,
            PhantomData::default(),
        ))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> AsRef<[u8]>
    for Secp256r1RecoverablePrivateKey<D>
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static> SigningKey
    for Secp256r1RecoverablePrivateKey<D>
{
    type PubKey = Secp256r1RecoverablePublicKey<D>;
    type Sig = Secp256r1RecoverableSignature<D>;
    const LENGTH: usize = Secp256r1PrivateKey::LENGTH;
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> ::serde::Serialize
    for Secp256r1RecoverablePrivateKey<D>
{
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de, Di: PublicKeyDigest<BasePK = Secp256r1PublicKey>> ::serde::Deserialize<'de>
    for Secp256r1RecoverablePrivateKey<Di>
{
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::decode_base64(&s).map_err(::serde::de::Error::custom)
    }
}
//
// Secp256r1RecoverableKeyPair
//
impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> From<Secp256r1RecoverablePrivateKey<D>>
    for Secp256r1RecoverableKeyPair<D>
{
    fn from(secret: Secp256r1RecoverablePrivateKey<D>) -> Self {
        let name = Secp256r1RecoverablePublicKey::from(&secret);
        Secp256r1RecoverableKeyPair { name, secret }
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey>> Signer<Secp256r1RecoverableSignature<D>>
    for Secp256r1RecoverableKeyPair<D>
{
    fn try_sign(&self, msg: &[u8]) -> Result<Secp256r1RecoverableSignature<D>, Error> {
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
            digest_type: PhantomData::default(),
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

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static> EncodeDecodeBase64
    for Secp256r1RecoverableKeyPair<D>
{
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

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static> FromStr
    for Secp256r1RecoverableKeyPair<D>
{
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256r1PublicKey> + 'static> KeyPair
    for Secp256r1RecoverableKeyPair<D>
{
    type PubKey = Secp256r1RecoverablePublicKey<D>;
    type PrivKey = Secp256r1RecoverablePrivateKey<D>;
    type Sig = Secp256r1RecoverableSignature<D>;

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
            name: Secp256r1RecoverablePublicKey(D::digest(&kp.name)),
            secret: Secp256r1RecoverablePrivateKey::from_bytes(kp.secret.as_ref()).unwrap(),
        }
    }
}

/// Digester used for testing which hashes the public key and returns the first 20 bytes.
#[derive(Debug, Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct TestDigester {}

#[derive(Debug, Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct TestDigest([u8; 20]);

impl AsRef<[u8]> for TestDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToFromBytes for TestDigest {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != 20 {
            return Err(FastCryptoError::InvalidInput);
        }
        let mut digest = [0u8; 20];
        digest.copy_from_slice(bytes);
        Ok(TestDigest(digest))
    }
}

impl PublicKeyDigest for TestDigester {
    type BasePK = Secp256r1PublicKey;
    type Digest = TestDigest;
    const DIGEST_SIZE: usize = 20;

    fn digest(pk: &Secp256r1PublicKey) -> TestDigest {
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&Sha256::digest(pk.as_bytes()).digest[0..20]);
        TestDigest(digest)
    }
}
