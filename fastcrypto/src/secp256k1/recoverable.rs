// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use crate::hash::HashFunction;
use crate::hash::Sha256;
use crate::pubkey_bytes::PublicKeyBytes;
use crate::secp256k1::{
    Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature,
};
use crate::secp256r1::PRIVATE_KEY_SIZE;
use crate::serde_helpers::keypair_decode_base64;
use crate::traits::{
    AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, PublicKeyDigest, RecoverableSignature,
    SigningKey, ToFromBytes, VerifyingKey,
};
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::OnceCell;
use rust_secp256k1::ecdsa::{RecoverableSignature as ExternalRecoverableSignature, RecoveryId};
use rust_secp256k1::hashes::sha256;
use rust_secp256k1::{constants, Message, Secp256k1};
use serde::{de, Deserialize, Serialize};
use signature::{Error, Signature, Signer, Verifier};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::str::FromStr;

pub const RECOVERABLE_SIGNATURE_SIZE: usize = constants::COMPACT_SIGNATURE_SIZE + 1;

/// Secp256k1 ecdsa "public key" for recoverable signatures.
#[readonly::make]
#[derive(Default, Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Secp256k1RecoverablePublicKey<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>>(
    pub D::Digest,
);

/// Binary representation of an instance of [Secp256k1RecoverablePublicKey]. Note that the [LENGTH] must
/// be equal to the length of the digests produced by [D].
pub type Secp256k1RecoverablePublicKeyBytes<D, const LENGTH: usize> =
    PublicKeyBytes<Secp256k1RecoverablePublicKey<D>, LENGTH>;

/// Secp256k1 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256k1RecoverablePrivateKey<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>>(
    pub(crate) Secp256k1PrivateKey,
    PhantomData<D>,
);

/// Secp256k1 ecdsa recoverable signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256k1RecoverableSignature<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> {
    pub sig: ExternalRecoverableSignature,
    pub bytes: OnceCell<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
    pub digest_type: PhantomData<D>,
}

/// Secp256k1 public/private key pair.
#[derive(Debug)]
pub struct Secp256k1RecoverableKeyPair<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> {
    pub name: Secp256k1RecoverablePublicKey<D>,
    pub secret: Secp256k1RecoverablePrivateKey<D>,
}

//
// Secp256k1RecoverablePublicKey
//
impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Display for Secp256k1RecoverablePublicKey<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0.as_ref())
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> ToFromBytes
    for Secp256k1RecoverablePublicKey<D>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256k1RecoverablePublicKey(
            D::Digest::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)?,
        ))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> AsRef<[u8]>
    for Secp256k1RecoverablePublicKey<D>
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static>
    Verifier<Secp256k1RecoverableSignature<D>> for Secp256k1RecoverablePublicKey<D>
{
    fn verify(
        &self,
        msg: &[u8],
        signature: &Secp256k1RecoverableSignature<D>,
    ) -> Result<(), Error> {
        let recovered = signature.recover(msg).map_err(|_| Error::new())?;
        if D::digest(&recovered) != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

impl<'a, D: PublicKeyDigest<BasePK = Secp256k1PublicKey>>
    From<&'a Secp256k1RecoverablePrivateKey<D>> for Secp256k1RecoverablePublicKey<D>
{
    fn from(sk: &'a Secp256k1RecoverablePrivateKey<D>) -> Self {
        Self::from(Secp256k1PublicKey::from(&sk.0))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> From<Secp256k1PublicKey>
    for Secp256k1RecoverablePublicKey<D>
{
    fn from(pk: Secp256k1PublicKey) -> Self {
        Secp256k1RecoverablePublicKey(D::digest(&pk))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static> VerifyingKey
    for Secp256k1RecoverablePublicKey<D>
{
    type PrivKey = Secp256k1RecoverablePrivateKey<D>;
    type Sig = Secp256k1RecoverableSignature<D>;
    const LENGTH: usize = D::DIGEST_SIZE;
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> ::serde::Serialize
    for Secp256k1RecoverablePublicKey<D>
{
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de, Di: PublicKeyDigest<BasePK = Secp256k1PublicKey>> ::serde::Deserialize<'de>
    for Secp256k1RecoverablePublicKey<Di>
{
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::decode_base64(&s).map_err(::serde::de::Error::custom)
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Secp256k1RecoverablePublicKey<D> {
    pub fn verify_hashed(
        &self,
        hashed_msg: &[u8],
        signature: &Secp256k1RecoverableSignature<D>,
    ) -> Result<(), signature::Error> {
        let message = Message::from_slice(hashed_msg).map_err(|_| signature::Error::new())?;
        let recovered = signature
            .recover_hashed(message.as_ref())
            .map_err(|_| Error::new())?;
        if D::digest(&recovered) != self.0 {
            return Err(Error::new());
        }
        Ok(())
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static, const L: usize>
    TryFrom<Secp256k1RecoverablePublicKeyBytes<D, L>> for Secp256k1RecoverablePublicKey<D>
{
    type Error = signature::Error;

    fn try_from(
        bytes: Secp256k1RecoverablePublicKeyBytes<D, L>,
    ) -> Result<Secp256k1RecoverablePublicKey<D>, Self::Error> {
        Secp256k1RecoverablePublicKey::from_bytes(bytes.as_ref()).map_err(|_| Self::Error::new())
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static, const L: usize>
    From<&Secp256k1RecoverablePublicKey<D>> for Secp256k1RecoverablePublicKeyBytes<D, L>
{
    fn from(pk: &Secp256k1RecoverablePublicKey<D>) -> Self {
        Secp256k1RecoverablePublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

//
// Secp256k1RecoverableSignature
//
impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> TryFrom<(&Secp256k1Signature, u8)>
    for Secp256k1RecoverableSignature<D>
{
    type Error = FastCryptoError;
    fn try_from((signature, rec_id): (&Secp256k1Signature, u8)) -> Result<Self, FastCryptoError> {
        let recovery_id =
            RecoveryId::from_i32(rec_id as i32).map_err(|_| FastCryptoError::InvalidInput)?;
        let sig = ExternalRecoverableSignature::from_compact(signature.as_ref(), recovery_id)
            .map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Secp256k1RecoverableSignature {
            sig,
            bytes: OnceCell::new(),
            digest_type: PhantomData::default(),
        })
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Serialize
    for Secp256k1RecoverableSignature<D>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_ref().serialize(serializer)
    }
}

impl<'de, Di: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Deserialize<'de>
    for Secp256k1RecoverableSignature<Di>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data: Vec<u8> = Vec::deserialize(deserializer)?;
        <Secp256k1RecoverableSignature<Di> as Signature>::from_bytes(&data)
            .map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl<'a, D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> From<&'a Secp256k1RecoverableSignature<D>>
    for Secp256k1Signature
{
    fn from(s: &'a Secp256k1RecoverableSignature<D>) -> Self {
        Secp256k1Signature {
            sig: s.sig.to_standard(),
            bytes: OnceCell::new(), // TODO: May use the first 64 bytes of an existing serialization
        }
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Signature
    for Secp256k1RecoverableSignature<D>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 65 {
            return Err(signature::Error::new());
        }
        RecoveryId::from_i32(bytes[64] as i32)
            .and_then(|rec_id| {
                ExternalRecoverableSignature::from_compact(&bytes[..64], rec_id).map(|sig| {
                    Secp256k1RecoverableSignature {
                        sig,
                        bytes: OnceCell::new(),
                        digest_type: PhantomData::default(),
                    }
                })
            })
            .map_err(|_| signature::Error::new())
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static> Authenticator
    for Secp256k1RecoverableSignature<D>
{
    type PubKey = Secp256k1RecoverablePublicKey<D>;
    type PrivKey = Secp256k1RecoverablePrivateKey<D>;
    const LENGTH: usize = RECOVERABLE_SIGNATURE_SIZE;
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static> RecoverableSignature
    for Secp256k1RecoverableSignature<D>
{
    type BasePubKey = Secp256k1PublicKey;

    fn recover(&self, msg: &[u8]) -> Result<Secp256k1PublicKey, FastCryptoError> {
        match self
            .sig
            .recover(&Message::from_hashed_data::<sha256::Hash>(msg))
        {
            Ok(pubkey) => Secp256k1PublicKey::from_bytes(pubkey.serialize().as_slice()),
            Err(_) => Err(FastCryptoError::GeneralError),
        }
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Secp256k1RecoverableSignature<D> {
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

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> AsRef<[u8]>
    for Secp256k1RecoverableSignature<D>
{
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

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Hash for Secp256k1RecoverableSignature<D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Display for Secp256k1RecoverableSignature<D> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Default for Secp256k1RecoverableSignature<D> {
    fn default() -> Self {
        <Secp256k1RecoverableSignature<D> as Signature>::from_bytes(
            &[1u8; RECOVERABLE_SIGNATURE_SIZE],
        )
        .unwrap()
    }
}

//
// Secp256k1RecoverablePrivateKey
//
impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> ToFromBytes
    for Secp256k1RecoverablePrivateKey<D>
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(Secp256k1RecoverablePrivateKey(
            Secp256k1PrivateKey::from_bytes(bytes)?,
            PhantomData::default(),
        ))
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> AsRef<[u8]>
    for Secp256k1RecoverablePrivateKey<D>
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static> SigningKey
    for Secp256k1RecoverablePrivateKey<D>
{
    type PubKey = Secp256k1RecoverablePublicKey<D>;
    type Sig = Secp256k1RecoverableSignature<D>;
    const LENGTH: usize = PRIVATE_KEY_SIZE;
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> ::serde::Serialize
    for Secp256k1RecoverablePrivateKey<D>
{
    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de, Di: PublicKeyDigest<BasePK = Secp256k1PublicKey>> ::serde::Deserialize<'de>
    for Secp256k1RecoverablePrivateKey<Di>
{
    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::decode_base64(&s).map_err(::serde::de::Error::custom)
    }
}

//
// Secp256k1KeyPair
//
// impl Secp256k1KeyPair {
//     // This test is used in the proptest because the k256 lib uses keccak256 as hash function.
//     #[cfg(test)]
//     pub fn try_sign_as_recoverable_keccak256(
//         &self,
//         msg: &[u8],
//     ) -> Result<Secp256k1RecoverableSignature<D>, signature::Error> {
//         let secp = Secp256k1::signing_only();
//
//         let message =
//             rust_secp256k1::Message::from_slice(Keccak256::digest(msg).digest.as_ref()).unwrap();
//
//         // Creates a 65-bytes signature of shape [r, s, v] where v can be 0 or 1.
//         // Pseudo-random deterministic nonce generation is used according to RFC6979.
//         Ok(Secp256k1RecoverableSignature {
//             sig: secp.sign_ecdsa_recoverable(&message, &self.secret.privkey),
//             bytes: OnceCell::new(),
//         })
//     }
// }

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> From<Secp256k1RecoverablePrivateKey<D>>
    for Secp256k1RecoverableKeyPair<D>
{
    fn from(secret: Secp256k1RecoverablePrivateKey<D>) -> Self {
        let name = Secp256k1RecoverablePublicKey::from(&secret);
        Secp256k1RecoverableKeyPair { name, secret }
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> Signer<Secp256k1RecoverableSignature<D>>
    for Secp256k1RecoverableKeyPair<D>
{
    fn try_sign(&self, msg: &[u8]) -> Result<Secp256k1RecoverableSignature<D>, Error> {
        let secp = Secp256k1::signing_only();

        let message = Message::from_hashed_data::<sha256::Hash>(msg);

        // Creates a 65-bytes signature of shape [r, s, v] where v can be 0 or 1.
        // Pseudo-random deterministic nonce generation is used according to RFC6979.
        Ok(Secp256k1RecoverableSignature {
            sig: secp.sign_ecdsa_recoverable(&message, &self.secret.0.privkey),
            bytes: OnceCell::new(),
            digest_type: PhantomData::default(),
        })
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static> EncodeDecodeBase64
    for Secp256k1RecoverableKeyPair<D>
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

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static> FromStr
    for Secp256k1RecoverableKeyPair<D>
{
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey>> From<Secp256k1KeyPair>
    for Secp256k1RecoverableKeyPair<D>
{
    fn from(kp: Secp256k1KeyPair) -> Self {
        Secp256k1RecoverableKeyPair {
            name: Secp256k1RecoverablePublicKey::<D>::from(kp.name.clone()),
            secret: Secp256k1RecoverablePrivateKey::<D>::from_bytes(kp.secret.as_ref()).unwrap(),
        }
    }
}

impl<D: PublicKeyDigest<BasePK = Secp256k1PublicKey> + 'static> KeyPair
    for Secp256k1RecoverableKeyPair<D>
{
    type PubKey = Secp256k1RecoverablePublicKey<D>;
    type PrivKey = Secp256k1RecoverablePrivateKey<D>;
    type Sig = Secp256k1RecoverableSignature<D>;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        self.secret
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256k1RecoverableKeyPair {
            name: self.name.clone(),
            secret: Secp256k1RecoverablePrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let kp = Secp256k1KeyPair::generate(rng);
        Secp256k1RecoverableKeyPair::from(kp)
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
    type BasePK = Secp256k1PublicKey;
    type Digest = TestDigest;
    const DIGEST_SIZE: usize = 20;

    fn digest(pk: &Secp256k1PublicKey) -> TestDigest {
        let mut digest = [0u8; 20];
        digest.copy_from_slice(&Sha256::digest(pk.pubkey.serialize()).digest[0..20]);
        TestDigest(digest)
    }
}
