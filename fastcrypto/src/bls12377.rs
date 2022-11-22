// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [BLS signature scheme over the BLS 12-377 curve](https://en.wikipedia.org/wiki/BLS_digital_signature).
//!
//! Messages can be signed and the signature can be verified again:
//! ```rust
//! # use fastcrypto::bls12377::*;
//! # use fastcrypto::{traits::{KeyPair, Signer}, Verifier};
//! use rand::thread_rng;
//! let kp = BLS12377KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert!(kp.public().verify(message, &signature).is_ok());
//! ```

use std::{
    borrow::Borrow,
    fmt::{self, Display},
    ops::Neg,
    str::FromStr,
};

use crate::{
    encoding::{Base64, Encoding},
    pubkey_bytes::PublicKeyBytes,
    serde_helpers::keypair_decode_base64,
    traits::{AggregateAuthenticator, AllowedRng, EncodeDecodeBase64, ToFromBytes},
};
use ::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_bls12_377::{Bls12_377, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{
    bytes::{FromBytes, ToBytes},
    One, Zero,
};
use celo_bls::{hash_to_curve::try_and_increment, HashToCurve, PublicKey};
use once_cell::sync::OnceCell;
use serde::{de, Deserialize, Serialize};
use serde_with::serde_as;
use signature::{Signer, Verifier};

use crate::error::FastCryptoError;
use crate::traits::{Authenticator, KeyPair, SigningKey, VerifyingKey};
use serde_with::{DeserializeAs, SerializeAs};
use zeroize::Zeroize;

// Arkworks is serde-unfriendly, hence this workaround, see https://github.com/arkworks-rs/algebra/issues/178
struct SerdeAs;

impl<T> SerializeAs<T> for SerdeAs
where
    T: CanonicalSerialize,
{
    fn serialize_as<S>(val: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        val.serialize(&mut bytes)
            .map_err(serde::ser::Error::custom)?;

        serde_with::Bytes::serialize_as(&bytes, serializer)
    }
}

impl<'de, T> DeserializeAs<'de, T> for SerdeAs
where
    T: CanonicalDeserialize,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        T::deserialize(&mut &bytes[..]).map_err(serde::de::Error::custom)
    }
}

struct RngWrapper<'a, R: AllowedRng>(pub &'a mut R);

impl<R: AllowedRng> rand::RngCore for RngWrapper<'_, R> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    // The feature disjunction is because celo's bls-crypto fails to activate ark-std/std
    #[cfg(feature = "std")]
    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        #[cfg(feature = "celo")]
        self.0
            .try_fill_bytes(dest)
            .map_err(|e| ark_std::rand::Error::new(e.take_inner()))
    }

    #[cfg(not(feature = "std"))]
    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0
            .try_fill_bytes(dest)
            .map_err(|_| ark_std::rand::Error::from(std::num::NonZeroU32::new(1).unwrap()))
    }
}

/// Length of a private key in bytes.
pub const CELO_BLS_PRIVATE_KEY_LENGTH: usize = 32;

/// Length of a public key in bytes.
pub const CELO_BLS_PUBLIC_KEY_LENGTH: usize = 96;

/// Length of a signature in bytes.
pub const CELO_BLS_SIGNATURE_LENGTH: usize = 48;

///
/// Define Structs
///

/// BLS 12-377 public key.
#[derive(Debug, Clone)]
pub struct BLS12377PublicKey {
    pub pubkey: PublicKey,
    pub bytes: OnceCell<[u8; CELO_BLS_PUBLIC_KEY_LENGTH]>,
}

/// Binary representation of an instance of an [BLS12377PublicKey].
pub type BLS12377PublicKeyBytes = PublicKeyBytes<BLS12377PublicKey, { BLS12377PublicKey::LENGTH }>;

/// BLS 12-377 private key.
#[readonly::make]
#[derive(Debug)]
pub struct BLS12377PrivateKey {
    pub privkey: celo_bls::PrivateKey,
    pub bytes: OnceCell<[u8; CELO_BLS_PRIVATE_KEY_LENGTH]>,
}

// There is a strong requirement for this specific impl. in Fab benchmarks
/// BLS 12-377 public/private keypair.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")] // necessary so as not to deser under a != type
pub struct BLS12377KeyPair {
    name: BLS12377PublicKey,
    secret: BLS12377PrivateKey,
}

/// BLS 12-377 signature.
#[readonly::make]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLS12377Signature {
    #[serde_as(as = "SerdeAs")]
    pub sig: celo_bls::Signature,
    #[serde(skip)]
    #[serde(default = "OnceCell::new")]
    pub bytes: OnceCell<[u8; CELO_BLS_SIGNATURE_LENGTH]>,
}

/// Aggregation of multiple BLS 12-377 signatures.
#[readonly::make]
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLS12377AggregateSignature {
    #[serde_as(as = "SerdeAs")]
    pub sig: Option<celo_bls::Signature>,
    #[serde(skip)]
    #[serde(default = "OnceCell::new")]
    pub bytes: OnceCell<[u8; CELO_BLS_SIGNATURE_LENGTH]>,
}

///
/// Implement Authenticator
///

impl signature::Signature for BLS12377Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        let g1 = <G1Affine as CanonicalDeserialize>::deserialize(bytes)
            .map_err(|_| signature::Error::new())?;
        Ok(BLS12377Signature {
            sig: g1.into_projective().into(),
            bytes: OnceCell::new(),
        })
    }
}
// see [#34](https://github.com/MystenLabs/narwhal/issues/34)
impl Default for BLS12377Signature {
    fn default() -> Self {
        let g1 = G1Projective::zero();
        BLS12377Signature {
            sig: g1.into(),
            bytes: OnceCell::new(),
        }
    }
}

impl AsRef<[u8]> for BLS12377Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let mut bytes = [0u8; CELO_BLS_SIGNATURE_LENGTH];
                self.sig.as_ref().into_affine().serialize(&mut bytes[..])?;
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

impl Display for BLS12377Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl PartialEq for BLS12377Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for BLS12377Signature {}

impl Authenticator for BLS12377Signature {
    type PubKey = BLS12377PublicKey;
    type PrivKey = BLS12377PrivateKey;
    const LENGTH: usize = CELO_BLS_SIGNATURE_LENGTH;
}

///
/// Implement VerifyingKey
///

impl Default for BLS12377PublicKey {
    // eprint.iacr.org/2021/323 should incite us to remove our usage of Default,
    // see https://github.com/MystenLabs/narwhal/issues/34
    fn default() -> Self {
        let public: PublicKey = G2Projective::zero().into();
        BLS12377PublicKey {
            pubkey: public,
            bytes: OnceCell::new(),
        }
    }
}

impl std::hash::Hash for BLS12377PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pubkey.hash(state);
    }
}

impl PartialEq for BLS12377PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.pubkey == other.pubkey
    }
}

impl Eq for BLS12377PublicKey {}

impl AsRef<[u8]> for BLS12377PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let mut bytes = [0u8; CELO_BLS_PUBLIC_KEY_LENGTH];
                self.pubkey
                    .as_ref()
                    .into_affine()
                    .serialize(&mut bytes[..])
                    .unwrap();
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

impl PartialOrd for BLS12377PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for BLS12377PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl ToFromBytes for BLS12377PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::FastCryptoError> {
        let g2 = <G2Affine as CanonicalDeserialize>::deserialize(bytes)
            .map_err(|_| crate::error::FastCryptoError::InvalidInput)?
            .into_projective();
        Ok(BLS12377PublicKey {
            pubkey: g2.into(),
            bytes: OnceCell::new(),
        })
    }
}

impl Display for BLS12377PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for BLS12377PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for BLS12377PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Verifier<BLS12377Signature> for BLS12377PublicKey {
    fn verify(&self, msg: &[u8], signature: &BLS12377Signature) -> Result<(), signature::Error> {
        let hash_to_g1 = &*celo_bls::hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1;

        self.pubkey
            .verify(msg, &[], &signature.sig, hash_to_g1)
            .map_err(|_| signature::Error::new())
    }
}

impl<'a> From<&'a BLS12377PrivateKey> for BLS12377PublicKey {
    fn from(secret: &'a BLS12377PrivateKey) -> Self {
        let inner = &secret.privkey;
        BLS12377PublicKey {
            pubkey: inner.to_public(),
            bytes: OnceCell::new(),
        }
    }
}

impl VerifyingKey for BLS12377PublicKey {
    type PrivKey = BLS12377PrivateKey;
    type Sig = BLS12377Signature;
    const LENGTH: usize = CELO_BLS_PUBLIC_KEY_LENGTH;

    fn verify_batch_empty_fail(
        msg: &[u8],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), FastCryptoError> {
        if sigs.is_empty() {
            return Err(FastCryptoError::InvalidInput);
        }
        if sigs.len() != pks.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let mut batch = celo_bls::bls::Batch::new(msg, &[]);
        pks.iter()
            .zip(sigs)
            .for_each(|(pk, sig)| batch.add(pk.pubkey.clone(), sig.sig.clone()));
        let hash_to_g1 = &*try_and_increment::COMPOSITE_HASH_TO_G1;
        batch
            .verify(hash_to_g1)
            .map_err(|_| FastCryptoError::GeneralError)
    }
}

///
/// Implement SigningKey
///

impl AsRef<[u8]> for BLS12377PrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                let mut bytes = [0u8; CELO_BLS_PRIVATE_KEY_LENGTH];
                self.privkey.as_ref().write(&mut bytes[..])?;
                Ok(bytes)
            })
            .expect("OnceCell invariant violated")
    }
}

impl ToFromBytes for BLS12377PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::FastCryptoError> {
        let fr = <Fr as FromBytes>::read(bytes)
            .map_err(|_| crate::error::FastCryptoError::InvalidInput)?;
        Ok(BLS12377PrivateKey {
            privkey: fr.into(),
            bytes: OnceCell::new(),
        })
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for BLS12377PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for BLS12377PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl SigningKey for BLS12377PrivateKey {
    type PubKey = BLS12377PublicKey;
    type Sig = BLS12377Signature;
    const LENGTH: usize = CELO_BLS_PRIVATE_KEY_LENGTH;
}

impl Signer<BLS12377Signature> for BLS12377PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<BLS12377Signature, signature::Error> {
        let hash_to_g1 = &*try_and_increment::COMPOSITE_HASH_TO_G1;

        let celo_bls_sig = self
            .privkey
            .sign(msg, &[], hash_to_g1)
            .map_err(|_| signature::Error::new())?;

        Ok(BLS12377Signature {
            sig: celo_bls_sig,
            bytes: OnceCell::new(),
        })
    }
}

///
/// Implement KeyPair
///

impl From<BLS12377PrivateKey> for BLS12377KeyPair {
    fn from(secret: BLS12377PrivateKey) -> Self {
        let name = BLS12377PublicKey::from(&secret);
        BLS12377KeyPair { name, secret }
    }
}

impl EncodeDecodeBase64 for BLS12377KeyPair {
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

impl KeyPair for BLS12377KeyPair {
    type PubKey = BLS12377PublicKey;
    type PrivKey = BLS12377PrivateKey;
    type Sig = BLS12377Signature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        BLS12377PrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        BLS12377KeyPair {
            name: self.name.clone(),
            secret: BLS12377PrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let celo_privkey = celo_bls::PrivateKey::generate(&mut RngWrapper(rng));
        let celo_pubkey = PublicKey::from(&celo_privkey);
        BLS12377KeyPair {
            name: BLS12377PublicKey {
                pubkey: celo_pubkey,
                bytes: OnceCell::new(),
            },
            secret: BLS12377PrivateKey {
                privkey: celo_privkey,
                bytes: OnceCell::new(),
            },
        }
    }
}

impl Signer<BLS12377Signature> for BLS12377KeyPair {
    fn try_sign(&self, msg: &[u8]) -> Result<BLS12377Signature, signature::Error> {
        let hash_to_g1 = &*try_and_increment::COMPOSITE_HASH_TO_G1;

        let celo_bls_sig = self
            .secret
            .privkey
            .sign(msg, &[], hash_to_g1)
            .map_err(|_| signature::Error::new())?;

        Ok(BLS12377Signature {
            sig: celo_bls_sig,
            bytes: OnceCell::new(),
        })
    }
}

impl FromStr for BLS12377KeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

///
/// Implement AggregateAuthenticator
///

impl AsRef<[u8]> for BLS12377AggregateSignature {
    fn as_ref(&self) -> &[u8] {
        match &self.sig {
            Some(sig) => self
                .bytes
                .get_or_try_init::<_, eyre::Report>(|| {
                    let mut bytes = [0u8; CELO_BLS_SIGNATURE_LENGTH];
                    sig.as_ref().into_affine().serialize(&mut bytes[..])?;
                    Ok(bytes)
                })
                .expect("OnceCell invariant violated"),
            None => &[],
        }
    }
}

impl Display for BLS12377AggregateSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

// see [#34](https://github.com/MystenLabs/narwhal/issues/34)
impl Default for BLS12377AggregateSignature {
    fn default() -> Self {
        BLS12377AggregateSignature {
            sig: None,
            bytes: OnceCell::new(),
        }
    }
}

impl AggregateAuthenticator for BLS12377AggregateSignature {
    type Sig = BLS12377Signature;
    type PubKey = BLS12377PublicKey;
    type PrivKey = BLS12377PrivateKey;

    /// Parse a key from its byte representation
    fn aggregate<'a, K: Borrow<Self::Sig> + 'a, I: IntoIterator<Item = &'a K>>(
        signatures: I,
    ) -> Result<Self, crate::error::FastCryptoError> {
        let sig = celo_bls::Signature::aggregate(signatures.into_iter().map(|x| &x.borrow().sig));
        Ok(BLS12377AggregateSignature {
            sig: Some(sig),
            bytes: OnceCell::new(),
        })
    }

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), crate::error::FastCryptoError> {
        match self.sig {
            Some(ref mut sig) => {
                let raw_sig = celo_bls::Signature::aggregate([signature.sig, sig.clone()]);
                self.sig = Some(raw_sig);
                Ok(())
            }
            None => {
                self.sig = Some(signature.sig);
                Ok(())
            }
        }
    }

    fn add_aggregate(&mut self, signature: Self) -> Result<(), crate::error::FastCryptoError> {
        match self.sig {
            Some(ref mut sig) => match signature.sig {
                Some(sig_to_add) => {
                    let raw_sig = celo_bls::Signature::aggregate([sig_to_add, sig.clone()]);
                    self.sig = Some(raw_sig);
                    Ok(())
                }
                None => Ok(()),
            },
            None => {
                self.sig = signature.sig;
                Ok(())
            }
        }
    }

    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        message: &[u8],
    ) -> Result<(), crate::error::FastCryptoError> {
        let mut cache = celo_bls::PublicKeyCache::new();
        let apk = cache.aggregate(pks.iter().map(|pk| pk.pubkey.clone()).collect());
        apk.verify(
            message,
            &[],
            self.sig
                .as_ref()
                .ok_or(crate::error::FastCryptoError::GeneralError)?,
            &*try_and_increment::COMPOSITE_HASH_TO_G1,
        )
        .map_err(|_| crate::error::FastCryptoError::GeneralError)
    }

    fn batch_verify<'a>(
        signatures: &[&Self],
        pks: Vec<impl Iterator<Item = &'a Self::PubKey>>,
        messages: &[&[u8]],
    ) -> Result<(), crate::error::FastCryptoError> {
        if pks.len() != messages.len() || messages.len() != signatures.len() {
            return Err(crate::error::FastCryptoError::InputLengthWrong(
                signatures.len(),
            ));
        }
        let mut pk_iter = pks.into_iter();
        for i in 0..signatures.len() {
            let sig = signatures[i].sig.clone();
            let mut cache = celo_bls::PublicKeyCache::new();
            let apk = cache.aggregate(
                pk_iter
                    .next()
                    .unwrap()
                    .map(|pk| pk.pubkey.clone())
                    .collect(),
            );
            apk.verify(
                messages[i],
                &[],
                &sig.ok_or(crate::error::FastCryptoError::GeneralError)?,
                &*try_and_increment::COMPOSITE_HASH_TO_G1,
            )
            .map_err(|_| crate::error::FastCryptoError::GeneralError)?;
        }
        Ok(())
    }

    fn verify_different_msg(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        messages: &[&[u8]],
    ) -> Result<(), crate::error::FastCryptoError> {
        if pks.len() != messages.len() {
            return Err(crate::error::FastCryptoError::InputLengthWrong(
                messages.len(),
            ));
        }

        // TODO: The ark-bls12-377 create doesn't have a good function to verify aggregate signatures over different messages,
        // but if it eventually does expose such a function, we should use that instead of the implementation below.
        let mut pairs: Vec<_> = pks
            .iter()
            .zip(messages)
            .map(|(pk, m)| {
                (
                    try_and_increment::COMPOSITE_HASH_TO_G1
                        .hash(celo_bls::SIG_DOMAIN, m, &[])
                        .unwrap()
                        .into_affine()
                        .into(),
                    pk.pubkey.as_ref().into_affine().into(),
                )
            })
            .collect();
        pairs.push((
            G1Projective::into_affine(self.sig.as_ref().unwrap().as_ref()).into(),
            G2Affine::prime_subgroup_generator().neg().into(),
        ));
        let pairing = Bls12_377::product_of_pairings(&pairs);

        if Fq12::is_one(&pairing) {
            Ok(())
        } else {
            Err(crate::error::FastCryptoError::GeneralError)
        }
    }
}

///
/// Implement VerifyingKeyBytes
///

impl TryFrom<BLS12377PublicKeyBytes> for BLS12377PublicKey {
    type Error = signature::Error;

    fn try_from(bytes: BLS12377PublicKeyBytes) -> Result<BLS12377PublicKey, Self::Error> {
        BLS12377PublicKey::from_bytes(bytes.as_ref()).map_err(|_| Self::Error::new())
    }
}

impl From<&BLS12377PublicKey> for BLS12377PublicKeyBytes {
    fn from(pk: &BLS12377PublicKey) -> Self {
        BLS12377PublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}

impl zeroize::Zeroize for BLS12377PrivateKey {
    fn zeroize(&mut self) {
        // PrivateKey.zeroize here is not necessary here because the underlying implicitly zeroizes.
        self.bytes.take().zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for BLS12377PrivateKey {}

impl Drop for BLS12377PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl zeroize::Zeroize for BLS12377KeyPair {
    fn zeroize(&mut self) {
        self.secret.zeroize()
    }
}

impl zeroize::ZeroizeOnDrop for BLS12377KeyPair {}

impl Drop for BLS12377KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "experimental")]
pub mod mskr {
    //
    // Implement MSKR for BLS12377
    //
    use crate::bls12377::{
        BLS12377KeyPair, BLS12377PrivateKey, BLS12377PublicKey, BLS12377Signature,
        CELO_BLS_PUBLIC_KEY_LENGTH,
    };
    use crate::hash::HashFunction;
    use crate::hash::Sha256;
    use crate::traits::mskr::{HashToScalar, Randomize};
    use ark_bls12_377::{Fr, G1Projective, G2Projective};
    use ark_ec::group::Group;
    use ark_ff::BigInteger256;
    use celo_bls::{PrivateKey, PublicKey};
    use once_cell::sync::OnceCell;
    use std::ops::Mul;

    pub struct BLS12377Hash {}

    impl HashToScalar<Fr> for BLS12377Hash {
        fn hash_to_scalar(bytes: &[u8]) -> Fr {
            let digest = Sha256::digest(bytes);
            let mut last_word: [u8; 8] = digest.digest[24..32].try_into().unwrap();
            last_word[7] = 0; // Scalars in Fr are at most 253 bits
            Fr::from(BigInteger256::new([
                u64::from_le_bytes(digest.digest[0..8].try_into().unwrap()),
                u64::from_le_bytes(digest.digest[8..16].try_into().unwrap()),
                u64::from_le_bytes(digest.digest[16..24].try_into().unwrap()),
                u64::from_le_bytes(last_word),
            ]))
        }
    }

    impl Randomize<BLS12377PublicKey, Fr, BLS12377Hash, CELO_BLS_PUBLIC_KEY_LENGTH>
        for BLS12377PublicKey
    {
        /// Randomize the public key using the input list of public keys.
        fn randomize_internal(&self, r: &Fr) -> BLS12377PublicKey {
            let pt: &G2Projective = self.pubkey.as_ref();
            let q = pt.mul(r);
            BLS12377PublicKey {
                pubkey: PublicKey::from(q),
                bytes: OnceCell::new(),
            }
        }
    }

    impl Randomize<BLS12377PublicKey, Fr, BLS12377Hash, CELO_BLS_PUBLIC_KEY_LENGTH>
        for BLS12377PrivateKey
    {
        /// Randomize the secret key using the input list of public keys.
        fn randomize_internal(&self, r: &Fr) -> BLS12377PrivateKey {
            let sk = self.privkey.as_ref().mul(r);
            BLS12377PrivateKey {
                privkey: PrivateKey::from(sk),
                bytes: OnceCell::new(),
            }
        }
    }

    impl Randomize<BLS12377PublicKey, Fr, BLS12377Hash, CELO_BLS_PUBLIC_KEY_LENGTH>
        for BLS12377KeyPair
    {
        /// Randomize a key pair using the input list of public keys.
        fn randomize_internal(&self, r: &Fr) -> BLS12377KeyPair {
            BLS12377KeyPair {
                secret: self.secret.randomize_internal(r),
                name: self.name.randomize_internal(r),
            }
        }
    }

    impl Randomize<BLS12377PublicKey, Fr, BLS12377Hash, CELO_BLS_PUBLIC_KEY_LENGTH>
        for BLS12377Signature
    {
        /// Randomize a signature using the input list of public keys.
        fn randomize_internal(&self, r: &Fr) -> BLS12377Signature {
            let pt: &G1Projective = self.sig.as_ref();
            let q = pt.mul(r);
            BLS12377Signature {
                sig: celo_bls::Signature::from(q),
                bytes: OnceCell::new(),
            }
        }
    }
}
