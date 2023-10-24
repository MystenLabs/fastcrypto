// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) signature scheme.
//!
//! Messages can be signed and the signature can be verified again:
//! ```rust
//! # use fastcrypto::ed25519::*;
//! # use fastcrypto::{traits::{KeyPair, Signer, VerifyingKey}};
//! use rand::thread_rng;
//! let kp = Ed25519KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert!(kp.public().verify(message, &signature).is_ok());
//! ```
use crate::serde_helpers::{to_custom_error, BytesRepresentation};
use crate::traits::{InsecureDefault, Signer};
use crate::{
    encoding::Base64,
    error::FastCryptoError,
    impl_base64_display_fmt,
    traits::{
        AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
        VerifyingKey,
    },
};
use crate::{
    encoding::Encoding, generate_bytes_representation, serialize_deserialize_with_to_from_bytes,
    traits,
};
use base64ct::Encoding as _;
use derive_more::AsRef;
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, Bytes as SerdeBytes, DeserializeAs, SerializeAs};

use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};
use zeroize::ZeroizeOnDrop;

#[cfg(any(test, feature = "experimental"))]
use crate::traits::AggregateAuthenticator;
#[cfg(any(test, feature = "experimental"))]
use ed25519_consensus::{batch, VerificationKeyBytes};
#[cfg(any(test, feature = "experimental"))]
use eyre::eyre;
#[cfg(any(test, feature = "experimental"))]
use signature::rand_core::OsRng;
#[cfg(any(test, feature = "experimental"))]
use std::borrow::Borrow;

/// The length of a private key in bytes.
pub const ED25519_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of a public key in bytes.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// The length of a signature in bytes.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// The key pair bytes length is the same as the private key length. This enforces deserialization to always derive the public key from the private key.
pub const ED25519_KEYPAIR_LENGTH: usize = ED25519_PRIVATE_KEY_LENGTH;

/// Ed25519 public key.
#[derive(Clone, PartialEq, Eq, AsRef)]
#[as_ref(forward)]
pub struct Ed25519PublicKey(pub ed25519_consensus::VerificationKey);

/// Ed25519 private key.
#[derive(SilentDebug, SilentDisplay, AsRef, ZeroizeOnDrop)]
#[as_ref(forward)]
pub struct Ed25519PrivateKey(pub ed25519_consensus::SigningKey);

/// Ed25519 key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519KeyPair {
    public: Ed25519PublicKey,
    private: Ed25519PrivateKey,
}

/// Ed25519 signature.
#[derive(Debug, Clone)]
pub struct Ed25519Signature {
    pub sig: ed25519_consensus::Signature,
    // Helps implementing AsRef<[u8]>.
    pub bytes: OnceCell<[u8; ED25519_SIGNATURE_LENGTH]>,
}

/// Aggregation of multiple Ed25519 signatures.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ed25519AggregateSignature {
    // The serialized form of this field includes a length prefix, whereas the as_ref() does not.
    // (The length prefix is small compared to the vector of signatures.)
    #[serde_as(as = "Vec<SingleSignature>")]
    pub sigs: Vec<ed25519_consensus::Signature>,
    // Helps implementing AsRef<[u8]>.
    #[serde(skip)]
    pub bytes: OnceCell<Vec<u8>>,
}

//
// Implementation of [Ed25519PrivateKey].
//

impl PartialEq for Ed25519PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Ed25519PrivateKey {}

impl SigningKey for Ed25519PrivateKey {
    type PubKey = Ed25519PublicKey;
    type Sig = Ed25519Signature;
    const LENGTH: usize = ED25519_PRIVATE_KEY_LENGTH;
}

impl ToFromBytes for Ed25519PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        ed25519_consensus::SigningKey::try_from(bytes)
            .map(Ed25519PrivateKey)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

serialize_deserialize_with_to_from_bytes!(Ed25519PrivateKey, ED25519_PRIVATE_KEY_LENGTH);

//
// Implementation of [Ed25519KeyPair].
//

impl From<Ed25519PrivateKey> for Ed25519KeyPair {
    fn from(private: Ed25519PrivateKey) -> Self {
        let public = Ed25519PublicKey::from(&private);
        Ed25519KeyPair { public, private }
    }
}

/// The bytes form of the keypair always only contain the private key bytes
impl ToFromBytes for Ed25519KeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ed25519PrivateKey::from_bytes(bytes).map(|private| private.into())
    }
}

impl AsRef<[u8]> for Ed25519KeyPair {
    fn as_ref(&self) -> &[u8] {
        self.private.as_ref()
    }
}

serialize_deserialize_with_to_from_bytes!(Ed25519KeyPair, ED25519_KEYPAIR_LENGTH);

impl KeyPair for Ed25519KeyPair {
    type PubKey = Ed25519PublicKey;
    type PrivKey = Ed25519PrivateKey;
    type Sig = Ed25519Signature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        Ed25519PrivateKey::from_bytes(self.private.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Self {
            public: Ed25519PublicKey::from_bytes(self.public.as_ref()).unwrap(),
            private: Ed25519PrivateKey::from_bytes(self.private.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let kp = ed25519_consensus::SigningKey::new(rng);
        Ed25519KeyPair {
            public: Ed25519PublicKey(kp.verification_key()),
            private: Ed25519PrivateKey(kp),
        }
    }
}

impl FromStr for Ed25519KeyPair {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| eyre::eyre!("{}", e.to_string()))?;
        Ok(kp)
    }
}

impl From<ed25519_consensus::SigningKey> for Ed25519KeyPair {
    fn from(kp: ed25519_consensus::SigningKey) -> Self {
        Ed25519KeyPair {
            public: Ed25519PublicKey(kp.verification_key()),
            private: Ed25519PrivateKey(kp),
        }
    }
}

impl Signer<Ed25519Signature> for Ed25519KeyPair {
    fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature {
            sig: self.private.0.sign(msg),
            bytes: OnceCell::new(),
        }
    }
}

//
// Implementation of [Ed25519Signature].
//

serialize_deserialize_with_to_from_bytes!(Ed25519Signature, ED25519_SIGNATURE_LENGTH);
generate_bytes_representation!(
    Ed25519Signature,
    ED25519_SIGNATURE_LENGTH,
    Ed25519SignatureAsBytes
);

impl PartialEq for Ed25519Signature {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Ed25519Signature {}

impl Authenticator for Ed25519Signature {
    type PubKey = Ed25519PublicKey;
    type PrivKey = Ed25519PrivateKey;
    const LENGTH: usize = ED25519_SIGNATURE_LENGTH;
}

impl ToFromBytes for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        ed25519_consensus::Signature::try_from(bytes)
            .map(|sig| Ed25519Signature {
                sig,
                bytes: OnceCell::new(),
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| self.sig.to_bytes())
    }
}

impl_base64_display_fmt!(Ed25519Signature);

impl Default for Ed25519Signature {
    fn default() -> Self {
        Ed25519Signature::from_bytes(&[1u8; ED25519_SIGNATURE_LENGTH]).unwrap()
    }
}

//
// Implementation of [Ed25519PublicKey].
//

impl<'a> From<&'a Ed25519PrivateKey> for Ed25519PublicKey {
    fn from(private: &'a Ed25519PrivateKey) -> Self {
        Ed25519PublicKey(private.0.verification_key())
    }
}

impl ToFromBytes for Ed25519PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        ed25519_consensus::VerificationKey::try_from(bytes)
            .map(Ed25519PublicKey)
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

impl InsecureDefault for Ed25519PublicKey {
    fn insecure_default() -> Self {
        Ed25519PublicKey::from_bytes(&[0u8; 32]).unwrap()
    }
}

impl_base64_display_fmt!(Ed25519PublicKey);

impl Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

#[allow(clippy::derived_hash_with_manual_eq)] // ed25519_consensus's PartialEq is compatible
impl std::hash::Hash for Ed25519PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl PartialOrd for Ed25519PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ed25519PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

serialize_deserialize_with_to_from_bytes!(Ed25519PublicKey, ED25519_PUBLIC_KEY_LENGTH);
generate_bytes_representation!(
    Ed25519PublicKey,
    ED25519_PUBLIC_KEY_LENGTH,
    Ed25519PublicKeyAsBytes
);
impl VerifyingKey for Ed25519PublicKey {
    type PrivKey = Ed25519PrivateKey;
    type Sig = Ed25519Signature;
    const LENGTH: usize = ED25519_PUBLIC_KEY_LENGTH;

    // Compliant to ZIP215: https://zips.z.cash/protocol/protocol.pdf#concreteed25519
    fn verify(&self, msg: &[u8], signature: &Ed25519Signature) -> Result<(), FastCryptoError> {
        self.0
            .verify(&signature.sig, msg)
            .map_err(|_| FastCryptoError::InvalidSignature)
    }

    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail(
        msg: &[u8],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report> {
        if sigs.is_empty() {
            return Err(eyre!("Critical Error! This behaviour can signal something dangerous, and that someone may be trying to bypass signature verification through providing empty batches."));
        }
        if sigs.len() != pks.len() {
            return Err(eyre!(
                "Mismatch between number of signatures and public keys provided"
            ));
        }

        let mut batch = batch::Verifier::new();

        for i in 0..sigs.len() {
            let vk_bytes = VerificationKeyBytes::try_from(pks[i].as_ref()).unwrap();
            batch.queue((vk_bytes, sigs[i].sig, msg))
        }
        batch
            .verify(OsRng)
            .map_err(|_| eyre!("Signature verification failed"))
    }

    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail_different_msg<'a, M>(
        msgs: &[M],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report>
    where
        M: Borrow<[u8]> + 'a,
    {
        if sigs.is_empty() {
            return Err(eyre!("Critical Error! This behaviour can signal something dangerous, and that someone may be trying to bypass signature verification through providing empty batches."));
        }
        if pks.len() != sigs.len() || pks.len() != msgs.len() {
            return Err(eyre!(
                "Mismatch between number of messages, signatures and public keys provided"
            ));
        }

        let mut batch = batch::Verifier::new();

        for i in 0..sigs.len() {
            let vk_bytes = VerificationKeyBytes::try_from(pks[i].as_ref()).unwrap();
            batch.queue((vk_bytes, sigs[i].sig, msgs[i].borrow()))
        }
        batch
            .verify(OsRng)
            .map_err(|_| eyre!("Signature verification failed"))
    }
}

//
// Implementation of [Ed25519AggregateSignature].
//

impl Display for Ed25519AggregateSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{:?}",
            self.sigs
                .iter()
                .map(|x| Base64::encode(x.to_bytes()))
                .collect::<Vec<_>>()
        )
    }
}

impl AsRef<[u8]> for Ed25519AggregateSignature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| {
            self.sigs
                .iter()
                .map(|s| s.to_bytes())
                .collect::<Vec<[u8; ED25519_SIGNATURE_LENGTH]>>()
                .concat()
        })
    }
}

impl ToFromBytes for Ed25519AggregateSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let sigs = bytes
            .chunks_exact(ED25519_SIGNATURE_LENGTH)
            .map(|chunk| <Ed25519Signature as traits::ToFromBytes>::from_bytes(chunk).unwrap())
            .map(|s| s.sig)
            .collect();
        Ok(Ed25519AggregateSignature {
            sigs,
            bytes: OnceCell::new(),
        })
    }
}

impl PartialEq for Ed25519AggregateSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sigs == other.sigs
    }
}

impl Eq for Ed25519AggregateSignature {}

// Ed25519AggregateSignature is experimental and here we disable it by default.
#[cfg(any(test, feature = "experimental"))]
impl AggregateAuthenticator for Ed25519AggregateSignature {
    type Sig = Ed25519Signature;
    type PubKey = Ed25519PublicKey;
    type PrivKey = Ed25519PrivateKey;

    /// Parse a key from its byte representation
    fn aggregate<'a, K: Borrow<Self::Sig> + 'a, I: IntoIterator<Item = &'a K>>(
        signatures: I,
    ) -> Result<Self, FastCryptoError> {
        Ok(Self {
            sigs: signatures.into_iter().map(|s| s.borrow().sig).collect(),
            bytes: OnceCell::new(),
        })
    }

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), FastCryptoError> {
        self.sigs.push(signature.sig);
        self.bytes.take();
        Ok(())
    }

    fn add_aggregate(&mut self, mut signature: Self) -> Result<(), FastCryptoError> {
        self.sigs.append(&mut signature.sigs);
        self.bytes.take();
        Ok(())
    }

    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        message: &[u8],
    ) -> Result<(), FastCryptoError> {
        if pks.len() != self.sigs.len() {
            return Err(FastCryptoError::InputLengthWrong(self.sigs.len()));
        }
        let mut batch = batch::Verifier::new();

        for (i, pk) in pks.iter().enumerate() {
            let vk_bytes = VerificationKeyBytes::try_from(pk.0).unwrap();
            batch.queue((vk_bytes, self.sigs[i], message));
        }

        batch
            .verify(OsRng)
            .map_err(|_| FastCryptoError::GeneralOpaqueError)
    }

    fn verify_different_msg(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> {
        if pks.len() != self.sigs.len() || messages.len() != self.sigs.len() {
            return Err(FastCryptoError::InputLengthWrong(self.sigs.len()));
        }
        let mut batch = batch::Verifier::new();

        for (i, (pk, msg)) in pks.iter().zip(messages).enumerate() {
            let vk_bytes = VerificationKeyBytes::try_from(pk.0).unwrap();
            batch.queue((vk_bytes, self.sigs[i], msg));
        }

        batch
            .verify(OsRng)
            .map_err(|_| FastCryptoError::GeneralOpaqueError)
    }

    fn batch_verify<'a>(
        sigs: &[&Self],
        pks: Vec<impl ExactSizeIterator<Item = &'a Self::PubKey>>,
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> {
        if pks.len() != messages.len() || messages.len() != sigs.len() {
            return Err(FastCryptoError::InputLengthWrong(sigs.len()));
        }
        let mut batch = batch::Verifier::new();

        let mut pk_iter = pks.into_iter();
        for i in 0..sigs.len() {
            let pk_list = &pk_iter.next().unwrap().map(|x| &x.0).collect::<Vec<_>>()[..];
            if pk_list.len() != sigs[i].sigs.len() {
                return Err(FastCryptoError::InvalidInput);
            }
            for (&pk, sig) in pk_list.iter().zip(&sigs[i].sigs) {
                let vk_bytes = VerificationKeyBytes::from(*pk);
                batch.queue((vk_bytes, *sig, messages[i]));
            }
        }
        batch
            .verify(OsRng)
            .map_err(|_| FastCryptoError::GeneralOpaqueError)
    }
}

//
// Serde for a single signature of [Ed25519AggregateSignature]
//

pub struct SingleSignature;

impl SerializeAs<ed25519_consensus::Signature> for SingleSignature {
    fn serialize_as<S>(
        source: &ed25519_consensus::Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // Serialise to Base64 encoded String
            Base64::encode(source.to_bytes()).serialize(serializer)
        } else {
            // Serialise to Bytes
            SerdeBytes::serialize_as(&source.to_bytes(), serializer)
        }
    }
}

impl<'de> DeserializeAs<'de, ed25519_consensus::Signature> for SingleSignature {
    fn deserialize_as<D>(deserializer: D) -> Result<ed25519_consensus::Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            base64ct::Base64::decode_vec(&s).map_err(to_custom_error::<'de, D, _>)?
        } else {
            SerdeBytes::deserialize_as(deserializer)?
        };
        ed25519_consensus::Signature::try_from(bytes.as_slice())
            .map_err(to_custom_error::<'de, D, _>)
    }
}
