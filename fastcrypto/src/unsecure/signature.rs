// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    error::FastCryptoError,
    hash::{Digest, HashFunction},
};
use base64ct::{Base64, Encoding};
use eyre::eyre;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use serde_with::serde_as;
use std::{
    borrow::Borrow,
    fmt::{self, Display},
    str::FromStr,
};

use crate::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, InsecureDefault, KeyPair, Signer,
    SigningKey, ToFromBytes, VerifyingKey,
};

use super::hash::Fast256HashUnsecure;
use crate::serde_helpers::BytesRepresentation;
use crate::traits::AllowedRng;
use crate::{generate_bytes_representation, serialize_deserialize_with_to_from_bytes};

///
/// Define Structs
///

// Set to same sizes as BLS
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 96;
pub const SIGNATURE_LENGTH: usize = 48;

type DefaultHashFunction = Fast256HashUnsecure;

#[readonly::make]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct UnsecurePublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnsecurePrivateKey(pub [u8; PRIVATE_KEY_LENGTH]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsecureKeyPair {
    name: UnsecurePublicKey,
    secret: UnsecurePrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnsecureSignature(pub [u8; SIGNATURE_LENGTH]);

impl<const DIGEST_LEN: usize> From<Digest<DIGEST_LEN>> for UnsecureSignature {
    fn from(digest: Digest<DIGEST_LEN>) -> Self {
        UnsecureSignature(digest.to_vec().try_into().unwrap())
    }
}

impl From<&[u8]> for UnsecureSignature {
    fn from(digest: &[u8]) -> Self {
        UnsecureSignature(digest.try_into().unwrap())
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsecureAggregateSignature(#[serde(with = "BigArray")] pub [u8; SIGNATURE_LENGTH]);

/// Signatures are implemented as H(pubkey || msg) where H is the non-cryptographic hash function, XXHash
fn sign(pk: [u8; PUBLIC_KEY_LENGTH], msg: &[u8]) -> UnsecureSignature {
    let copies = (SIGNATURE_LENGTH - 1) / DefaultHashFunction::OUTPUT_SIZE + 1;
    let mut hash = DefaultHashFunction::default();
    hash.update(pk);
    hash.update(msg);
    let digest = hash.finalize();

    // Duplicate the output of the hash function as many times as needed and then truncate to the desired signature size
    let combined: Vec<u8> = vec![digest.digest; copies].concat();
    UnsecureSignature::from(&combined[0..SIGNATURE_LENGTH])
}

///
/// Implement SigningKey
///

impl InsecureDefault for UnsecurePublicKey {
    fn insecure_default() -> Self {
        Self([0; PUBLIC_KEY_LENGTH])
    }
}

impl AsRef<[u8]> for UnsecurePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToFromBytes for UnsecurePublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes_fixed: [u8; PUBLIC_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InputLengthWrong(PUBLIC_KEY_LENGTH))?;
        Ok(Self(bytes_fixed))
    }
}

impl Display for UnsecurePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

serialize_deserialize_with_to_from_bytes!(UnsecurePublicKey, PUBLIC_KEY_LENGTH);

impl<'a> From<&'a UnsecurePrivateKey> for UnsecurePublicKey {
    fn from(secret: &'a UnsecurePrivateKey) -> Self {
        UnsecureKeyPair::from(secret.clone()).public().clone()
    }
}

impl VerifyingKey for UnsecurePublicKey {
    type PrivKey = UnsecurePrivateKey;
    type Sig = UnsecureSignature;

    const LENGTH: usize = PUBLIC_KEY_LENGTH;

    fn verify(&self, msg: &[u8], signature: &UnsecureSignature) -> Result<(), FastCryptoError> {
        let digest = sign(self.0, msg);
        if ToFromBytes::as_bytes(signature) == digest.0 {
            return Ok(());
        }
        Err(FastCryptoError::InvalidSignature)
    }

    #[cfg(any(test, feature = "experimental"))]
    fn verify_batch_empty_fail(
        _msg: &[u8],
        pks: &[Self],
        sigs: &[Self::Sig],
    ) -> Result<(), eyre::Report> {
        if pks
            .iter()
            .zip(sigs.iter())
            .map(|(pk, sig)| pk.verify(_msg, sig))
            .all(|v| v.is_ok())
        {
            return Ok(());
        }
        Err(eyre!("Verification failed!"))
    }
}

///
/// Implement Authenticator
///

impl Default for UnsecureSignature {
    fn default() -> Self {
        Self([0; SIGNATURE_LENGTH])
    }
}

impl AsRef<[u8]> for UnsecureSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToFromBytes for UnsecureSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes_fixed: [u8; SIGNATURE_LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InputLengthWrong(SIGNATURE_LENGTH))?;
        Ok(Self(bytes_fixed))
    }
}

impl Display for UnsecureSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

impl Authenticator for UnsecureSignature {
    type PubKey = UnsecurePublicKey;
    type PrivKey = UnsecurePrivateKey;
    const LENGTH: usize = 0;
}

serialize_deserialize_with_to_from_bytes!(UnsecureSignature, SIGNATURE_LENGTH);

///
/// Implement SigningKey
///

impl AsRef<[u8]> for UnsecurePrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToFromBytes for UnsecurePrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes: [u8; PRIVATE_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InputLengthWrong(PRIVATE_KEY_LENGTH))?;
        Ok(UnsecurePrivateKey(bytes))
    }
}

impl SigningKey for UnsecurePrivateKey {
    type PubKey = UnsecurePublicKey;
    type Sig = UnsecureSignature;
    const LENGTH: usize = PRIVATE_KEY_LENGTH;
}

serialize_deserialize_with_to_from_bytes!(UnsecurePrivateKey, PRIVATE_KEY_LENGTH);

///
/// Implement KeyPair
///

impl From<UnsecurePrivateKey> for UnsecureKeyPair {
    fn from(secret: UnsecurePrivateKey) -> Self {
        let mut pk_bytes = [0; PUBLIC_KEY_LENGTH];
        pk_bytes[0..PRIVATE_KEY_LENGTH].copy_from_slice(&secret.0);
        UnsecureKeyPair {
            name: UnsecurePublicKey(pk_bytes),
            secret,
        }
    }
}

/// The bytes form of the keypair always only contain the private key bytes
impl ToFromBytes for UnsecureKeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let sk = UnsecurePrivateKey::from_bytes(bytes)?;
        Ok(UnsecureKeyPair::from(sk))
    }
}

impl AsRef<[u8]> for UnsecureKeyPair {
    fn as_ref(&self) -> &[u8] {
        self.secret.as_ref()
    }
}

impl KeyPair for UnsecureKeyPair {
    type PubKey = UnsecurePublicKey;
    type PrivKey = UnsecurePrivateKey;
    type Sig = UnsecureSignature;

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        UnsecureKeyPair {
            name: UnsecurePublicKey(self.name.0),
            secret: UnsecurePrivateKey(self.secret.0),
        }
    }

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        self.secret
    }

    fn generate<R: AllowedRng>(_rng: &mut R) -> Self {
        let sk_bytes: [u8; PRIVATE_KEY_LENGTH] = rand::thread_rng().gen();
        let sk = UnsecurePrivateKey(sk_bytes);
        sk.into()
    }
}

impl Signer<UnsecureSignature> for UnsecureKeyPair {
    fn sign(&self, msg: &[u8]) -> UnsecureSignature {
        // A signature for msg is equal to H(pk || msg)
        sign(self.name.0, msg)
    }
}

impl FromStr for UnsecureKeyPair {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|_| FastCryptoError::GeneralOpaqueError)?;
        Ok(kp)
    }
}

serialize_deserialize_with_to_from_bytes!(UnsecureKeyPair, PRIVATE_KEY_LENGTH);

///
/// Implement AggregateAuthenticator. Aggregate signatures are implemented as xor's of the individual signatures.
///

impl AsRef<[u8]> for UnsecureAggregateSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for UnsecureAggregateSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

impl ToFromBytes for UnsecureAggregateSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Ok(UnsecureAggregateSignature(bytes.try_into().unwrap()))
    }
}

fn xor<const N: usize>(x: [u8; N], y: [u8; N]) -> [u8; N] {
    let v: Vec<u8> = x.iter().zip(y.iter()).map(|(xi, yi)| xi ^ yi).collect();
    v.try_into().unwrap()
}

impl Default for UnsecureAggregateSignature {
    fn default() -> Self {
        Self([0; SIGNATURE_LENGTH])
    }
}

impl AggregateAuthenticator for UnsecureAggregateSignature {
    type PrivKey = UnsecurePrivateKey;
    type PubKey = UnsecurePublicKey;
    type Sig = UnsecureSignature;

    /// Combine signatures into a single aggregated signature.
    fn aggregate<'a, K: Borrow<Self::Sig> + 'a, I: IntoIterator<Item = &'a K>>(
        signatures: I,
    ) -> Result<Self, FastCryptoError> {
        Ok(UnsecureAggregateSignature(
            signatures
                .into_iter()
                .map(|s| s.borrow().0)
                .reduce(xor)
                .unwrap(),
        ))
    }

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), FastCryptoError> {
        self.0 = xor(self.0, signature.0);
        Ok(())
    }

    fn add_aggregate(&mut self, signatures: Self) -> Result<(), FastCryptoError> {
        self.0 = xor(self.0, signatures.0);
        Ok(())
    }

    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        msg: &[u8],
    ) -> Result<(), FastCryptoError> {
        let actual = pks.iter().map(|pk| sign(pk.0, msg).0).reduce(xor).unwrap();

        if actual == self.0 {
            return Ok(());
        }
        Err(FastCryptoError::GeneralOpaqueError)
    }

    fn batch_verify<'a>(
        sigs: &[&Self],
        pks: Vec<impl ExactSizeIterator<Item = &'a Self::PubKey>>,
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> {
        if sigs.len() != pks.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        let mut pks_iter = pks.into_iter();

        for (msg, sig) in messages.iter().zip(sigs.iter()) {
            let public_keys: Vec<UnsecurePublicKey> = pks_iter
                .next()
                .unwrap()
                .map(|pk| UnsecurePublicKey(pk.0))
                .collect();

            if sig.verify(&public_keys, msg).is_err() {
                return Err(FastCryptoError::GeneralOpaqueError);
            }
        }
        Ok(())
    }

    fn verify_different_msg(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError> where {
        let actual = pks
            .iter()
            .zip(messages.iter())
            .map(|(pk, m)| sign(pk.0, m).0)
            .reduce(xor)
            .unwrap();

        if actual == self.0 {
            return Ok(());
        }
        Err(FastCryptoError::GeneralOpaqueError)
    }
}

generate_bytes_representation!(
    UnsecureAggregateSignature,
    SIGNATURE_LENGTH,
    UnsecureAggregateSignatureAsBytes
);
