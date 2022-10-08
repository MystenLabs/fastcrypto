// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use base64ct::Encoding;
use eyre::eyre;

use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
pub use signature::Signer;
use std::{
    borrow::Borrow,
    fmt::{Debug, Display},
    str::FromStr,
};

use crate::error::FastCryptoError;

/// Trait impl'd by concrete types that represent digital cryptographic material
/// (keys). For signatures, we rely on `signature::Signature`, which may be more widely implemented.
///
/// Key types *must* (as mandated by the `AsRef<[u8]>` bound) be a thin
/// wrapper around the "bag-of-bytes" serialized form of a key which can
/// be directly parsed from or written to the "wire".
///
/// The [`ToFromBytes`] trait aims to provide similar simplicity by minimizing
/// the number of steps involved to obtain a serializable key and
/// ideally ensuring there is one signature type for any given signature system
/// shared by all "provider" crates.
///
/// For signature systems which require a more advanced internal representation
/// (e.g. involving decoded scalars or decompressed elliptic curve points) it's
/// recommended that "provider" libraries maintain their own internal signature
/// type and use `From` bounds to provide automatic conversions.
///
// This is essentially a copy of signature::Signature:
// - we can't implement signature::Signature on Pubkeys / PrivKeys w/o violating the orphan rule,
// - and we need a trait to base the definition of EncodeDecodeBase64 as an extension trait on.
pub trait ToFromBytes: AsRef<[u8]> + Debug + Sized {
    /// Parse a key from its byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError>;

    /// Borrow a byte slice representing the serialized form of this key
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl<T: signature::Signature> ToFromBytes for T {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        <Self as signature::Signature>::from_bytes(bytes).map_err(|_| FastCryptoError::GeneralError)
    }
}

/// Cryptographic material with an immediate conversion to/from Base64 strings.
///
/// This is an [extension trait](https://rust-lang.github.io/rfcs/0445-extension-trait-conventions.html) of `ToFromBytes` above.
///
pub trait EncodeDecodeBase64: Sized {
    fn encode_base64(&self) -> String;
    fn decode_base64(value: &str) -> Result<Self, eyre::Report>;
}

// The Base64ct is not strictly necessary for (PubKey|Signature), but this simplifies things a lot
impl<T: ToFromBytes> EncodeDecodeBase64 for T {
    fn encode_base64(&self) -> String {
        base64ct::Base64::encode_string(self.as_bytes())
    }

    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        let bytes = base64ct::Base64::decode_vec(value).map_err(|e| eyre!("{}", e.to_string()))?;
        <T as ToFromBytes>::from_bytes(&bytes).map_err(|e| e.into())
    }
}

/// Trait impl'd by public keys in asymmetric cryptography.
///
/// The trait bounds are implemented so as to be symmetric and equivalent
/// to the ones on its associated types for private and signature material.
///
pub trait VerifyingKey:
    Serialize
    + DeserializeOwned
    + std::hash::Hash
    + Display
    + Eq  // required to make some cached bytes representations explicit
    + Ord // required to put keys in BTreeMap
    + Default // see [#34](https://github.com/MystenLabs/narwhal/issues/34)
    + ToFromBytes
    + signature::Verifier<Self::Sig>
    + for <'a> From<&'a Self::PrivKey> // conversion PrivateKey -> PublicKey
    + Send
    + Sync
    + 'static
    + Clone
{
    type PrivKey: SigningKey<PubKey = Self>;
    type Sig: Authenticator<PubKey = Self>;
    const LENGTH: usize;

    // Expected to be overridden by implementations
    fn verify_batch_empty_fail(msg: &[u8], pks: &[Self], sigs: &[Self::Sig]) -> Result<(), eyre::Report> {
        if sigs.is_empty() {
            return Err(eyre!("Critical Error! This behavious can signal something dangerous, and that someone may be trying to bypass signature verification through providing empty batches."));
        }
        if pks.len() != sigs.len() {
            return Err(eyre!("Mismatch between number of signatures and public keys provided"));
        }
        pks.iter()
            .zip(sigs)
            .try_for_each(|(pk, sig)| pk.verify(msg, sig))
            .map_err(|_| eyre!("Signature verification failed"))
    }
}

/// Trait impl'd by private (secret) keys in asymmetric cryptography.
///
/// The trait bounds are implemented so as to be symmetric and equivalent
/// to the ones on its associated types for public key and signature material.
///
pub trait SigningKey: ToFromBytes + Serialize + DeserializeOwned + Send + Sync + 'static {
    type PubKey: VerifyingKey<PrivKey = Self>;
    type Sig: Authenticator<PrivKey = Self>;
    const LENGTH: usize;
}

/// Trait impl'd by signatures in asymmetric cryptography.
///
/// The trait bounds are implemented so as to be symmetric and equivalent
/// to the ones on its associated types for private key and public key material.
///
pub trait Authenticator:
    signature::Signature
    + Display
    + Default
    + Serialize
    + DeserializeOwned
    + Send
    + Sync
    + 'static
    + Clone
{
    type PubKey: VerifyingKey<Sig = Self>;
    type PrivKey: SigningKey<Sig = Self>;
    const LENGTH: usize;
}

/// Trait impl'd by a public / private key pair in asymmetric cryptography.
///
pub trait KeyPair:
    Sized + From<Self::PrivKey> + Signer<Self::Sig> + EncodeDecodeBase64 + FromStr
{
    type PubKey: VerifyingKey<PrivKey = Self::PrivKey, Sig = Self::Sig>;
    type PrivKey: SigningKey<PubKey = Self::PubKey, Sig = Self::Sig>;
    type Sig: Authenticator<PubKey = Self::PubKey, PrivKey = Self::PrivKey>;

    fn public(&'_ self) -> &'_ Self::PubKey;
    fn private(self) -> Self::PrivKey;

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self;

    fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self;
}

/// Trait impl'd by aggregated signatures in asymmetric cryptography.
///
/// The trait bounds are implemented to allow the aggregation of multiple signatures,
/// and to verify it against multiple, unaggregated public keys. For signature schemes
/// where aggregation is not possible, a trivial implementation is provided.
///
pub trait AggregateAuthenticator:
    Display + Default + Serialize + DeserializeOwned + Send + Sync + 'static + Clone
{
    type Sig: Authenticator<PubKey = Self::PubKey>;
    type PubKey: VerifyingKey<Sig = Self::Sig>;
    type PrivKey: SigningKey<Sig = Self::Sig>;

    /// Parse a key from its byte representation
    fn aggregate<'a, K: Borrow<Self::Sig> + 'a, I: IntoIterator<Item = &'a K>>(
        signatures: I,
    ) -> Result<Self, FastCryptoError>;

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), FastCryptoError>;
    fn add_aggregate(&mut self, signature: Self) -> Result<(), FastCryptoError>;

    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        message: &[u8],
    ) -> Result<(), FastCryptoError>;

    fn batch_verify<'a>(
        sigs: &[&Self],
        pks: Vec<impl ExactSizeIterator<Item = &'a Self::PubKey>>,
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError>;
}

/// Trait impl'd by cryptographic material that can be generated randomly such as keys and nonces.
///
pub trait Generate {
    fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self;
}

/// Trait impl'd by encryption keys in symmetric cryptography
///
pub trait EncryptionKey:
    ToFromBytes + 'static + Serialize + DeserializeOwned + Send + Sync + Sized + Generate
{
}

/// Trait impl'd by nonces and IV's used in symmetric cryptography
///
pub trait Nonce:
    ToFromBytes + 'static + Serialize + DeserializeOwned + Send + Sync + Sized + Generate
{
}

/// Trait impl'd by symmetric ciphers.
///
pub trait Cipher {
    type IVType: Nonce;

    /// Encrypt `plaintext` and write result to `buffer` using the given IV
    fn encrypt(&self, iv: &Self::IVType, plaintext: &[u8]) -> Result<Vec<u8>, FastCryptoError>;

    /// Decrypt `ciphertext` and write result to `buffer` using the given IV
    fn decrypt(&self, iv: &Self::IVType, ciphertext: &[u8]) -> Result<Vec<u8>, FastCryptoError>;
}

/// Trait impl'd by symmetric ciphers for authenticated encryption.
///
pub trait AuthenticatedCipher {
    type IVType: Nonce;

    /// Encrypt `plaintext` and write result to `buffer` using the given IV and authentication data
    fn encrypt_authenticated(
        &self,
        iv: &Self::IVType,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, FastCryptoError>;

    /// Decrypt `ciphertext` and write result to `buffer` using the given IV and authentication data
    fn decrypt_authenticated(
        &self,
        iv: &Self::IVType,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, FastCryptoError>;
}

/// Trait impl'd by a keys/secret seeds for generating a secure instance.
///
pub trait FromUniformBytes<const LENGTH: usize>: ToFromBytes {
    fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; LENGTH];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes).unwrap()
    }
}
