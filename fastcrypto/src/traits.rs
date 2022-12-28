// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use eyre::eyre;

use rand::rngs::{StdRng, ThreadRng};
use rand::{CryptoRng, RngCore};
use serde::{de::DeserializeOwned, Serialize};
pub use signature::Signer;
use std::{
    borrow::Borrow,
    fmt::{Debug, Display},
    str::FromStr,
};

use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
};

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

// The Base64ct is not strictly necessary for (PubKey|Signature), but this simplifies things a lot.
impl<T: ToFromBytes> EncodeDecodeBase64 for T {
    fn encode_base64(&self) -> String {
        Base64::encode(self.as_bytes())
    }

    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        let bytes = Base64::decode(value)?;
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
    + Eq  // required to make some cached bytes representations explicit.
    + Ord // required to put keys in BTreeMap.
    + Default // see [#34](https://github.com/MystenLabs/narwhal/issues/34).
    + ToFromBytes
    + signature::Verifier<Self::Sig>
    + for<'a> From<&'a Self::PrivKey> // conversion PrivateKey -> PublicKey.
    + Send
    + Sync
    + 'static
    + Clone
{
    type PrivKey: SigningKey<PubKey=Self>;
    type Sig: Authenticator<PubKey=Self>;
    const LENGTH: usize;

    // Expected to be overridden by implementations
    /// Batch verification over the same message. Implementations of this method can be fast,
    /// assuming rogue key checks have already been performed.
    /// TODO: take as input a flag to denote if rogue key protection already took place.
    ///
    /// # Example
    /// ```rust
    /// use fastcrypto::ed25519::*;
    /// # use fastcrypto::{traits::{AggregateAuthenticator, KeyPair, Signer, VerifyingKey}, Verifier};
    /// use rand::thread_rng;
    /// let message: &[u8] = b"Hello, world!";
    /// let kp1 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature1 = kp1.sign(message);
    /// let kp2 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature2 = kp2.sign(message);
    /// let public_keys = [kp1.public().clone(), kp2.public().clone()];
    /// let signatures = [signature1.clone(), signature2.clone()];
    /// assert!(Ed25519PublicKey::verify_batch_empty_fail(message, &public_keys, &signatures).is_ok());
    /// ``` 
    fn verify_batch_empty_fail(msg: &[u8], pks: &[Self], sigs: &[Self::Sig]) -> Result<(), eyre::Report> {
        if sigs.is_empty() {
            return Err(eyre!("Critical Error! This behaviour can signal something dangerous, and that someone may be trying to bypass signature verification through providing empty batches."));
        }
        if pks.len() != sigs.len() {
            return Err(eyre!("Mismatch between number of signatures and public keys provided"));
        }
        pks.iter()
            .zip(sigs)
            .try_for_each(|(pk, sig)| pk.verify(msg, sig))
            .map_err(|_| eyre!("Signature verification failed"))
    }

    // Expected to be overridden by implementations
    /// Batch verification over different messages. Implementations of this method can be fast,
    /// assuming rogue key checks have already been performed.
    /// TODO: take as input a flag to denote if rogue key protection already took place.
    ///
    /// # Example
    /// ```rust
    /// use fastcrypto::ed25519::*;
    /// # use fastcrypto::{traits::{AggregateAuthenticator, KeyPair, Signer, VerifyingKey}, Verifier};
    /// use rand::thread_rng;
    /// let message1: &[u8] = b"Hello, world!";
    /// let kp1 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature1 = kp1.sign(message1);
    /// let message2: &[u8] = b"Hello, world!!!";
    /// let kp2 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature2 = kp2.sign(message2);
    /// let messages = [message1, message2];
    /// let public_keys = [kp1.public().clone(), kp2.public().clone()];
    /// let signatures = [signature1.clone(), signature2.clone()];
    /// assert!(Ed25519PublicKey::verify_batch_empty_fail_different_msg(&messages, &public_keys, &signatures).is_ok());
    /// ``` 
    fn verify_batch_empty_fail_different_msg<'a, M>(msgs: &[M], pks: &[Self], sigs: &[Self::Sig]) -> Result<(), eyre::Report> where M: Borrow<[u8]> + 'a {
        if sigs.is_empty() {
            return Err(eyre!("Critical Error! This behaviour can signal something dangerous, and that someone may be trying to bypass signature verification through providing empty batches."));
        }
        if pks.len() != sigs.len() || pks.len() != msgs.len() {
            return Err(eyre!("Mismatch between number of messages, signatures and public keys provided"));
        }
        pks.iter()
            .zip(sigs)
            .zip(msgs)
            .try_for_each(|((pk, sig), msg)| pk.verify(msg.borrow(), sig))
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

    /// Get the public key.
    fn public(&'_ self) -> &'_ Self::PubKey;
    /// Get the private key.
    fn private(self) -> Self::PrivKey;

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self;

    /// Generate a new keypair using the given RNG.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self;
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

    /// Combine signatures into a single aggregated signature.
    fn aggregate<'a, K: Borrow<Self::Sig> + 'a, I: IntoIterator<Item = &'a K>>(
        signatures: I,
    ) -> Result<Self, FastCryptoError>;

    fn add_signature(&mut self, signature: Self::Sig) -> Result<(), FastCryptoError>;
    fn add_aggregate(&mut self, signature: Self) -> Result<(), FastCryptoError>;

    /// Verify this aggregate signature assuming that all signatures are over the same message.
    ///
    /// # Example
    /// ```rust
    /// use fastcrypto::ed25519::*;
    /// # use fastcrypto::{traits::{AggregateAuthenticator, KeyPair, Signer}, Verifier};
    /// use rand::thread_rng;
    ///
    /// let message: &[u8] = b"Hello, world!";
    /// let kp1 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature1 = kp1.sign(message);
    ///
    /// let kp2 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature2 = kp2.sign(message);
    ///
    /// let aggregated_signature = Ed25519AggregateSignature::aggregate(vec!(&signature1, &signature2)).unwrap();
    /// let public_keys = &[kp1.public().clone(), kp2.public().clone()];
    /// assert!(aggregated_signature.verify(public_keys, message).is_ok());
    /// ```
    fn verify(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        message: &[u8],
    ) -> Result<(), FastCryptoError>;

    /// Verify this aggregate signature where the signatures are over different messages.
    ///
    /// # Example
    /// ```rust
    /// use fastcrypto::ed25519::*;
    /// # use fastcrypto::{traits::{AggregateAuthenticator, KeyPair, Signer, VerifyingKey}, Verifier};
    /// use rand::thread_rng;
    ///
    /// let message1: &[u8] = b"Hello, world!";
    /// let kp1 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature1 = kp1.sign(message1);
    ///
    /// let message2: &[u8] = b"Hello, world!!!";
    /// let kp2 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature2 = kp2.sign(message2);
    ///
    /// let aggregated_signature = Ed25519AggregateSignature::aggregate(vec!(&signature1, &signature2)).unwrap();
    /// let messages = [message1, message2];
    /// let public_keys = [kp1.public().clone(), kp2.public().clone()];
    /// assert!(aggregated_signature.verify_different_msg(&public_keys, &messages).is_ok());
    /// ```
    fn verify_different_msg(
        &self,
        pks: &[<Self::Sig as Authenticator>::PubKey],
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError>;

    /// Verify a batch of aggregate signatures, each consisting of a number of signatures over the same message.
    ///
    /// # Example
    /// ```rust
    /// use fastcrypto::ed25519::*;
    /// # use fastcrypto::{traits::{AggregateAuthenticator, KeyPair, Signer, VerifyingKey}, Verifier};
    /// use rand::thread_rng;
    ///
    /// let message1: &[u8] = b"Hello, world!";
    /// let kp1 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature1 = kp1.sign(message1);
    /// let aggregated_signature1 = Ed25519AggregateSignature::aggregate(vec!(&signature1)).unwrap();
    ///
    /// let message2: &[u8] = b"1234";
    /// let kp2 = Ed25519KeyPair::generate(&mut thread_rng());
    /// let signature2 = kp2.sign(message2);
    /// let aggregated_signature2 = Ed25519AggregateSignature::aggregate(vec!(&signature2)).unwrap();
    ///
    /// let aggregated_signatures = [&aggregated_signature1, &aggregated_signature2];
    /// let messages = [message1, message2];
    /// let pks1 = [kp1.public().clone()];
    /// let pks2 = [kp2.public().clone()];
    /// let public_keys = vec!(pks1.iter(), pks2.iter());
    /// assert!(Ed25519AggregateSignature::batch_verify(&aggregated_signatures, public_keys, &messages).is_ok());
    /// ```
    fn batch_verify<'a>(
        sigs: &[&Self],
        pks: Vec<impl ExactSizeIterator<Item = &'a Self::PubKey>>,
        messages: &[&[u8]],
    ) -> Result<(), FastCryptoError>;
}

/// Trait impl'd by cryptographic material that can be generated randomly such as keys and nonces.
///
pub trait Generate {
    /// Generate a new random instance using the given RNG.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self;
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
    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; LENGTH];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(&bytes).unwrap()
    }
}

// Whitelist the RNG our APIs accept (see https://rust-random.github.io/book/guide-rngs.html for
// others).
/// Trait impl'd by RNG's accepted by fastcrypto.
pub trait AllowedRng: CryptoRng + RngCore {}

// StdRng uses ChaCha12 (see https://github.com/rust-random/rand/issues/932).
// It should be seeded with OsRng (e.g., StdRng::from_rng(OsRng)).
// TODO: Deprecate StdRng (expect for tests) and use thread_rng() everywhere.
impl AllowedRng for StdRng {}
// thread_rng() uses OsRng for the seed, and ChaCha12 as the PRG function.
impl AllowedRng for ThreadRng {}

#[cfg(feature = "experimental")]
pub mod mskr {
    use crate::traits::ToFromBytes;

    /// Trait impl'd by keys and signatures for signature schemes supporting the MSKR (Multi-Signature with Key Randomization) scheme.
    pub trait Randomize<
        PubKey: ToFromBytes,
        Scalar,
        H: HashToScalar<Scalar>,
        const PUBLIC_KEY_LENGTH: usize,
    >: Sized
    {
        /// Randomize this with the given scalar.
        fn randomize_internal(&self, r: &Scalar) -> Self;

        /// Randomize this deterministically based on the given public keys.
        fn randomize(&self, pk: &PubKey, pks: &[PubKey]) -> Self {
            self.randomize_internal(
                &randomization_scalar::<PubKey, Scalar, H, PUBLIC_KEY_LENGTH>(pk, pks),
            )
        }
    }

    pub trait HashToScalar<Scalar> {
        fn hash_to_scalar(bytes: &[u8]) -> Scalar;
    }

    /// Compute as hash of (pk, pks) into a scalar type.
    pub(crate) fn randomization_scalar<
        PubKey: ToFromBytes,
        Scalar,
        H: HashToScalar<Scalar>,
        const PUBLIC_KEY_LENGTH: usize,
    >(
        pk: &PubKey,
        pks: &[PubKey],
    ) -> Scalar {
        let mut seed: Vec<u8> = Vec::with_capacity(PUBLIC_KEY_LENGTH * (pks.len() + 1));
        seed.extend_from_slice(pk.as_bytes());
        for pki in pks {
            seed.extend_from_slice(pki.as_bytes());
        }
        H::hash_to_scalar(seed.as_slice())
    }
}
