// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ML-DSA-65](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
//! signature scheme from FIPS 204, on top of the `mysten-mldsa-native-rs` wrapper around the
//! mldsa-native C library.
//!
//! The private key is the 32-byte seed from which FIPS 204 derives the full signing key.
//! Serialization emits only the seed, and key expansion is fully specified by the standard.
//! Signing is hedged (the FIPS 204 default): each signature draws fresh randomness from the
//! operating system, so two signatures over the same msg differ while both verify. The FIPS
//! 204 context string is fixed to empty but the wrapper gets context up to 255-bytes.
//!
//! msgs can be signed and the signature can be verified again:
//! ```rust
//! # use fastcrypto_pq::mldsa65::*;
//! # use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
//! use rand::thread_rng;
//! let keypair = MLDSA65KeyPair::generate(&mut thread_rng());
//! let msg: &[u8] = b"Hello, Q world!";
//! let signature = keypair.sign(msg);
//! assert!(keypair.public().verify(msg, &signature).is_ok());
//! ```

use std::{
    fmt::{self, Debug},
    str::FromStr,
};

use mysten_mldsa_native_rs as mldsa;
use rand::rngs::OsRng;
use rand::RngCore;

use fastcrypto_derive::{SilentDebug, SilentDisplay};

use fastcrypto::error::FastCryptoError::{InvalidInput, InvalidSignature};
use fastcrypto::serde_helpers::BytesRepresentation;
use fastcrypto::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    impl_base64_display_fmt,
    traits::{
        AllowedRng, Authenticator, EncodeDecodeBase64, InsecureDefault, KeyPair, Signer,
        SigningKey, ToFromBytes, VerifyingKey,
    },
};
use fastcrypto::{generate_bytes_representation, serialize_deserialize_with_to_from_bytes};

/// The length of a private key in bytes: the FIPS 204 seed.
pub const MLDSA65_PRIVATE_KEY_LENGTH: usize = mldsa::SEED_LENGTH;

/// The length of a public key in bytes.
pub const MLDSA65_PUBLIC_KEY_LENGTH: usize = mldsa::PUBLIC_KEY_LENGTH;

/// The length of a signature in bytes.
pub const MLDSA65_SIGNATURE_LENGTH: usize = mldsa::SIGNATURE_LENGTH;

/// The key pair bytes length is the same as the private key length. This enforces
/// deserialization to always derive the public key from the private key.
pub const MLDSA65_KEYPAIR_LENGTH: usize = MLDSA65_PRIVATE_KEY_LENGTH;

/// ML-DSA-65 public key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MLDSA65PublicKey(mldsa::VerifyingKey);

/// ML-DSA-65 private key: the 32-byte FIPS 204 seed, kept next to the expanded signing key
/// derived from it so signing never re-runs key generation. Only the seed is serialized, and
/// both wrapper types zeroize their material on drop.
///
/// This holds secret material only. The public key is not cached here even though key
/// expansion produces it for free, because a type named for the private key we would prefer
/// to not carry public data in this struct; Deriving it costs one more expansion
#[derive(SilentDebug, SilentDisplay)]
pub struct MLDSA65PrivateKey {
    seed: mldsa::SigningKeySeed,
    key: mldsa::SigningKey,
}

impl MLDSA65PrivateKey {
    fn from_seed(seed: mldsa::SigningKeySeed) -> Self {
        let (key, _) = seed.expand();
        MLDSA65PrivateKey { seed, key }
    }
}

impl PartialEq for MLDSA65PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        // The expanded key is derived from the seed, so seed equality is key equality.
        self.seed == other.seed
    }
}

impl Eq for MLDSA65PrivateKey {}

/// ML-DSA-65 key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct MLDSA65KeyPair {
    public: MLDSA65PublicKey,
    private: MLDSA65PrivateKey,
}

/// ML-DSA-65 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct MLDSA65Signature(mldsa::Signature);

//
// Implementation of [MLDSA65PrivateKey].
//

impl SigningKey for MLDSA65PrivateKey {
    type PubKey = MLDSA65PublicKey;
    type Sig = MLDSA65Signature;
    const LENGTH: usize = MLDSA65_PRIVATE_KEY_LENGTH;
}

impl ToFromBytes for MLDSA65PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let seed = mldsa::SigningKeySeed::from_bytes(bytes).map_err(|_| InvalidInput)?;
        Ok(MLDSA65PrivateKey::from_seed(seed))
    }
}

impl AsRef<[u8]> for MLDSA65PrivateKey {
    fn as_ref(&self) -> &[u8] {
        self.seed.as_ref()
    }
}

serialize_deserialize_with_to_from_bytes!(MLDSA65PrivateKey, MLDSA65_PRIVATE_KEY_LENGTH);

//
// Implementation of [MLDSA65KeyPair].
//

impl From<MLDSA65PrivateKey> for MLDSA65KeyPair {
    fn from(private: MLDSA65PrivateKey) -> Self {
        let public = MLDSA65PublicKey::from(&private);
        MLDSA65KeyPair { public, private }
    }
}

/// The bytes form of the keypair always only contain the private key bytes
impl ToFromBytes for MLDSA65KeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        MLDSA65PrivateKey::from_bytes(bytes).map(|private| private.into())
    }
}

impl AsRef<[u8]> for MLDSA65KeyPair {
    fn as_ref(&self) -> &[u8] {
        self.private.as_ref()
    }
}

serialize_deserialize_with_to_from_bytes!(MLDSA65KeyPair, MLDSA65_KEYPAIR_LENGTH);

impl KeyPair for MLDSA65KeyPair {
    type PubKey = MLDSA65PublicKey;
    type PrivKey = MLDSA65PrivateKey;
    type Sig = MLDSA65Signature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        self.private
    }

    // Not cfg-gated on copy_key; this crate always enables fastcrypto/copy_key, so the
    // trait method always exists here.
    fn copy(&self) -> Self {
        MLDSA65KeyPair {
            public: self.public.clone(),
            private: MLDSA65PrivateKey::from_seed(mldsa::SigningKeySeed::from(
                *self.private.seed.as_bytes(),
            )),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; MLDSA65_PRIVATE_KEY_LENGTH];
        rng.fill_bytes(&mut seed);
        MLDSA65PrivateKey::from_seed(mldsa::SigningKeySeed::from(seed)).into()
    }
}

impl FromStr for MLDSA65KeyPair {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_base64(s)
    }
}

impl Signer<MLDSA65Signature> for MLDSA65KeyPair {
    fn sign(&self, msg: &[u8]) -> MLDSA65Signature {
        // Hedged signing, the FIPS 204 default: fresh randomness from the operating system
        // (OsRng/getrandom) for every sig, so signing the same msg twice gives different
        // sigs. `rnd` need not be kept secret, so it is not zeroized.
        let mut rnd = [0u8; mldsa::RND_LENGTH];
        OsRng.fill_bytes(&mut rnd);
        MLDSA65Signature(
            self.private
                .key
                .sign(msg, b"", &rnd)
                .expect("the empty context cannot exceed the length limit"),
        )
    }
}

//
// Implementation of [MLDSA65Signature].
//

serialize_deserialize_with_to_from_bytes!(MLDSA65Signature, MLDSA65_SIGNATURE_LENGTH);
generate_bytes_representation!(
    MLDSA65Signature,
    MLDSA65_SIGNATURE_LENGTH,
    MLDSA65SignatureAsBytes
);

impl Authenticator for MLDSA65Signature {
    type PubKey = MLDSA65PublicKey;
    type PrivKey = MLDSA65PrivateKey;
    const LENGTH: usize = MLDSA65_SIGNATURE_LENGTH;
}

impl ToFromBytes for MLDSA65Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        mldsa::Signature::from_bytes(bytes)
            .map(MLDSA65Signature)
            .map_err(|_| InvalidInput)
    }
}

impl AsRef<[u8]> for MLDSA65Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl_base64_display_fmt!(MLDSA65Signature);

// A derived Debug would dump all 3309 bytes; Base64 keeps assertion failures readable.
impl Debug for MLDSA65Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

//
// Implementation of [MLDSA65PublicKey].
//

impl<'a> From<&'a MLDSA65PrivateKey> for MLDSA65PublicKey {
    fn from(private: &'a MLDSA65PrivateKey) -> Self {
        // re-expanding the seed is the only way to recover public key. Callers that
        // need it repeatedly should hold/cache the MLDSA65KeyPair.
        let (_, public) = private.seed.expand();
        MLDSA65PublicKey(public)
    }
}

impl ToFromBytes for MLDSA65PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        mldsa::VerifyingKey::from_bytes(bytes)
            .map(MLDSA65PublicKey)
            .map_err(|_| InvalidInput)
    }
}

impl InsecureDefault for MLDSA65PublicKey {
    fn insecure_default() -> Self {
        MLDSA65PublicKey::from_bytes(&[0u8; MLDSA65_PUBLIC_KEY_LENGTH]).unwrap()
    }
}

impl AsRef<[u8]> for MLDSA65PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl_base64_display_fmt!(MLDSA65PublicKey);

impl Debug for MLDSA65PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

serialize_deserialize_with_to_from_bytes!(MLDSA65PublicKey, MLDSA65_PUBLIC_KEY_LENGTH);
generate_bytes_representation!(
    MLDSA65PublicKey,
    MLDSA65_PUBLIC_KEY_LENGTH,
    MLDSA65PublicKeyAsBytes
);

impl VerifyingKey for MLDSA65PublicKey {
    type PrivKey = MLDSA65PrivateKey;
    type Sig = MLDSA65Signature;
    const LENGTH: usize = MLDSA65_PUBLIC_KEY_LENGTH;

    fn verify(&self, msg: &[u8], signature: &MLDSA65Signature) -> Result<(), FastCryptoError> {
        // Every failure maps to InvalidSignature without classification; the backend reports
        // malformed encodings and ordinary mismatches through one code.
        self.0
            .verify(msg, b"", &signature.0)
            .map_err(|_| InvalidSignature)
    }
}
