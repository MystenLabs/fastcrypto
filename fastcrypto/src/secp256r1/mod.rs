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

pub mod recoverable;

use crate::serialize_deserialize_with_to_from_bytes;
use ecdsa::signature::{Signer as ECDSASigner, Verifier as ECDSAVerifier};
use once_cell::sync::OnceCell;
use p256::ecdsa::{
    Signature as ExternalSignature, SigningKey as ExternalSecretKey,
    VerifyingKey as ExternalPublicKey,
};
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::IsHigh;
use p256::{AffinePoint, NistP256, Scalar};
use serde::{de, Deserialize, Serialize};
use signature::{Error, Signature, Signer, Verifier};
use std::{
    fmt::{self, Debug, Display},
    str::FromStr,
};
use zeroize::Zeroize;

use fastcrypto_derive::{SilentDebug, SilentDisplay};

use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    traits::{
        AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
        VerifyingKey,
    },
};

pub const PUBLIC_KEY_SIZE: usize = 33;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

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
    fn verify(&self, msg: &[u8], signature: &Secp256r1Signature) -> Result<(), Error> {
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

impl Serialize for Secp256r1PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

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
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(Error::new());
        }

        let sig = ExternalSignature::try_from(bytes).map_err(|_| Error::new())?;

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
                Ok(<[u8; SIGNATURE_SIZE]>::try_from(self.sig.to_bytes().as_slice()).unwrap())
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

impl Secp256r1Signature {
    /// util function to parse wycheproof test key from DER format.
    #[cfg(test)]
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self, signature::Error> {
        ExternalSignature::try_from(bytes)
            .map(|sig| Secp256r1Signature {
                sig,
                bytes: OnceCell::new(),
            })
            .map_err(|_| signature::Error::new())
    }
}

/// Secp256r1 public/private key pair.
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
        let sig: ecdsa::Signature<NistP256> = self.secret.privkey.sign(msg);
        let sig_low = sig.normalize_s().unwrap_or(sig);
        Ok(Secp256r1Signature {
            sig: sig_low,
            bytes: OnceCell::new(),
        })
    }
}

impl From<Secp256r1PrivateKey> for Secp256r1KeyPair {
    fn from(secret: Secp256r1PrivateKey) -> Self {
        let name = Secp256r1PublicKey::from(&secret);
        Secp256r1KeyPair { name, secret }
    }
}

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
