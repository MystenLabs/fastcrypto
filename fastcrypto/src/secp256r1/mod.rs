// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ECDSA signature scheme](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) over the
//! [secp256r1 NIST-P1 curve](https://www.secg.org/SEC2-Ver-1.0.pdf). The nonce is generated deterministically according to [RFC6979](https://www.rfc-editor.org/rfc/rfc6979).
//!
//! Messages can be signed and the signature can be verified again:
//! # Example
//! ```rust
//! # use fastcrypto::secp256r1::*;
//! # use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
//! use rand::thread_rng;
//! let kp = Secp256r1KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert!(kp.public().verify(message, &signature).is_ok());
//! ```

pub mod recoverable;

pub mod conversion;

use crate::serde_helpers::BytesRepresentation;
use crate::{generate_bytes_representation, serialize_deserialize_with_to_from_bytes};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::Field;
use elliptic_curve::{Curve, FieldBytesEncoding, PrimeField};
use once_cell::sync::OnceCell;
use p256::ecdsa::{
    Signature as ExternalSignature, Signature, SigningKey as ExternalSecretKey,
    VerifyingKey as ExternalPublicKey,
};
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::scalar::IsHigh;
use p256::{FieldBytes, NistP256, Scalar};
use std::fmt::{self, Debug, Display};
use std::str::FromStr;
use zeroize::Zeroize;

use fastcrypto_derive::{SilentDebug, SilentDisplay};

use crate::hash::{HashFunction, Sha256};
use crate::secp256r1::conversion::{
    affine_pt_p256_to_arkworks, arkworks_fq_to_fr, fr_arkworks_to_p256, fr_p256_to_arkworks,
    get_affine_x_coordinate, reduce_bytes,
};
use crate::secp256r1::recoverable::Secp256r1RecoverableSignature;
use crate::traits::Signer;
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    traits::{
        AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
        VerifyingKey,
    },
};

/// The length of a public key in bytes.
pub const SECP256R1_PUBLIC_KEY_LENGTH: usize = 33;

/// The length of a private key in bytes.
pub const SECP256R1_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of a signature in bytes.
pub const SECP256R1_SIGNATURE_LENTH: usize = 64;

/// The key pair bytes length is the same as the private key length. This enforces deserialization to always derive the public key from the private key.
pub const SECP256R1_KEYPAIR_LENGTH: usize = SECP256R1_PRIVATE_KEY_LENGTH;

/// Default hash function used for signing and verifying messages unless another hash function is
/// specified using the `with_hash` functions.
pub type DefaultHash = Sha256;

/// Secp256r1 public key.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1PublicKey {
    pub pubkey: ExternalPublicKey,
    pub bytes: OnceCell<[u8; SECP256R1_PUBLIC_KEY_LENGTH]>,
}

/// Secp256r1 private key.
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256r1PrivateKey {
    pub privkey: ExternalSecretKey,
    pub bytes: OnceCell<[u8; SECP256R1_PRIVATE_KEY_LENGTH]>,
}

/// Secp256r1 signature.
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1Signature {
    pub sig: ExternalSignature,
    pub bytes: OnceCell<[u8; SECP256R1_SIGNATURE_LENTH]>,
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
    const LENGTH: usize = SECP256R1_PUBLIC_KEY_LENGTH;

    fn verify(&self, msg: &[u8], signature: &Secp256r1Signature) -> Result<(), FastCryptoError> {
        self.verify_with_hash::<DefaultHash>(msg, signature)
    }
}

serialize_deserialize_with_to_from_bytes!(Secp256r1PublicKey, SECP256R1_PUBLIC_KEY_LENGTH);
generate_bytes_representation!(
    Secp256r1PublicKey,
    SECP256R1_PUBLIC_KEY_LENGTH,
    Secp256r1PublicKeyAsBytes
);
impl Secp256r1PublicKey {
    /// Verify the signature using the given hash function to hash the message.
    pub fn verify_with_hash<H: HashFunction<32>>(
        &self,
        msg: &[u8],
        signature: &Secp256r1Signature,
    ) -> Result<(), FastCryptoError> {
        if signature.sig.s().is_high().into() {
            return Err(FastCryptoError::GeneralError(
                "The s value of ECDSA signature must be low".to_string(),
            ));
        }

        // The flow below is identical to verify_prehash from ecdsa-0.16.6/src/hazmat.rs, but using
        // arkworks for the finite field and elliptic curve arithmetic.

        // Extract scalars from signature
        let (r, s) = signature.sig.split_scalars();
        let z = reduce_bytes(&H::digest(msg).digest);

        // Convert scalars to arkworks representation
        let r = fr_p256_to_arkworks(&r);
        let s = fr_p256_to_arkworks(&s);
        let q = affine_pt_p256_to_arkworks(self.pubkey.as_affine());

        // Verify signature
        let s_inv = s.inverse().expect("s is zero. This should never happen.");
        let u1 = z * s_inv;
        let u2 = r * s_inv;
        let p = ark_secp256r1::Projective::generator() * u1 + q * u2;
        let x = get_affine_x_coordinate(&p);

        // Note that x is none if and only if p is zero, in which case the signature is invalid. See
        // step 5 in section 4.1.4 in "SEC 1: Elliptic Curve Cryptography".
        if x.is_some() && arkworks_fq_to_fr(&x.unwrap()) == r {
            return Ok(());
        }
        Err(FastCryptoError::InvalidSignature)
    }
}

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
                bytes: match <[u8; SECP256R1_PUBLIC_KEY_LENGTH]>::try_from(bytes) {
                    Ok(result) => OnceCell::with_value(result),
                    Err(_) => OnceCell::new(),
                },
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl Display for Secp256r1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
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
    const LENGTH: usize = SECP256R1_PRIVATE_KEY_LENGTH;
}

serialize_deserialize_with_to_from_bytes!(Secp256r1PrivateKey, SECP256R1_PRIVATE_KEY_LENGTH);

impl ToFromBytes for Secp256r1PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        match ExternalSecretKey::try_from(bytes) {
            Ok(privkey) => Ok(Secp256r1PrivateKey {
                privkey,
                bytes: OnceCell::with_value(
                    <[u8; SECP256R1_PRIVATE_KEY_LENGTH]>::try_from(bytes).map_err(|_| {
                        FastCryptoError::InputLengthWrong(SECP256R1_PRIVATE_KEY_LENGTH)
                    })?,
                ),
            }),
            Err(_) => Err(FastCryptoError::InvalidInput),
        }
    }
}

impl PartialEq for Secp256r1PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.privkey == other.privkey
    }
}

impl Eq for Secp256r1PrivateKey {}

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

serialize_deserialize_with_to_from_bytes!(Secp256r1Signature, SECP256R1_SIGNATURE_LENTH);
generate_bytes_representation!(
    Secp256r1Signature,
    SECP256R1_SIGNATURE_LENTH,
    Secp256r1SignatureAsBytes
);

impl ToFromBytes for Secp256r1Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != SECP256R1_SIGNATURE_LENTH {
            return Err(FastCryptoError::InputLengthWrong(SECP256R1_SIGNATURE_LENTH));
        }

        let sig = ExternalSignature::try_from(bytes).map_err(|_| FastCryptoError::InvalidInput)?;

        Ok(Secp256r1Signature {
            sig,
            bytes: OnceCell::new(),
        })
    }
}

impl Authenticator for Secp256r1Signature {
    type PubKey = Secp256r1PublicKey;
    type PrivKey = Secp256r1PrivateKey;
    const LENGTH: usize = SECP256R1_SIGNATURE_LENTH;
}

impl AsRef<[u8]> for Secp256r1Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_try_init::<_, eyre::Report>(|| {
                Ok(
                    <[u8; SECP256R1_SIGNATURE_LENTH]>::try_from(self.sig.to_bytes().as_slice())
                        .unwrap(),
                )
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

impl From<&Secp256r1RecoverableSignature> for Secp256r1Signature {
    fn from(recoverable_sig: &Secp256r1RecoverableSignature) -> Self {
        Secp256r1Signature {
            sig: recoverable_sig.sig,
            bytes: OnceCell::new(),
        }
    }
}

impl Secp256r1Signature {
    /// util function to parse wycheproof test key from DER format.
    #[cfg(test)]
    pub fn from_uncompressed(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        ExternalSignature::try_from(bytes)
            .map(|sig| Secp256r1Signature {
                sig,
                bytes: OnceCell::new(),
            })
            .map_err(|_| FastCryptoError::InvalidInput)
    }
}

/// Secp256r1 public/private key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct Secp256r1KeyPair {
    pub public: Secp256r1PublicKey,
    pub secret: Secp256r1PrivateKey,
}

impl Secp256r1KeyPair {
    /// Sign a message using the given hash function and return the signature and the elliptic curve
    /// point R = kG where k is the ephemeral nonce generated according to RFC6979.
    fn sign_common<H: HashFunction<32>>(&self, msg: &[u8]) -> (Signature, ark_secp256r1::Affine) {
        // Hash message
        let z = H::digest(msg).digest;

        // Private key as scalar
        let x = self.secret.privkey.as_nonzero_scalar();

        // Generate nonce according to RFC6979. The unwrap is safe because k is generated smaller
        // than the group size.
        let k = fr_p256_to_arkworks(
            &Scalar::from_repr(rfc6979::generate_k::<sha2::Sha256, _>(
                &x.to_bytes(),
                &NistP256::ORDER.encode_field_bytes(),
                &FieldBytes::from(z),
                &[],
            ))
            .unwrap(),
        );

        // Convert secret key and message to arkworks scalars.
        let x = fr_p256_to_arkworks(x);
        let z = reduce_bytes(&z);

        // Compute scalar inversion of k
        let k_inv = k.inverse().expect("k should not be zero");

        // Compute R = kG
        let big_r = (ark_secp256r1::Affine::generator() * k).into_affine();

        // Lift x-coordinate of R and reduce it into an element of the scalar field
        let r = arkworks_fq_to_fr(big_r.x().expect("R should not be zero"));

        // Compute s as a signature over r and z.
        let s = k_inv * (z + (r * x));

        // Convert to p256 format
        let s = fr_arkworks_to_p256(&s).to_bytes();
        let r = fr_arkworks_to_p256(&r).to_bytes();

        // This can only fail if either 𝒓 or 𝒔 are zero (see ecdsa-0.15.0/src/lib.rs) which is negligible.
        let signature = Signature::from_scalars(r, s).expect("r or s is zero");

        (signature, big_r)
    }

    /// Create a new signature using the given hash function to hash the message.
    pub fn sign_with_hash<H: HashFunction<32>>(&self, msg: &[u8]) -> Secp256r1Signature {
        let (signature, _) = self.sign_common::<H>(msg);

        // Normalize signature
        let normalized_signature = signature.normalize_s().unwrap_or(signature);

        Secp256r1Signature {
            sig: normalized_signature,
            bytes: OnceCell::new(),
        }
    }
}

/// The bytes form of the keypair always only contain the private key bytes
impl ToFromBytes for Secp256r1KeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Secp256r1PrivateKey::from_bytes(bytes).map(|secret| secret.into())
    }
}

serialize_deserialize_with_to_from_bytes!(Secp256r1KeyPair, SECP256R1_KEYPAIR_LENGTH);

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
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        Secp256r1PrivateKey::from_bytes(self.secret.as_ref()).unwrap()
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        Secp256r1KeyPair {
            public: self.public.clone(),
            secret: Secp256r1PrivateKey::from_bytes(self.secret.as_ref()).unwrap(),
        }
    }

    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        let privkey = ExternalSecretKey::random(rng);
        Secp256r1PrivateKey {
            privkey,
            bytes: OnceCell::new(),
        }
        .into()
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
    fn sign(&self, msg: &[u8]) -> Secp256r1Signature {
        self.sign_with_hash::<DefaultHash>(msg)
    }
}

impl From<Secp256r1PrivateKey> for Secp256r1KeyPair {
    fn from(secret: Secp256r1PrivateKey) -> Self {
        let public = Secp256r1PublicKey::from(&secret);
        Secp256r1KeyPair { public, secret }
    }
}
