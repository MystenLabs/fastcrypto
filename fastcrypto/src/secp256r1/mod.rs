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
//!
//! # Encodings
//!
//! The types below implement [ToFromBytes] and serde with these encodings:
//!
//! * [Secp256r1PublicKey]: 33 bytes in the SEC1 compressed format,
//!   [SEC1, sec. 2.3.3](https://www.secg.org/sec1-v2.pdf): a tag byte, `0x02` if the y-coordinate
//!   is even and `0x03` if it is odd, followed by the x-coordinate as 32 big-endian bytes.
//!   This is the only accepted encoding: decoding rejects the 65-byte uncompressed format (tag
//!   `0x04`), the 33-byte compact format (tag `0x05`) and x-coordinates that are not smaller than
//!   the field modulus, so encoding a decoded key always returns the input bytes.
//!   [Secp256r1PublicKey::from_bytes_lenient] also accepts the uncompressed and compact formats,
//!   for callers that must keep accepting them.
//! * [Secp256r1PrivateKey] and [Secp256r1KeyPair]: the secret scalar as 32 big-endian bytes,
//!   [SEC1, sec. 2.3.7](https://www.secg.org/sec1-v2.pdf). Decoding rejects zero and values not
//!   smaller than the group order. A key pair is encoded as its secret key only.
//! * [Secp256r1Signature]: 64 bytes, r followed by s, each as 32 big-endian bytes (the fixed-size
//!   format of [IEEE P1363](https://standards.ieee.org/ieee/1363/2049/), not ASN.1 DER). Decoding
//!   rejects r or s that are zero or not smaller than the group order. Signing always produces a
//!   signature with a low s (s <= n / 2) and verification rejects signatures with a high s, so for
//!   each signature there is only one encoding that verifies.
//!
//! Human-readable serde formats (e.g. JSON) use the Base64 encoding of these bytes. Binary
//! formats (e.g. BCS or bincode) write them as a fixed-size array without a length prefix.

pub mod recoverable;

pub mod conversion;

use crate::groups::GroupElement;
use crate::serde_helpers::BytesRepresentation;
use crate::{
    generate_bytes_representation, impl_base64_display_fmt,
    serialize_deserialize_with_to_from_bytes,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use elliptic_curve::{Curve, FieldBytesEncoding, PrimeField as OtherPrimeField};
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use p256::ecdsa::{
    Signature as ExternalSignature, Signature, SigningKey as ExternalSecretKey,
    VerifyingKey as ExternalPublicKey,
};
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::scalar::IsHigh;
use p256::{NistP256, Scalar};
use std::fmt::{self, Debug};
use std::str::FromStr;

use fastcrypto_derive::{SilentDebug, SilentDisplay};

use crate::groups::multiplier::windowed::WindowedScalarMultiplier;
use crate::groups::multiplier::ScalarMultiplier;
use crate::groups::secp256r1;
use crate::groups::secp256r1::ProjectivePoint;
use crate::hash::{HashFunction, Sha256};
use crate::secp256r1::conversion::{
    affine_pt_p256_to_projective_arkworks, arkworks_fq_to_fr, fr_arkworks_to_p256,
    fr_p256_to_arkworks, get_affine_x_coordinate, reduce_bytes,
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

/// SEC1 tags of the compressed point encoding, for an even and odd y-coordinate respectively.
const SEC1_COMPRESSED_TAGS: [u8; 2] = [0x02, 0x03];

/// The length of a private key in bytes.
pub const SECP256R1_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of a signature in bytes.
pub const SECP256R1_SIGNATURE_LENGTH: usize = 64;

/// The key pair bytes length is the same as the private key length. This enforces deserialization to always derive the public key from the private key.
pub const SECP256R1_KEYPAIR_LENGTH: usize = SECP256R1_PRIVATE_KEY_LENGTH;

/// The number of precomputed points used for scalar multiplication.
pub const PRECOMPUTED_POINTS: usize = 256;

/// The size of the sliding window used for scalar multiplication.
pub const SLIDING_WINDOW_WIDTH: usize = 5;

/// Default hash function used for signing and verifying messages unless another hash function is
/// specified using the `with_hash` functions.
pub type DefaultHash = Sha256;

/// Secp256r1 public key. Encoded in the 33-byte SEC1 compressed format, see the
/// [module documentation](self).
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1PublicKey {
    pub pubkey: ExternalPublicKey,
    pub bytes: OnceCell<[u8; SECP256R1_PUBLIC_KEY_LENGTH]>,
}

/// Secp256r1 private key. Encoded as 32 big-endian bytes, see the [module documentation](self).
#[readonly::make]
#[derive(SilentDebug, SilentDisplay)]
pub struct Secp256r1PrivateKey {
    pub privkey: ExternalSecretKey,
    pub bytes: OnceCell<zeroize::Zeroizing<[u8; SECP256R1_PRIVATE_KEY_LENGTH]>>,
}

/// Secp256r1 ECDSA signature. Encoded as 64 bytes, r followed by s, see the
/// [module documentation](self).
#[readonly::make]
#[derive(Debug, Clone)]
pub struct Secp256r1Signature {
    pub sig: ExternalSignature,
    pub bytes: OnceCell<[u8; SECP256R1_SIGNATURE_LENGTH]>,
}

impl std::hash::Hash for Secp256r1PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash the canonical encoding so that Hash agrees with Eq.
        self.pubkey.as_ref().to_bytes().hash(state);
    }
}

impl PartialOrd for Secp256r1PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Secp256r1PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pubkey.cmp(&other.pubkey)
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

lazy_static! {
    static ref MULTIPLIER: WindowedScalarMultiplier<
        ProjectivePoint,
        <ProjectivePoint as GroupElement>::ScalarType,
        PRECOMPUTED_POINTS,
        SLIDING_WINDOW_WIDTH,
    > = WindowedScalarMultiplier::<
        ProjectivePoint,
        <ProjectivePoint as GroupElement>::ScalarType,
        PRECOMPUTED_POINTS,
        SLIDING_WINDOW_WIDTH,
    >::new(
        secp256r1::ProjectivePoint::generator(),
        secp256r1::ProjectivePoint::zero()
    );
}

serialize_deserialize_with_to_from_bytes!(Secp256r1PublicKey, SECP256R1_PUBLIC_KEY_LENGTH);
generate_bytes_representation!(
    Secp256r1PublicKey,
    SECP256R1_PUBLIC_KEY_LENGTH,
    Secp256r1PublicKeyAsBytes
);
impl Secp256r1PublicKey {
    /// Decode a public key from any SEC1 format accepted by p256: compressed (33 bytes),
    /// uncompressed (65 bytes, tag `0x04`) or compact (33 bytes, tag `0x05`). The decoded key is
    /// always encoded in the compressed format.
    ///
    /// This accepts the same inputs as [ToFromBytes::from_bytes] did before it was restricted to
    /// the compressed format, and is meant for callers that must keep accepting those inputs.
    /// Prefer [ToFromBytes::from_bytes] otherwise.
    pub fn from_bytes_lenient(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let pubkey =
            ExternalPublicKey::try_from(bytes).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Secp256r1PublicKey {
            pubkey,
            bytes: OnceCell::new(),
        })
    }

    /// Same as [ToFromBytes::from_bytes], which now also only accepts the SEC1 compressed format.
    #[deprecated(note = "use ToFromBytes::from_bytes, which is now equally strict")]
    pub fn from_bytes_strict(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        <Self as ToFromBytes>::from_bytes(bytes)
    }

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

        // Split signature into scalars. Note that this panics if r or s are zero, which is handled
        // in Secp256r1Signature::from_bytes.
        let (r, s) = signature.sig.split_scalars();
        let z = reduce_bytes(&H::digest(msg).digest);

        // Convert scalars to arkworks representation
        let r = fr_p256_to_arkworks(&r);
        let s = fr_p256_to_arkworks(&s);
        let q = affine_pt_p256_to_projective_arkworks(self.pubkey.as_affine());

        // Compute inverse of s. This fails if s is zero which is checked in deserialization and in
        // split_scalars above, but we avoid an unwrap here to be safe.
        let s_inv = s.inverse().ok_or(FastCryptoError::InvalidSignature)?;

        // Verify signature
        let u1 = z * s_inv;
        let u2 = r * s_inv;

        // Do optimised double multiplication
        let p = MULTIPLIER
            .two_scalar_mul(
                &secp256r1::Scalar(u1),
                &ProjectivePoint(q),
                &secp256r1::Scalar(u2),
            )
            .0;

        // Note that x is none if and only if p is zero, in which case the signature is invalid. See
        // step 5 in section 4.1.4 in "SEC 1: Elliptic Curve Cryptography".
        let x = get_affine_x_coordinate(&p).ok_or(FastCryptoError::InvalidSignature)?;

        let (x_reduced, _) = arkworks_fq_to_fr(&x);
        if x_reduced == r {
            return Ok(());
        }
        Err(FastCryptoError::InvalidSignature)
    }
}

impl AsRef<[u8]> for Secp256r1PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init::<_>(|| self.pubkey.as_ref().to_bytes().into())
    }
}

impl ToFromBytes for Secp256r1PublicKey {
    /// Decode a public key from the 33-byte SEC1 compressed format. Other formats, such as the
    /// 65-byte uncompressed (tag `0x04`) and the 33-byte compact (tag `0x05`) formats, are rejected,
    /// so every key has exactly one accepted encoding.
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes = <[u8; SECP256R1_PUBLIC_KEY_LENGTH]>::try_from(bytes)
            .map_err(|_| FastCryptoError::InputLengthWrong(SECP256R1_PUBLIC_KEY_LENGTH))?;
        // ExternalPublicKey::try_from also accepts the compact format, which has the same length.
        if !SEC1_COMPRESSED_TAGS.contains(&bytes[0]) {
            return Err(FastCryptoError::InvalidInput);
        }
        // This rejects x-coordinates that are not smaller than the field modulus, so the input is
        // the canonical encoding of the key and can be cached.
        let pubkey =
            ExternalPublicKey::try_from(&bytes[..]).map_err(|_| FastCryptoError::InvalidInput)?;
        Ok(Secp256r1PublicKey {
            pubkey,
            bytes: OnceCell::with_value(bytes),
        })
    }
}

impl_base64_display_fmt!(Secp256r1PublicKey);

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
                bytes: OnceCell::with_value(zeroize::Zeroizing::new(
                    <[u8; SECP256R1_PRIVATE_KEY_LENGTH]>::try_from(bytes).map_err(|_| {
                        FastCryptoError::InputLengthWrong(SECP256R1_PRIVATE_KEY_LENGTH)
                    })?,
                )),
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
            .get_or_init::<_>(|| zeroize::Zeroizing::new(self.privkey.to_bytes().into()))
            .as_ref()
    }
}

// All fields impl zeroize::ZeroizeOnDrop directly or indirectly (OnceCell's drop will call
// ZeroizeOnDrop).
impl zeroize::ZeroizeOnDrop for Secp256r1PrivateKey {}

serialize_deserialize_with_to_from_bytes!(Secp256r1Signature, SECP256R1_SIGNATURE_LENGTH);
generate_bytes_representation!(
    Secp256r1Signature,
    SECP256R1_SIGNATURE_LENGTH,
    Secp256r1SignatureAsBytes
);

impl ToFromBytes for Secp256r1Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != SECP256R1_SIGNATURE_LENGTH {
            return Err(FastCryptoError::InputLengthWrong(
                SECP256R1_SIGNATURE_LENGTH,
            ));
        }

        // This fails if either r or s are zero: https://docs.rs/ecdsa/0.16.6/src/ecdsa/lib.rs.html#209-219.
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
    const LENGTH: usize = SECP256R1_SIGNATURE_LENGTH;
}

impl AsRef<[u8]> for Secp256r1Signature {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get_or_init::<_>(|| {
            <[u8; SECP256R1_SIGNATURE_LENGTH]>::try_from(self.sig.to_bytes().as_slice()).unwrap()
        })
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

impl_base64_display_fmt!(Secp256r1Signature);

impl From<&Secp256r1RecoverableSignature> for Secp256r1Signature {
    fn from(recoverable_sig: &Secp256r1RecoverableSignature) -> Self {
        Secp256r1Signature {
            sig: recoverable_sig.sig,
            bytes: OnceCell::new(),
        }
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
    fn sign_common<H: HashFunction<32>>(&self, msg: &[u8]) -> (Signature, bool, bool) {
        // Hash message
        let z = reduce_bytes(&H::digest(msg).digest);

        // Private key as scalar
        let x = self.secret.privkey.as_nonzero_scalar();

        // Generate nonce according to RFC6979. The unwrap is safe because k is generated smaller
        // than the group size.
        let k = fr_p256_to_arkworks(
            &Scalar::from_repr(rfc6979::generate_k::<sha2::Sha256, _>(
                &x.to_bytes(),
                &NistP256::ORDER.encode_field_bytes(),
                &fr_arkworks_to_p256(&z).to_bytes(),
                &[],
            ))
            .unwrap(),
        );

        // Convert secret key and message to arkworks scalars.
        let x = fr_p256_to_arkworks(x);

        // Compute scalar inversion of k
        let k_inv = k.inverse().expect("k should not be zero");

        // Compute R = kG
        let big_r = MULTIPLIER.mul(&secp256r1::Scalar(k)).0.into_affine();

        // Lift x-coordinate of R and reduce it into an element of the scalar field
        let (r, is_x_reduced) = arkworks_fq_to_fr(big_r.x().expect("R should not be zero"));

        // Compute s as a signature over r and z.
        let s = k_inv * (z + r * x);

        // Convert to p256 format
        let s = fr_arkworks_to_p256(&s).to_bytes();
        let r = fr_arkworks_to_p256(&r).to_bytes();

        // This can only fail if either 𝒓 or 𝒔 are zero (see ecdsa-0.15.0/src/lib.rs) which is negligible.
        let signature = Signature::from_scalars(r, s).expect("r or s is zero");

        // The parity of the y coordinate is needed for computing the recovery id.
        let is_r_odd = big_r.y().expect("R is zero").into_bigint().is_odd();
        let is_s_high: bool = signature.s().is_high().into();
        let is_y_odd = is_r_odd ^ is_s_high;

        // Normalize signature
        let normalized_signature = signature.normalize_s().unwrap_or(signature);

        (normalized_signature, is_y_odd, is_x_reduced)
    }

    /// Create a new signature using the given hash function to hash the message.
    pub fn sign_with_hash<H: HashFunction<32>>(&self, msg: &[u8]) -> Secp256r1Signature {
        let (signature, _, _) = self.sign_common::<H>(msg);

        Secp256r1Signature {
            sig: signature,
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
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_base64(s)
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
