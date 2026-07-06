// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [Falcon-512](https://falcon-sign.info) signature scheme
//! (NIST PQC Round-3; FIPS 206 / FN-DSA is not final yet, so this ships clearly labeled pre-standard).
//! Verification uses the in-crate Montgomery-NTT port of the reference verifier in strict canonical
//! mode (exactly one accepted byte encoding per signature); signing uses PQClean via
//! [`pqcrypto-falcon`](https://crates.io/crates/pqcrypto-falcon).
//!
//! Messages can be signed and the signature can be verified again:
//! # Example
//! ```rust
//! # use fastcrypto::falcon512::*;
//! # use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
//! use rand::thread_rng;
//! let kp = Falcon512KeyPair::generate(&mut thread_rng());
//! let message: &[u8] = b"Hello, world!";
//! let signature = kp.sign(message);
//! assert!(kp.public().verify(message, &signature).is_ok());
//! ```

// The permissive verify path and some spec constants of the ported module
// are only exercised by the KAT tests (and documented for future interop
// use), so dead-code analysis of the non-test build is silenced for it. The
// clippy style lints are also silenced to keep the ported code close to
// its source.
#[allow(
    dead_code,
    clippy::module_inception,
    clippy::needless_range_loop,
    clippy::manual_range_contains
)]
pub(crate) mod verify;

use crate::serde_helpers::BytesRepresentation;
use crate::traits::Signer;
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    generate_bytes_representation, impl_base64_display_fmt,
    serialize_deserialize_with_to_from_bytes,
    traits::{
        AllowedRng, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
        VerifyingKey,
    },
};
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use pqcrypto_falcon::falconpadded512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use std::fmt::{self, Debug};
use std::str::FromStr;

/// The length of a public key in bytes.
pub const FALCON512_PUBLIC_KEY_LENGTH: usize = verify::PUBKEY_LEN; // 897

/// The length of the PQClean Falcon-512 secret key in bytes.
const PQCLEAN_SECRET_KEY_LENGTH: usize = 1281;

/// The length of a private key in bytes: the PQClean secret key followed by
/// the public key (PQClean cannot derive the public key from the secret key
/// alone, so it is stored alongside it).
pub const FALCON512_PRIVATE_KEY_LENGTH: usize =
    PQCLEAN_SECRET_KEY_LENGTH + FALCON512_PUBLIC_KEY_LENGTH; // 2178

/// The length of a signature in bytes (the fixed, zero-padded canonical form).
pub const FALCON512_SIGNATURE_LENGTH: usize = verify::SIG_PADDED_LEN; // 666

/// The key pair bytes length is the same as the private key length. This
/// enforces deserialization to always derive the public key from the private
/// key bytes.
pub const FALCON512_KEYPAIR_LENGTH: usize = FALCON512_PRIVATE_KEY_LENGTH;

/// Falcon-512 public key.
#[derive(Clone)]
pub struct Falcon512PublicKey {
    /// The 897-byte encoded public key (header byte `0x09`, then 512
    /// coefficients packed at 14 bits each). Validated on construction.
    bytes: [u8; FALCON512_PUBLIC_KEY_LENGTH],
}

/// Falcon-512 private key: PQClean secret key ‖ public key.
#[derive(SilentDebug, SilentDisplay)]
pub struct Falcon512PrivateKey {
    /// `PQClean sk (1281 bytes) ‖ pk (897 bytes)`. Kept in a `Zeroizing` heap
    /// allocation so the secret half is wiped on drop.
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

/// Falcon-512 signature in the canonical 666-byte padded encoding.
#[derive(Clone)]
pub struct Falcon512Signature {
    /// Boxed to keep the (fairly large) signature off the stack of every
    /// enum/struct that embeds it.
    sig: Box<[u8; FALCON512_SIGNATURE_LENGTH]>,
}

/// Falcon-512 public/private key pair.
#[derive(Debug, PartialEq, Eq)]
pub struct Falcon512KeyPair {
    public: Falcon512PublicKey,
    private: Falcon512PrivateKey,
}

//
// Implementation of [Falcon512PublicKey].
//

impl std::hash::Hash for Falcon512PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialOrd for Falcon512PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Falcon512PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl PartialEq for Falcon512PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Falcon512PublicKey {}

impl AsRef<[u8]> for Falcon512PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl ToFromBytes for Falcon512PublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let bytes: [u8; FALCON512_PUBLIC_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InputLengthWrong(FALCON512_PUBLIC_KEY_LENGTH))?;
        // Reject malformed keys (wrong header byte, coefficients ≥ q,
        // non-zero padding bits) at parse time rather than at verify time.
        if !verify::validate_public_key(&bytes) {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Falcon512PublicKey { bytes })
    }
}

impl_base64_display_fmt!(Falcon512PublicKey);

impl Debug for Falcon512PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl<'a> From<&'a Falcon512PrivateKey> for Falcon512PublicKey {
    fn from(secret: &'a Falcon512PrivateKey) -> Self {
        // The public key is stored verbatim as the tail of the private key
        // bytes (validated when the private key was constructed).
        let mut bytes = [0u8; FALCON512_PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(&secret.bytes[PQCLEAN_SECRET_KEY_LENGTH..]);
        Falcon512PublicKey { bytes }
    }
}

serialize_deserialize_with_to_from_bytes!(Falcon512PublicKey, FALCON512_PUBLIC_KEY_LENGTH);
generate_bytes_representation!(
    Falcon512PublicKey,
    FALCON512_PUBLIC_KEY_LENGTH,
    Falcon512PublicKeyAsBytes
);

impl VerifyingKey for Falcon512PublicKey {
    type PrivKey = Falcon512PrivateKey;
    type Sig = Falcon512Signature;
    const LENGTH: usize = FALCON512_PUBLIC_KEY_LENGTH;

    /// Verify the signature in **strict canonical form only**: the fixed
    /// 666-byte padded encoding with header `0x39` and zero tail. Any other
    /// encoding of the same underlying signature (in particular the
    /// variable-length `0x29` form emitted by the NIST KATs) is rejected, so
    /// exactly one byte-string verifies per signature — see the module
    /// documentation for the malleability rationale.
    fn verify(&self, msg: &[u8], signature: &Falcon512Signature) -> Result<(), FastCryptoError> {
        if verify::verify_strict(&self.bytes, msg, signature.as_ref()) {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidSignature)
        }
    }
}

//
// Implementation of [Falcon512PrivateKey].
//

impl PartialEq for Falcon512PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Falcon512PrivateKey {}

impl SigningKey for Falcon512PrivateKey {
    type PubKey = Falcon512PublicKey;
    type Sig = Falcon512Signature;
    const LENGTH: usize = FALCON512_PRIVATE_KEY_LENGTH;
}

impl ToFromBytes for Falcon512PrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        if bytes.len() != FALCON512_PRIVATE_KEY_LENGTH {
            return Err(FastCryptoError::InputLengthWrong(
                FALCON512_PRIVATE_KEY_LENGTH,
            ));
        }
        // Validate both halves and their consistency: structural decode of
        // (f, g, F), f invertible, h = g·f⁻¹ matching the embedded public
        // key (which is itself decoded canonically, so
        // `From<&Falcon512PrivateKey>` can never produce a malformed public
        // key). This rejects corrupted secret halves and secret keys spliced
        // onto a different key's public half. No probe-signing here:
        // `sign` is infallible by trait, and PQClean's signer can loop
        // without bound on adversarial key material, so it must never run on
        // unvalidated bytes.
        if !verify::validate_secret_key(
            &bytes[..PQCLEAN_SECRET_KEY_LENGTH],
            &bytes[PQCLEAN_SECRET_KEY_LENGTH..],
        ) {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Falcon512PrivateKey {
            bytes: zeroize::Zeroizing::new(bytes.to_vec()),
        })
    }
}

impl AsRef<[u8]> for Falcon512PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

// The single field is a `Zeroizing` allocation, which wipes itself on drop.
impl zeroize::ZeroizeOnDrop for Falcon512PrivateKey {}

serialize_deserialize_with_to_from_bytes!(Falcon512PrivateKey, FALCON512_PRIVATE_KEY_LENGTH);

//
// Implementation of [Falcon512Signature].
//

impl std::hash::Hash for Falcon512Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for Falcon512Signature {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl Eq for Falcon512Signature {}

impl Authenticator for Falcon512Signature {
    type PubKey = Falcon512PublicKey;
    type PrivKey = Falcon512PrivateKey;
    const LENGTH: usize = FALCON512_SIGNATURE_LENGTH;
}

impl ToFromBytes for Falcon512Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        let sig: [u8; FALCON512_SIGNATURE_LENGTH] = bytes
            .try_into()
            .map_err(|_| FastCryptoError::InputLengthWrong(FALCON512_SIGNATURE_LENGTH))?;
        Ok(Falcon512Signature { sig: Box::new(sig) })
    }
}

impl AsRef<[u8]> for Falcon512Signature {
    fn as_ref(&self) -> &[u8] {
        &self.sig[..]
    }
}

impl Debug for Falcon512Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Base64::encode(self.as_ref()))
    }
}

impl_base64_display_fmt!(Falcon512Signature);

serialize_deserialize_with_to_from_bytes!(Falcon512Signature, FALCON512_SIGNATURE_LENGTH);
generate_bytes_representation!(
    Falcon512Signature,
    FALCON512_SIGNATURE_LENGTH,
    Falcon512SignatureAsBytes
);

//
// Implementation of [Falcon512KeyPair].
//

impl From<Falcon512PrivateKey> for Falcon512KeyPair {
    fn from(private: Falcon512PrivateKey) -> Self {
        let public = Falcon512PublicKey::from(&private);
        Falcon512KeyPair { public, private }
    }
}

/// The bytes form of the keypair only contains the private key bytes (which
/// embed the public key; see the module documentation).
impl ToFromBytes for Falcon512KeyPair {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        Falcon512PrivateKey::from_bytes(bytes).map(|private| private.into())
    }
}

impl AsRef<[u8]> for Falcon512KeyPair {
    fn as_ref(&self) -> &[u8] {
        self.private.as_ref()
    }
}

serialize_deserialize_with_to_from_bytes!(Falcon512KeyPair, FALCON512_KEYPAIR_LENGTH);

impl KeyPair for Falcon512KeyPair {
    type PubKey = Falcon512PublicKey;
    type PrivKey = Falcon512PrivateKey;
    type Sig = Falcon512Signature;

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.public
    }

    fn private(self) -> Self::PrivKey {
        self.private
    }

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        // Direct field copy: the bytes were validated when `private` was
        // constructed, and re-validating through `from_bytes` would redo the
        // NTT consistency check for nothing.
        Falcon512KeyPair {
            public: self.public.clone(),
            private: Falcon512PrivateKey {
                bytes: self.private.bytes.clone(),
            },
        }
    }

    /// Generate a new key pair.
    ///
    /// **Note**: the `rng` parameter is *unused* for this scheme. Key
    /// generation goes through PQClean's `keypair()`, which draws its own
    /// randomness from the operating system; the C API offers no way to
    /// inject a caller-provided RNG. In particular, seeded generation is NOT
    /// deterministic for Falcon-512.
    fn generate<R: AllowedRng>(_rng: &mut R) -> Self {
        let (pk, sk) = falconpadded512::keypair();
        let mut bytes = Vec::with_capacity(FALCON512_PRIVATE_KEY_LENGTH);
        bytes.extend_from_slice(sk.as_bytes());
        bytes.extend_from_slice(pk.as_bytes());
        debug_assert_eq!(bytes.len(), FALCON512_PRIVATE_KEY_LENGTH);
        Falcon512PrivateKey {
            bytes: zeroize::Zeroizing::new(bytes),
        }
        .into()
    }
}

impl FromStr for Falcon512KeyPair {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_base64(s)
    }
}

impl Signer<Falcon512Signature> for Falcon512KeyPair {
    /// Signing assumes the key bytes were validated at construction
    /// (`from_bytes` or `generate`); PQClean's signer may reject or fail to
    /// terminate on key material that never went through those paths.
    fn sign(&self, msg: &[u8]) -> Falcon512Signature {
        // Reconstructing the PQClean secret key is a length-checked copy of
        // the first 1281 private-key bytes; the length is a struct invariant.
        let sk = falconpadded512::SecretKey::from_bytes(
            &self.private.bytes[..PQCLEAN_SECRET_KEY_LENGTH],
        )
        .expect("private key length is a struct invariant");
        let sig = falconpadded512::detached_sign(msg, &sk);
        // PQClean falcon-padded-512 emits exactly the fixed 666-byte padded
        // form (header 0x39), which is the canonical encoding this module's
        // verify accepts.
        Falcon512Signature::from_bytes(sig.as_bytes())
            .expect("falcon-padded-512 signatures are exactly 666 bytes")
    }
}
