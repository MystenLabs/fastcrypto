// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [Falcon-512](https://falcon-sign.info) signature scheme
//! (NIST PQC Round-3; FIPS 206 / FN-DSA is not final yet, so this ships clearly labeled pre-standard).
//! Verification uses the in-crate Montgomery-NTT port of the reference verifier in strict canonical
//! mode (exactly one accepted byte encoding per signature) and is always available. Signing and key
//! generation go through PQClean C (the `sign` submodule).
#![cfg_attr(
    feature = "falcon-sign",
    doc = r#"
Messages can be signed and the signature can be verified again. Key
generation draws nothing but a 48-byte seed from the given RNG and expands it
deterministically, so — as with the other schemes — a seeded RNG reproduces
the same key pair. [`Falcon512KeyPair::generate_from_seed`] is the canonical
seed → key map (`@noble/post-quantum`'s `falcon512padded.keygen` agrees on
most seeds but not all; see the `sign` module docs before relying on TS-side
derivation). Wallets deriving from a mnemonic should go through
[`Falcon512KeyPair::generate_from_ikm`], which produces those 48 bytes from a
master secret with the falcon domain-separation label built in.
# Example
```rust
# use fastcrypto::falcon512::*;
# use fastcrypto::traits::{KeyPair, Signer, ToFromBytes, VerifyingKey};
use rand::thread_rng;
let kp = Falcon512KeyPair::generate(&mut thread_rng());
let message: &[u8] = b"Hello, world!";
let signature = kp.sign(message);
assert!(kp.public().verify(message, &signature).is_ok());

// Deterministic derivation: same seed, same key pair.
let kp1 = Falcon512KeyPair::generate_from_seed(&[7u8; 48]);
let kp2 = Falcon512KeyPair::generate_from_seed(&[7u8; 48]);
assert_eq!(kp1.public(), kp2.public());

// Wallet derivation: master secret -> HKDF-SHA3-256 -> 48-byte seed -> keys.
use fastcrypto::hmac::HkdfIkm;
let ikm = HkdfIkm::from_bytes(&[0u8; 32]).unwrap();
let kp3 = Falcon512KeyPair::generate_from_ikm(&ikm, b"m/44'/784'/0'");
assert_eq!(kp3, Falcon512KeyPair::generate_from_ikm(&ikm, b"m/44'/784'/0'"));
```
"#
)]

#[allow(
    dead_code,
    clippy::module_inception,
    clippy::needless_range_loop,
    clippy::manual_range_contains
)]
pub(crate) mod verify;

#[cfg(feature = "falcon-sign")]
pub mod sign;

use crate::serde_helpers::BytesRepresentation;
#[cfg(feature = "falcon-sign")]
use crate::traits::{AllowedRng, KeyPair, Signer};
use crate::{
    encoding::{Base64, Encoding},
    error::FastCryptoError,
    generate_bytes_representation, impl_base64_display_fmt,
    serialize_deserialize_with_to_from_bytes,
    traits::{Authenticator, EncodeDecodeBase64, SigningKey, ToFromBytes, VerifyingKey},
};
use fastcrypto_derive::{SilentDebug, SilentDisplay};
use std::fmt::{self, Debug};
use std::str::FromStr;

/// The length of a parameter
pub const FALCON512_PUBLIC_KEY_LENGTH: usize = verify::PUBKEY_LEN; // 897
/// The bare PQClean secret key; the public key is derived from it (h = g/f),
/// not stored.
pub const FALCON512_PRIVATE_KEY_LENGTH: usize = verify::SECKEY_LEN; // 1281
pub const FALCON512_KEYPAIR_LENGTH: usize = FALCON512_PRIVATE_KEY_LENGTH;
// zero-padded signatures
pub const FALCON512_SIGNATURE_LENGTH: usize = verify::SIG_PADDED_LEN; // 666

/// HKDF domain-separation label for [`Falcon512KeyPair::generate_from_ikm`].
/// It is what keeps a falcon seed from colliding with any other scheme
/// derived off the same master secret, and it is part of the frozen
/// mnemonic → account map: any other stack (e.g. a TS wallet expanding with
/// `@noble/hashes`' HKDF over SHA3-256) must use this exact label to arrive
/// at the same keys.
pub const FALCON512_KEYGEN_HKDF_INFO: &[u8] = b"falcon512-keygen-v1";

/// Structures
#[derive(Clone)]
pub struct Falcon512PublicKey {
    /// The 897-byte encoded pk (header byte `0x09`, then 512 coeffs packed at 14 bits each), i.e. (512*14)/8+1 = 897
    bytes: [u8; FALCON512_PUBLIC_KEY_LENGTH],
}
#[derive(SilentDebug, SilentDisplay)]
pub struct Falcon512PrivateKey {
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
pub struct Falcon512Signature {
    /// Inside a box
    sig: Box<[u8; FALCON512_SIGNATURE_LENGTH]>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Falcon512KeyPair {
    public: Falcon512PublicKey,
    private: Falcon512PrivateKey,
}

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
        // h = g/f; cannot fail, the bytes were validated at construction.
        let bytes =
            verify::derive_public_key(&secret.bytes).expect("private key bytes are validated");
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

    /// Strict canonical form only: 666 bytes, header `0x39`, zero tail.
    /// Exactly one byte-string verifies per signature; see the verify module
    /// docs for the malleability rationale.
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
        // Structural decode of (f, g, F) and f invertible, i.e. the key
        // derives a public key. No probe-signing: PQClean's signer can loop
        // forever on adversarial key material.
        if verify::derive_public_key(bytes).is_none() {
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

#[cfg(feature = "falcon-sign")]
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

    /// Generate a new key pair. All randomness is a 48-byte seed drawn from
    /// `rng` and expanded deterministically (see [`sign::keygen_from_seed`]),
    /// so a seeded `StdRng` reproduces the same key pair — the same seed
    /// semantics as the other schemes.
    fn generate<R: AllowedRng>(rng: &mut R) -> Self {
        use zeroize::Zeroize as _;
        let mut seed = [0u8; sign::KEYGEN_SEED_LEN];
        rng.fill_bytes(&mut seed);
        let kp = Self::generate_from_seed(&seed);
        seed.zeroize();
        kp
    }
}

#[cfg(feature = "falcon-sign")]
impl Falcon512KeyPair {
    /// Derive the key pair for `seed`. This is the stable derivation contract
    /// for wallet recovery: unlike `generate(&mut StdRng::from_seed(..))`, it
    /// does not additionally depend on the rand crate keeping `StdRng`'s
    /// ChaCha12 stream stable across versions. Wallets deriving from a
    /// master secret should prefer [`Self::generate_from_ikm`], which
    /// produces the 48 bytes with domain separation built in.
    pub fn generate_from_seed(seed: &[u8; sign::KEYGEN_SEED_LEN]) -> Self {
        // Keygen returns both halves, so skip the re-derivation `.into()`
        // would do.
        let (sk, pk) = sign::keygen_from_seed(seed);
        Falcon512KeyPair {
            public: Falcon512PublicKey { bytes: pk },
            private: Falcon512PrivateKey {
                bytes: zeroize::Zeroizing::new(sk.to_vec()),
            },
        }
    }

    /// Derive the key pair for a master secret: HKDF-SHA3-256 expands `ikm`
    /// under the fixed [`FALCON512_KEYGEN_HKDF_INFO`] label into the 48-byte
    /// keygen seed for [`Self::generate_from_seed`]. The fixed label
    /// domain-separates falcon from every other scheme derived off the same
    /// secret; per-account context (e.g. a derivation path) goes in `salt`.
    pub fn generate_from_ikm(ikm: &crate::hmac::HkdfIkm, salt: &[u8]) -> Self {
        use zeroize::Zeroize as _;
        let mut seed = crate::hmac::hkdf_sha3_256(
            ikm,
            salt,
            FALCON512_KEYGEN_HKDF_INFO,
            sign::KEYGEN_SEED_LEN,
        )
        .expect("48 bytes is far below the HKDF-SHA3-256 output bound");
        let kp = Self::generate_from_seed(
            seed.as_slice()
                .try_into()
                .expect("HKDF returns the requested length"),
        );
        seed.zeroize();
        kp
    }
}

impl FromStr for Falcon512KeyPair {
    type Err = FastCryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_base64(s)
    }
}

#[cfg(feature = "falcon-sign")]
impl Signer<Falcon512Signature> for Falcon512KeyPair {
    /// Signing assumes the key bytes were validated at construction
    /// (`from_bytes` or `generate`); PQClean's signer may reject or fail to
    /// terminate on key material that never went through those paths.
    fn sign(&self, msg: &[u8]) -> Falcon512Signature {
        let sk = self.private.bytes[..]
            .try_into()
            .expect("length is a struct invariant");
        let sig = sign::sign(sk, &self.public.bytes, msg)
            .expect("signing with a validated key emits the canonical form");
        Falcon512Signature { sig: Box::new(sig) }
    }
}
