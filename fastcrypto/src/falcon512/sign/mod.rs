// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Falcon-512 signing and key generation through PQClean `falcon-padded-512`
//! via [`pqcrypto-falcon`](https://crates.io/crates/pqcrypto-falcon), built
//! without SIMD features (portable C only). Verification stays with the
//! in-crate port in [`super::verify`]; nothing here routes to PQClean's.
//!
//! The salt is OS randomness (signatures are randomized) and there is no
//! seeded keygen, so no mnemonic derivation. pqcrypto is flagged unmaintained
//! (RUSTSEC-2026-0163/0165) now that PQClean is archived; migration target is
//! Pornin's pure-Rust `fn-dsa` once FIPS 206 is final.
//!
//! # Example
//! ```rust
//! use fastcrypto::falcon512::sign::{keygen, sign};
//! use fastcrypto::falcon512::Falcon512PublicKey;
//! use fastcrypto::traits::{ToFromBytes, VerifyingKey};
//! let (sk, pk) = keygen();
//! let sig = sign(&sk, &pk, b"Hello, world!").unwrap();
//! let pk = Falcon512PublicKey::from_bytes(&pk).unwrap();
//! let sig = <fastcrypto::falcon512::Falcon512Signature as ToFromBytes>::from_bytes(&sig).unwrap();
//! assert!(pk.verify(b"Hello, world!", &sig).is_ok());
//! ```

use crate::error::FastCryptoError;
use pqcrypto_falcon::falconpadded512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use super::verify;
use super::verify::{PUBKEY_LEN, SECKEY_LEN, SIG_PADDED_LEN};

/// Generate a PQClean-format key pair, returned as (secret key, public key)
/// bytes. Randomness is drawn by PQClean from the operating system; there is
/// no seeded variant.
pub fn keygen() -> ([u8; SECKEY_LEN], [u8; PUBKEY_LEN]) {
    let (pk, sk) = falconpadded512::keypair();
    let sk = sk
        .as_bytes()
        .try_into()
        .expect("PQClean secret keys are 1281 bytes");
    let pk = pk
        .as_bytes()
        .try_into()
        .expect("PQClean public keys are 897 bytes");
    (sk, pk)
}

/// Sign `msg` with a PQClean-format secret key. `pk` is the matching public
/// key, passed in to avoid re-deriving it per call; every signature is checked with
/// [`verify::verify_strict`] before it is returned, so signer drift surfaces
/// as `GeneralError` here instead of a signature the verifier rejects.
pub fn sign(
    sk: &[u8; SECKEY_LEN],
    pk: &[u8; PUBKEY_LEN],
    msg: &[u8],
) -> Result<[u8; SIG_PADDED_LEN], FastCryptoError> {
    let sk =
        falconpadded512::SecretKey::from_bytes(sk).map_err(|_| FastCryptoError::InvalidInput)?;
    let sig: [u8; SIG_PADDED_LEN] = falconpadded512::detached_sign(msg, &sk)
        .as_bytes()
        .try_into()
        .map_err(|_| {
            FastCryptoError::GeneralError("falcon signature is not the 666-byte padded form".into())
        })?;
    if sig[0] != 0x39 || !verify::verify_strict(pk, msg, &sig) {
        return Err(FastCryptoError::GeneralError(
            "falcon signature failed the strict verify gate".into(),
        ));
    }
    Ok(sig)
}
