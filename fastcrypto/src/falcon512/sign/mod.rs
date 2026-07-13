// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Falcon-512 signing and key generation through PQClean's
//! `falcon-padded-512` (the Pornin reference lineage), via
//! [`pqcrypto-falcon`](https://crates.io/crates/pqcrypto-falcon) built
//! without SIMD features so the portable "clean" C is the only code path.
//! Verification stays with the in-crate port in [`super::verify`]; nothing
//! here routes to PQClean's verifier.
//!
//! The signing salt comes from the operating system, so signatures are
//! randomized, and PQClean has no seeded keygen, so keys are generate-once
//! (no mnemonic derivation). The pqcrypto crates are flagged unmaintained
//! (RUSTSEC-2026-0163/0165) now that PQClean is archived; the migration
//! target is Pornin's pure-Rust `fn-dsa` once FIPS 206 is final.
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

/// Sign `msg` with a PQClean-format secret key.
///
/// `pk` is the matching public key: PQClean cannot derive it from the secret
/// key, and every signature is checked with [`verify::verify_strict`] before
/// it is returned, so any format drift in the signer surfaces here as an
/// error rather than as a signature the verifier rejects.
///
/// Returns `InvalidInput` if the secret key does not parse, and
/// `GeneralError` if the emitted signature is not the strict canonical form
/// (666 bytes, header `0x39`, zero tail) or does not verify under `pk`.
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
