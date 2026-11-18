// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Verifies attacker-chosen (public key, signature, message) triples the way Sui's
//! `ed25519_verify` Move native does (`from_bytes` for both, then `verify`). Keys and signatures
//! are biased towards the ZIP215 edge cases: small-order and non-canonical encodings, small-order
//! components in R and in the key, s ≥ ℓ.
//!
//! Invariants: nothing panics, verification agrees with an independent ZIP215 implementation, and
//! the only signature that verifies under a fixed honest key is its owner's. Batches, including
//! batches of one, are in `ed25519_batch_verify`.

#![no_main]

#[path = "ed25519_common.rs"]
mod ed25519_common;

use arbitrary::Arbitrary;
use ed25519_common::{reference_verify, verify_bytes, Key, Sig};
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519Signature};
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;

/// The seed of the fixed honest key. Inputs never sign with it.
const KEY_SEED: [u8; 32] = [1; 32];

static KEY: Lazy<Ed25519KeyPair> = Lazy::new(|| Ed25519KeyPair::from_bytes(&KEY_SEED).unwrap());

#[derive(Arbitrary, Debug)]
struct Input {
    key: Key,
    sig: Sig,
    msg: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let pk = input.key.bytes();
    let sig = input.sig.bytes(&input.key, &input.msg);

    let verified = verify_bytes(&pk, &sig, &input.msg);
    assert_eq!(
        verified,
        reference_verify(&pk, &sig, &input.msg),
        "disagrees with the reference implementation"
    );

    // Only the owner can sign under an honest key.
    let knows_key_seed = matches!(input.key, Key::Seed { seed, .. } if seed == KEY_SEED);
    if let Ok(sig) = <Ed25519Signature as ToFromBytes>::from_bytes(&sig) {
        if !knows_key_seed && KEY.public().verify(&input.msg, &sig).is_ok() {
            assert_eq!(sig, KEY.sign(&input.msg), "forged a signature");
        }
    }
});
