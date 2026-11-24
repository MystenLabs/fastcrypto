// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Verifies (signature, public key, message, hash function) inputs the way Sui's
//! `ecdsa_k1::secp256k1_verify` Move native does: `from_bytes` for the 64-byte signature and for
//! the public key (any encoding), then `verify_with_hash` with Keccak-256 (flag 0) or SHA-256
//! (flag 1); other flags return false. The signature and the public key are either arbitrary bytes
//! or derived from a fixed key pair.
//!
//! Invariants: nothing panics, the result agrees with k256, and the fixed key only accepts its own
//! (deterministic, low-s) signature: ECDSA signatures are not unique, but nobody without the
//! private key can find another one.

#![no_main]

#[path = "secp256k1_common.rs"]
mod secp256k1_common;

use arbitrary::Arbitrary;
use fastcrypto::hash::{Keccak256, Sha256};
use fastcrypto::secp256k1::{Secp256k1PublicKey, Secp256k1Signature};
use fastcrypto::traits::{KeyPair, ToFromBytes};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use libfuzzer_sys::fuzz_target;
use secp256k1_common::{
    assert_real_crypto, digest, negate_s, SignatureInput, KECCAK256, KEY, SHA256,
};

#[derive(Arbitrary, Debug)]
enum PublicKeyInput {
    Raw(Vec<u8>),
    /// The compressed (0), uncompressed (1) or hybrid (2) encoding of the fixed key.
    Fixed(u8),
}

#[derive(Arbitrary, Debug)]
struct Input {
    signature: SignatureInput,
    public_key: PublicKeyInput,
    msg: Vec<u8>,
    hash: u8,
}

/// The fixed key's signature, with SHA-256 for flags other than Keccak-256.
fn sign(msg: &[u8], hash: u8) -> Vec<u8> {
    match hash {
        KECCAK256 => KEY.sign_with_hash::<Keccak256>(msg),
        _ => KEY.sign_with_hash::<Sha256>(msg),
    }
    .as_bytes()
    .to_vec()
}

fuzz_target!(|input: Input| {
    assert_real_crypto();
    let honest = sign(&input.msg, input.hash);
    let signature = input.signature.bytes(&honest, &negate_s(&honest));
    let public_key = match input.public_key {
        PublicKeyInput::Raw(bytes) => bytes,
        PublicKeyInput::Fixed(encoding) => {
            let mut bytes = KEY.public().pubkey.serialize_uncompressed();
            match encoding % 3 {
                0 => KEY.public().as_bytes().to_vec(),
                1 => bytes.to_vec(),
                _ => {
                    bytes[0] = 0x06 | (bytes[64] & 1);
                    bytes.to_vec()
                }
            }
        }
    };

    // What the Move native does.
    let sig = <Secp256k1Signature as ToFromBytes>::from_bytes(&signature).ok();
    let pk = Secp256k1PublicKey::from_bytes(&public_key).ok();
    let verified = match (&sig, &pk, input.hash) {
        (Some(sig), Some(pk), KECCAK256) => {
            pk.verify_with_hash::<Keccak256>(&input.msg, sig).is_ok()
        }
        (Some(sig), Some(pk), SHA256) => pk.verify_with_hash::<Sha256>(&input.msg, sig).is_ok(),
        _ => false,
    };

    // k256 agrees. It does not support hybrid encodings, so it is given the compressed encoding of
    // the decoded key.
    let k256_verified = match (
        &pk,
        k256::ecdsa::Signature::try_from(signature.as_slice()),
        digest(&input.msg, input.hash),
    ) {
        (Some(pk), Ok(sig), Some(digest)) => {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(pk.as_bytes())
                .unwrap()
                .verify_prehash(&digest, &sig)
                .is_ok()
        }
        _ => false,
    };
    assert_eq!(verified, k256_verified, "k256 disagrees");

    // The fixed key only accepts its own signature.
    if pk.as_ref() == Some(KEY.public()) {
        let valid_flag = digest(&input.msg, input.hash).is_some();
        assert_eq!(
            verified,
            valid_flag && signature == honest,
            "unexpected result for the fixed key"
        );
    }
});
