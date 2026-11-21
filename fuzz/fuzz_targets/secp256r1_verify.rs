// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Verifies (signature, public key, message, hash function) inputs the way Sui's
//! `ecdsa_r1::secp256r1_verify` Move native does: `from_bytes` for the signature and the public key,
//! with no length checks, then `verify_with_hash` with Keccak-256 for flag 0 and SHA-256 for flag 1,
//! and `false` for other flags. The signature and the key are either arbitrary bytes or derived from
//! a fixed key pair.
//!
//! Invariants: nothing panics; verification agrees with p256 restricted to signatures with a low s;
//! and the only signature that verifies under the fixed key is its own.

#![no_main]

#[path = "secp256r1_common.rs"]
mod secp256r1_common;

use arbitrary::Arbitrary;
use fastcrypto::hash::{Keccak256, Sha256};
use fastcrypto::secp256r1::{Secp256r1PublicKey, Secp256r1Signature};
use fastcrypto::traits::{KeyPair, ToFromBytes};
use libfuzzer_sys::fuzz_target;
use secp256r1_common::{
    digest, is_high_s, negate_s, p256_verify, SignatureInput, KECCAK256, KEY, SHA256, SIG_LENGTH,
};

#[derive(Arbitrary, Debug)]
enum PublicKeyInput {
    Raw(Vec<u8>),
    /// The fixed key, compressed.
    Fixed,
    /// The fixed key with the parity of y flipped, which is its negation.
    Negated,
    /// The fixed key in another SEC1 format: uncompressed (tag 0x04) or with another tag.
    Uncompressed(u8),
    /// The fixed key with a byte replaced.
    SetByte(u8, u8),
}

impl PublicKeyInput {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = KEY.public().as_bytes().to_vec();
        match self {
            PublicKeyInput::Raw(raw) => bytes = raw.clone(),
            PublicKeyInput::Fixed => (),
            PublicKeyInput::Negated => bytes[0] ^= 1,
            PublicKeyInput::Uncompressed(tag) => {
                bytes = KEY
                    .public()
                    .pubkey
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec();
                if *tag != 0 {
                    bytes[0] = *tag;
                }
            }
            PublicKeyInput::SetByte(index, value) => {
                let len = bytes.len();
                bytes[*index as usize % len] = *value;
            }
        }
        bytes
    }
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

/// What the secp256r1_verify Move native does.
fn secp256r1_verify(signature: &[u8], public_key: &[u8], msg: &[u8], hash: u8) -> bool {
    let (Ok(signature), Ok(public_key)) = (
        <Secp256r1Signature as ToFromBytes>::from_bytes(signature),
        Secp256r1PublicKey::from_bytes(public_key),
    ) else {
        return false;
    };
    match hash {
        KECCAK256 => public_key
            .verify_with_hash::<Keccak256>(msg, &signature)
            .is_ok(),
        SHA256 => public_key
            .verify_with_hash::<Sha256>(msg, &signature)
            .is_ok(),
        _ => false,
    }
}

fuzz_target!(|input: Input| {
    let honest = sign(&input.msg, input.hash);
    let signature = input.signature.bytes(&honest, &negate_s(&honest));
    let public_key = input.public_key.bytes();

    let verified = secp256r1_verify(&signature, &public_key, &input.msg, input.hash);

    // p256 decodes every key that fastcrypto decodes to the same point, and verifies the same
    // signatures except those with a high s.
    let expected = Secp256r1PublicKey::from_bytes(&public_key).is_ok()
        && signature.len() == SIG_LENGTH
        && !is_high_s(&signature)
        && digest(&input.msg, input.hash)
            .is_some_and(|digest| p256_verify(&public_key, &digest, &signature));
    assert_eq!(verified, expected, "disagrees with p256");

    // Only the owner can sign under the fixed key.
    if verified && Secp256r1PublicKey::from_bytes(&public_key).unwrap() == *KEY.public() {
        assert_eq!(signature, honest, "forged a signature");
    }
});
