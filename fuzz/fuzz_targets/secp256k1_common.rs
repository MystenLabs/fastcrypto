// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Shared by the secp256k1 fuzz targets: a check that the cryptography is not mocked, the hash
//! function flags of Sui's Move natives, and signatures derived from a fixed key pair, so that the
//! fuzzer also explores signatures close to valid ones.

#![allow(dead_code)]

use arbitrary::Arbitrary;
use fastcrypto::hash::{HashFunction, Keccak256, Sha256};
use fastcrypto::secp256k1::Secp256k1KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use hex_literal::hex;
use k256::elliptic_curve::PrimeField;
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, SeedableRng};

/// The hash function flags of Sui's `secp256k1_verify` and `secp256k1_ecrecover` Move natives.
/// Other flags are rejected.
pub const KECCAK256: u8 = 0;
pub const SHA256: u8 = 1;

/// The compressed encoding of the generator, which is the public key of the private key 1.
const GENERATOR: [u8; 33] =
    hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

/// rust-secp256k1 replaces its cryptography with insecure mocks when it is built with
/// `cfg(fuzzing)`, which cargo-fuzz sets unless it is given `--no-cfg-fuzzing`. Fail instead of
/// fuzzing the mocks.
pub fn assert_real_crypto() {
    static CHECKED: std::sync::Once = std::sync::Once::new();
    CHECKED.call_once(|| {
        let mut one = [0u8; 32];
        one[31] = 1;
        let kp = Secp256k1KeyPair::from_bytes(&one).unwrap();
        assert_eq!(
            kp.public().as_bytes(),
            GENERATOR,
            "secp256k1 is mocked: build with `cargo fuzz build --no-cfg-fuzzing`"
        );
    });
}

/// The fixed key pair. Inputs never sign with it.
pub static KEY: Lazy<Secp256k1KeyPair> =
    Lazy::new(|| Secp256k1KeyPair::generate(&mut StdRng::from_seed([1; 32])));

/// The digest of a message with the hash function of a flag, or `None` for other flags.
pub fn digest(msg: &[u8], hash: u8) -> Option<[u8; 32]> {
    match hash {
        KECCAK256 => Some(Keccak256::digest(msg).digest),
        SHA256 => Some(Sha256::digest(msg).digest),
        _ => None,
    }
}

/// Replaces s by n - s in r || s (followed by anything).
pub fn negate_s(signature: &[u8]) -> Vec<u8> {
    let s = k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&signature[32..64])).unwrap();
    let mut bytes = signature.to_vec();
    bytes[32..64].copy_from_slice(&(-s).to_bytes());
    bytes
}

#[derive(Arbitrary, Debug)]
pub enum SignatureInput {
    Raw(Vec<u8>),
    /// The fixed key's signature on the message.
    Honest,
    /// The fixed key's signature on the message with one bit flipped.
    FlipBit(u16),
    /// The other form of the fixed key's signature: s replaced by n - s (and, for a recoverable
    /// signature, the other recovery id).
    HighS,
}

impl SignatureInput {
    /// The signature bytes, given the fixed key's signature and its other form.
    pub fn bytes(&self, honest: &[u8], high_s: &[u8]) -> Vec<u8> {
        match self {
            SignatureInput::Raw(bytes) => bytes.clone(),
            SignatureInput::Honest => honest.to_vec(),
            SignatureInput::FlipBit(bit) => {
                let mut bytes = honest.to_vec();
                let bit = *bit as usize % (bytes.len() * 8);
                bytes[bit / 8] ^= 1 << (bit % 8);
                bytes
            }
            SignatureInput::HighS => high_s.to_vec(),
        }
    }
}
