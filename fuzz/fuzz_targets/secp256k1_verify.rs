// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Verifies (signature, public key, message, hash function) inputs the way Sui's
//! `ecdsa_k1::secp256k1_verify` Move native does: `from_bytes` for the 64-byte signature and for
//! the public key (any encoding), then `verify_with_hash` with Keccak-256 (flag 0) or SHA-256
//! (flag 1); other flags return false. The signature and the public key are either arbitrary bytes
//! or derived from a fixed key pair, so that the fuzzer also explores signatures close to valid
//! ones.
//!
//! Invariants: nothing panics, the result agrees with k256, and the fixed key only accepts its own
//! (deterministic, low-s) signature: ECDSA signatures are not unique, but nobody without the
//! private key can find another one.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::hash::{HashFunction, Keccak256, Sha256};
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use fastcrypto::traits::{KeyPair, ToFromBytes};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::elliptic_curve::PrimeField;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, SeedableRng};

const KECCAK256: u8 = 0;
const SHA256: u8 = 1;

/// The compressed encoding of the generator, which is the public key of the private key 1.
const GENERATOR: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

/// rust-secp256k1 replaces its cryptography with insecure mocks when it is built with
/// `cfg(fuzzing)`, which cargo-fuzz sets unless it is given `--no-cfg-fuzzing`. Fail instead of
/// fuzzing the mocks.
fn assert_real_crypto() {
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

static KEY: Lazy<Secp256k1KeyPair> =
    Lazy::new(|| Secp256k1KeyPair::generate(&mut StdRng::from_seed([1; 32])));

#[derive(Arbitrary, Debug)]
enum SignatureInput {
    Raw(Vec<u8>),
    /// The fixed key's signature on the message.
    Honest,
    /// The fixed key's signature on the message with one bit flipped.
    FlipBit(u16),
    /// The fixed key's signature on the message with s replaced by n - s.
    HighS,
}

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

fn sign(msg: &[u8], hash: u8) -> Vec<u8> {
    match hash {
        KECCAK256 => KEY.sign_with_hash::<Keccak256>(msg),
        _ => KEY.sign_with_hash::<Sha256>(msg),
    }
    .as_bytes()
    .to_vec()
}

/// Replaces s by n - s.
fn negate_s(signature: &[u8]) -> Vec<u8> {
    let s = k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&signature[32..])).unwrap();
    let mut bytes = signature.to_vec();
    bytes[32..].copy_from_slice(&(-s).to_bytes());
    bytes
}

/// What the Move native does.
fn secp256k1_verify(signature: &[u8], public_key: &[u8], msg: &[u8], hash: u8) -> bool {
    let Ok(sig) = <Secp256k1Signature as ToFromBytes>::from_bytes(signature) else {
        return false;
    };
    let Ok(pk) = Secp256k1PublicKey::from_bytes(public_key) else {
        return false;
    };
    match hash {
        KECCAK256 => pk.verify_with_hash::<Keccak256>(msg, &sig).is_ok(),
        SHA256 => pk.verify_with_hash::<Sha256>(msg, &sig).is_ok(),
        _ => false,
    }
}

fuzz_target!(|input: Input| {
    assert_real_crypto();
    let hash = input.hash;
    let signature = match &input.signature {
        SignatureInput::Raw(bytes) => bytes.clone(),
        SignatureInput::Honest => sign(&input.msg, hash),
        SignatureInput::FlipBit(bit) => {
            let mut bytes = sign(&input.msg, hash);
            let bit = *bit as usize % (bytes.len() * 8);
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        }
        SignatureInput::HighS => negate_s(&sign(&input.msg, hash)),
    };
    let public_key = match &input.public_key {
        PublicKeyInput::Raw(bytes) => bytes.clone(),
        PublicKeyInput::Fixed(encoding) => {
            let uncompressed = KEY.public().pubkey.serialize_uncompressed();
            match encoding % 3 {
                0 => KEY.public().as_bytes().to_vec(),
                1 => uncompressed.to_vec(),
                _ => {
                    let mut hybrid = uncompressed;
                    hybrid[0] = 0x06 | (uncompressed[64] & 1);
                    hybrid.to_vec()
                }
            }
        }
    };

    let verified = secp256k1_verify(&signature, &public_key, &input.msg, hash);

    // k256 agrees. It does not support hybrid encodings, so it is given the compressed encoding of
    // the decoded key.
    let k256_verified = match (
        Secp256k1PublicKey::from_bytes(&public_key),
        k256::ecdsa::Signature::try_from(signature.as_slice()),
    ) {
        (Ok(pk), Ok(sig)) if hash == KECCAK256 || hash == SHA256 => {
            let digest = match hash {
                KECCAK256 => Keccak256::digest(&input.msg).digest,
                _ => Sha256::digest(&input.msg).digest,
            };
            k256::ecdsa::VerifyingKey::from_sec1_bytes(pk.as_bytes())
                .unwrap()
                .verify_prehash(&digest, &sig)
                .is_ok()
        }
        _ => false,
    };
    assert_eq!(verified, k256_verified, "k256 disagrees");

    // The fixed key only accepts its own signature.
    if Secp256k1PublicKey::from_bytes(&public_key).is_ok_and(|pk| &pk == KEY.public()) {
        let honest = (hash == KECCAK256 || hash == SHA256) && signature == sign(&input.msg, hash);
        assert_eq!(verified, honest, "unexpected result for the fixed key");
    }
});
