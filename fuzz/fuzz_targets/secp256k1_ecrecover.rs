// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Recovers public keys from (signature, message, hash function) inputs the way Sui's
//! `ecdsa_k1::secp256k1_ecrecover` Move native does (`from_bytes` for the 65-byte signature, then
//! `recover_with_hash` with Keccak-256 for flag 0 or SHA-256 for flag 1, returning the compressed
//! key), and decompresses public keys the way `ecdsa_k1::decompress_pubkey` does. The signature is
//! either arbitrary bytes or derived from a fixed key pair, so that the fuzzer also explores
//! signatures close to valid ones.
//!
//! Invariants: nothing panics; a recovered key is a valid compressed public key that verifies the
//! signature, also as a non-recoverable signature once s is normalized (so the output of
//! `secp256k1_ecrecover` is accepted by `secp256k1_verify`); recovery agrees with k256 for the
//! recovery ids k256 supports (0 and 1); the fixed key is only recovered from its own signature and
//! that signature's high-s form; and decompression agrees with k256 and round-trips.

#![no_main]

use arbitrary::Arbitrary;
use fastcrypto::hash::{HashFunction, Keccak256, Sha256};
use fastcrypto::secp256k1::recoverable::Secp256k1RecoverableSignature;
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PublicKey, Secp256k1Signature};
use fastcrypto::traits::VerifyRecoverable;
use fastcrypto::traits::{KeyPair, RecoverableSignature, RecoverableSigner, ToFromBytes};
use k256::elliptic_curve::sec1::ToEncodedPoint;
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
    /// The fixed key's recoverable signature on the message.
    Honest,
    /// The fixed key's recoverable signature on the message with one bit flipped.
    FlipBit(u16),
    /// The fixed key's recoverable signature on the message with s replaced by n - s and the
    /// recovery id flipped.
    HighS,
}

#[derive(Arbitrary, Debug)]
struct Input {
    signature: SignatureInput,
    msg: Vec<u8>,
    hash: u8,
    public_key: Vec<u8>,
}

fn sign(msg: &[u8], hash: u8) -> Vec<u8> {
    match hash {
        KECCAK256 => KEY.sign_recoverable_with_hash::<Keccak256>(msg),
        _ => KEY.sign_recoverable_with_hash::<Sha256>(msg),
    }
    .as_bytes()
    .to_vec()
}

/// Replaces s by n - s and flips the recovery id.
fn high_s(signature: &[u8]) -> Vec<u8> {
    let s = k256::Scalar::from_repr(*k256::FieldBytes::from_slice(&signature[32..64])).unwrap();
    let mut bytes = signature.to_vec();
    bytes[32..64].copy_from_slice(&(-s).to_bytes());
    bytes[64] ^= 1;
    bytes
}

fn digest(msg: &[u8], hash: u8) -> [u8; 32] {
    match hash {
        KECCAK256 => Keccak256::digest(msg).digest,
        _ => Sha256::digest(msg).digest,
    }
}

/// What the `secp256k1_ecrecover` Move native does.
fn secp256k1_ecrecover(signature: &[u8], msg: &[u8], hash: u8) -> Option<Vec<u8>> {
    let sig = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(signature).ok()?;
    let pk = match hash {
        KECCAK256 => sig.recover_with_hash::<Keccak256>(msg),
        SHA256 => sig.recover_with_hash::<Sha256>(msg),
        _ => return None,
    };
    pk.ok().map(|pk| pk.as_bytes().to_vec())
}

fn check_recovered_key(signature: &[u8], msg: &[u8], hash: u8, recovered: &[u8]) {
    let pk = Secp256k1PublicKey::from_bytes(recovered).unwrap();
    assert_eq!(pk.as_bytes(), recovered);
    let sig = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(signature).unwrap();
    let mut standard = Secp256k1Signature::from(&sig).sig;
    standard.normalize_s();
    let standard =
        <Secp256k1Signature as ToFromBytes>::from_bytes(&standard.serialize_compact()).unwrap();
    match hash {
        KECCAK256 => {
            assert!(pk
                .verify_recoverable_with_hash::<Keccak256>(msg, &sig)
                .is_ok());
            assert!(pk.verify_with_hash::<Keccak256>(msg, &standard).is_ok());
        }
        _ => {
            assert!(pk.verify_recoverable_with_hash::<Sha256>(msg, &sig).is_ok());
            assert!(pk.verify_with_hash::<Sha256>(msg, &standard).is_ok());
        }
    }
}

/// Recovery with k256, which only supports the recovery ids 0 and 1.
fn k256_recover(signature: &[u8], msg: &[u8], hash: u8) -> Option<Vec<u8>> {
    let sig = k256::ecdsa::recoverable::Signature::try_from(signature).ok()?;
    let pk = sig
        .recover_verifying_key_from_digest_bytes(k256::FieldBytes::from_slice(&digest(msg, hash)))
        .ok()?;
    Some(pk.to_encoded_point(true).as_bytes().to_vec())
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
        SignatureInput::HighS => high_s(&sign(&input.msg, hash)),
    };

    let recovered = secp256k1_ecrecover(&signature, &input.msg, hash);
    if let Some(recovered) = &recovered {
        check_recovered_key(&signature, &input.msg, hash, recovered);
    }
    if hash == KECCAK256 || hash == SHA256 {
        if signature.len() == 65 && signature[64] <= 1 {
            assert_eq!(
                recovered,
                k256_recover(&signature, &input.msg, hash),
                "k256 disagrees"
            );
        }
        let honest = sign(&input.msg, hash);
        assert_eq!(
            recovered.as_deref() == Some(KEY.public().as_bytes()),
            signature == honest || signature == high_s(&honest),
            "unexpected recovery of the fixed key"
        );
    }

    // decompress_pubkey.
    let pk = Secp256k1PublicKey::from_bytes(&input.public_key);
    if let Ok(pk) = &pk {
        let uncompressed = pk.pubkey.serialize_uncompressed();
        assert_eq!(&Secp256k1PublicKey::from_bytes(&uncompressed).unwrap(), pk);
        let k256_pk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk.as_bytes()).unwrap();
        assert_eq!(
            k256_pk.to_encoded_point(false).as_bytes(),
            &uncompressed[..]
        );
    }
});
