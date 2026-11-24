// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Recovers public keys from (signature, message, hash function) inputs the way Sui's
//! `ecdsa_k1::secp256k1_ecrecover` Move native does (`from_bytes` for the 65-byte signature, then
//! `recover_with_hash` with Keccak-256 for flag 0 or SHA-256 for flag 1, returning the compressed
//! key), and decompresses public keys the way `ecdsa_k1::decompress_pubkey` does. The signature is
//! either arbitrary bytes or derived from a fixed key pair.
//!
//! Invariants: nothing panics; a recovered key is a valid compressed public key that verifies the
//! signature, also as a non-recoverable signature once s is normalized (so the output of
//! `secp256k1_ecrecover` is accepted by `secp256k1_verify`); recovery agrees with k256 for the
//! recovery ids k256 supports (0 and 1); the fixed key is only recovered from its own signature and
//! that signature's high-s form; and decompression agrees with k256 and round-trips.

#![no_main]

#[path = "secp256k1_common.rs"]
mod secp256k1_common;

use arbitrary::Arbitrary;
use fastcrypto::hash::{Keccak256, Sha256};
use fastcrypto::secp256k1::recoverable::Secp256k1RecoverableSignature;
use fastcrypto::secp256k1::{Secp256k1PublicKey, Secp256k1Signature};
use fastcrypto::traits::VerifyRecoverable;
use fastcrypto::traits::{KeyPair, RecoverableSignature, RecoverableSigner, ToFromBytes};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use libfuzzer_sys::fuzz_target;
use secp256k1_common::{
    assert_real_crypto, digest, negate_s, SignatureInput, KECCAK256, KEY, SHA256,
};

const RECOVERABLE_SIG_LENGTH: usize = 65;

#[derive(Arbitrary, Debug)]
struct Input {
    signature: SignatureInput,
    msg: Vec<u8>,
    hash: u8,
    public_key: Vec<u8>,
}

/// The fixed key's recoverable signature, with SHA-256 for flags other than Keccak-256.
fn sign(msg: &[u8], hash: u8) -> Vec<u8> {
    match hash {
        KECCAK256 => KEY.sign_recoverable_with_hash::<Keccak256>(msg),
        _ => KEY.sign_recoverable_with_hash::<Sha256>(msg),
    }
    .as_bytes()
    .to_vec()
}

/// Replaces s by n - s and flips the recovery id, which recovers the same key.
fn high_s(signature: &[u8]) -> Vec<u8> {
    let mut bytes = negate_s(signature);
    bytes[64] ^= 1;
    bytes
}

/// A recovered key is encoded compressed and verifies the signature, also as a non-recoverable
/// signature once s is normalized.
fn check_recovered_key(
    sig: &Secp256k1RecoverableSignature,
    pk: &Secp256k1PublicKey,
    msg: &[u8],
    hash: u8,
) {
    assert_eq!(&Secp256k1PublicKey::from_bytes(pk.as_bytes()).unwrap(), pk);
    let mut standard = Secp256k1Signature::from(sig).sig;
    standard.normalize_s();
    let standard =
        <Secp256k1Signature as ToFromBytes>::from_bytes(&standard.serialize_compact()).unwrap();
    if hash == KECCAK256 {
        assert!(pk
            .verify_recoverable_with_hash::<Keccak256>(msg, sig)
            .is_ok());
        assert!(pk.verify_with_hash::<Keccak256>(msg, &standard).is_ok());
    } else {
        assert!(pk.verify_recoverable_with_hash::<Sha256>(msg, sig).is_ok());
        assert!(pk.verify_with_hash::<Sha256>(msg, &standard).is_ok());
    }
}

/// Recovery with k256, which only supports the recovery ids 0 and 1.
fn k256_recover(signature: &[u8], digest: &[u8; 32]) -> Option<Vec<u8>> {
    let sig = k256::ecdsa::recoverable::Signature::try_from(signature).ok()?;
    let pk = sig
        .recover_verifying_key_from_digest_bytes(k256::FieldBytes::from_slice(digest))
        .ok()?;
    Some(pk.to_encoded_point(true).as_bytes().to_vec())
}

fuzz_target!(|input: Input| {
    assert_real_crypto();
    let honest = sign(&input.msg, input.hash);
    let signature = input.signature.bytes(&honest, &high_s(&honest));

    // What the secp256k1_ecrecover Move native does.
    let sig = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(&signature).ok();
    let recovered = match (&sig, input.hash) {
        (Some(sig), KECCAK256) => sig.recover_with_hash::<Keccak256>(&input.msg).ok(),
        (Some(sig), SHA256) => sig.recover_with_hash::<Sha256>(&input.msg).ok(),
        _ => None,
    };
    if let (Some(sig), Some(pk)) = (&sig, &recovered) {
        check_recovered_key(sig, pk, &input.msg, input.hash);
    }
    if let Some(digest) = digest(&input.msg, input.hash) {
        if signature.len() == RECOVERABLE_SIG_LENGTH && signature[64] <= 1 {
            assert_eq!(
                recovered.as_ref().map(|pk| pk.as_bytes().to_vec()),
                k256_recover(&signature, &digest),
                "k256 disagrees"
            );
        }
        assert_eq!(
            recovered.as_ref() == Some(KEY.public()),
            signature == honest || signature == high_s(&honest),
            "unexpected recovery of the fixed key"
        );
    }

    // What the decompress_pubkey Move native does.
    if let Ok(pk) = Secp256k1PublicKey::from_bytes(&input.public_key) {
        let uncompressed = pk.pubkey.serialize_uncompressed();
        assert_eq!(Secp256k1PublicKey::from_bytes(&uncompressed).unwrap(), pk);
        let k256_pk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk.as_bytes()).unwrap();
        assert_eq!(
            k256_pk.to_encoded_point(false).as_bytes(),
            &uncompressed[..]
        );
    }
});
