// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Decodes arbitrary bytes as every secp256k1 signature-scheme type, through every decoding path
//! (`from_bytes`, BCS, bincode, JSON and the `*AsBytes` representations).
//!
//! Invariants: nothing panics; every accepted public key encoding is the compressed, uncompressed
//! or hybrid encoding of the decoded key, and `as_bytes` is the compressed one; `Eq`, `Hash` and
//! `Ord` agree with the compressed encoding; public keys and private keys are accepted iff k256
//! accepts them (except for the hybrid and compact encodings, which only one of them supports);
//! signatures are accepted iff r < n and s < n (and, for recoverable signatures, the recovery id is
//! at most 3) and keep their bytes; binary serde accepts exactly the fixed-length encodings that
//! `from_bytes` accepts; the `*AsBytes` representations accept any bytes of the right length and
//! convert like binary serde; and JSON agrees with `from_bytes`.

#![no_main]

#[path = "secp256k1_common.rs"]
mod secp256k1_common;

use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::secp256k1::recoverable::Secp256k1RecoverableSignature;
use fastcrypto::secp256k1::{
    Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1PublicKeyAsBytes,
    Secp256k1Signature, Secp256k1SignatureAsBytes,
};
use fastcrypto::traits::{KeyPair, ToFromBytes};
use hex_literal::hex;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use libfuzzer_sys::fuzz_target;
use secp256k1_common::assert_real_crypto;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const PK_LENGTH: usize = 33;
const UNCOMPRESSED_PK_LENGTH: usize = 65;
const SIG_LENGTH: usize = 64;
const RECOVERABLE_SIG_LENGTH: usize = 65;
const SK_LENGTH: usize = 32;

/// The order n of the secp256k1 group, big-endian.
const GROUP_ORDER: [u8; 32] =
    hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn json(data: &[u8]) -> String {
    format!("\"{}\"", Base64::encode(data))
}

fn check_public_key(data: &[u8]) {
    let pk = Secp256k1PublicKey::from_bytes(data);
    if let Ok(pk) = &pk {
        let uncompressed = pk.pubkey.serialize_uncompressed();
        let mut hybrid = uncompressed;
        hybrid[0] = 0x06 | (uncompressed[64] & 1);
        let encodings = [pk.as_bytes(), &uncompressed[..], &hybrid[..]];
        assert!(encodings.contains(&data), "unexpected public key encoding");
        assert_eq!(pk.as_bytes().len(), PK_LENGTH);
        let compressed = Secp256k1PublicKey::from_bytes(pk.as_bytes()).unwrap();
        assert_eq!(&compressed, pk);
        assert_eq!(hash_of(&compressed), hash_of(pk));
        assert_eq!(compressed.cmp(pk), std::cmp::Ordering::Equal);
    }

    let k256_pk = k256::ecdsa::VerifyingKey::from_sec1_bytes(data);
    match (data.len(), data.first()) {
        (UNCOMPRESSED_PK_LENGTH, Some(0x06 | 0x07)) => assert!(k256_pk.is_err()),
        (PK_LENGTH, Some(0x05)) => assert!(pk.is_err()),
        _ => {
            assert_eq!(pk.is_ok(), k256_pk.is_ok(), "k256 disagrees");
            if let (Ok(pk), Ok(k256_pk)) = (&pk, &k256_pk) {
                assert_eq!(pk.as_bytes(), k256_pk.to_encoded_point(true).as_bytes());
            }
        }
    }

    let bcs_pk = bcs::from_bytes::<Secp256k1PublicKey>(data);
    assert_eq!(
        bcs_pk.as_ref().ok(),
        pk.as_ref().ok().filter(|_| data.len() == PK_LENGTH)
    );
    let _ = bincode::deserialize::<Secp256k1PublicKey>(data);
    let pk_bytes = bcs::from_bytes::<Secp256k1PublicKeyAsBytes>(data);
    assert_eq!(pk_bytes.is_ok(), data.len() == PK_LENGTH);
    if let Ok(pk_bytes) = &pk_bytes {
        assert_eq!(Secp256k1PublicKey::try_from(pk_bytes).ok(), bcs_pk.ok());
    }
    assert_eq!(
        serde_json::from_str::<Secp256k1PublicKey>(&json(data)).ok(),
        pk.ok()
    );
}

fn check_signatures(data: &[u8]) {
    let in_range = |scalar: &[u8]| scalar < &GROUP_ORDER[..];

    let sig = <Secp256k1Signature as ToFromBytes>::from_bytes(data);
    assert_eq!(
        sig.is_ok(),
        data.len() == SIG_LENGTH && in_range(&data[..32]) && in_range(&data[32..])
    );
    if let Ok(sig) = &sig {
        assert_eq!(sig.as_bytes(), data);
        let again = <Secp256k1Signature as ToFromBytes>::from_bytes(sig.as_bytes()).unwrap();
        assert_eq!(&again, sig);
        assert_eq!(hash_of(&again), hash_of(sig));
    }
    let bcs_sig = bcs::from_bytes::<Secp256k1Signature>(data);
    assert_eq!(bcs_sig.as_ref().ok(), sig.as_ref().ok());
    let _ = bincode::deserialize::<Secp256k1Signature>(data);
    let sig_bytes = bcs::from_bytes::<Secp256k1SignatureAsBytes>(data);
    assert_eq!(sig_bytes.is_ok(), data.len() == SIG_LENGTH);
    if let Ok(sig_bytes) = &sig_bytes {
        assert_eq!(Secp256k1Signature::try_from(sig_bytes).ok(), bcs_sig.ok());
    }
    assert_eq!(
        serde_json::from_str::<Secp256k1Signature>(&json(data)).ok(),
        sig.ok()
    );

    let recoverable = <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(data);
    assert_eq!(
        recoverable.is_ok(),
        data.len() == RECOVERABLE_SIG_LENGTH
            && in_range(&data[..32])
            && in_range(&data[32..64])
            && data[64] <= 3
    );
    if let Ok(recoverable) = &recoverable {
        assert_eq!(recoverable.as_bytes(), data);
        let again =
            <Secp256k1RecoverableSignature as ToFromBytes>::from_bytes(recoverable.as_bytes())
                .unwrap();
        assert_eq!(&again, recoverable);
        assert_eq!(hash_of(&again), hash_of(recoverable));
        let standard = Secp256k1Signature::from(recoverable);
        assert_eq!(standard.as_bytes(), &data[..SIG_LENGTH]);
    }
    assert_eq!(
        bcs::from_bytes::<Secp256k1RecoverableSignature>(data).ok(),
        recoverable.as_ref().ok().cloned()
    );
    assert_eq!(
        serde_json::from_str::<Secp256k1RecoverableSignature>(&json(data)).ok(),
        recoverable.ok()
    );
}

fn check_private_key(data: &[u8]) {
    let kp = Secp256k1KeyPair::from_bytes(data);
    assert_eq!(Secp256k1PrivateKey::from_bytes(data).is_ok(), kp.is_ok());
    let k256_sk = if data.len() == SK_LENGTH {
        k256::ecdsa::SigningKey::from_bytes(data).ok()
    } else {
        None
    };
    assert_eq!(kp.is_ok(), k256_sk.is_some(), "k256 disagrees");
    if let (Ok(kp), Some(k256_sk)) = (&kp, &k256_sk) {
        assert_eq!(kp.as_bytes(), data);
        assert_eq!(
            kp.public().as_bytes(),
            k256_sk.verifying_key().to_encoded_point(true).as_bytes()
        );
    }
    assert_eq!(
        bcs::from_bytes::<Secp256k1KeyPair>(data).ok(),
        kp.ok().filter(|_| data.len() == SK_LENGTH)
    );
}

fuzz_target!(|data: &[u8]| {
    assert_real_crypto();
    check_public_key(data);
    check_signatures(data);
    check_private_key(data);

    // Human-readable serde on arbitrary strings.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Secp256k1PublicKey>(s);
        let _ = serde_json::from_str::<Secp256k1RecoverableSignature>(s);
        let _ = serde_json::from_str::<Secp256k1KeyPair>(s);
    }
});
