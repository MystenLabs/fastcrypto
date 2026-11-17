// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Decodes arbitrary bytes as every Ed25519 type, through every decoding path (`from_bytes`, BCS,
//! bincode, JSON and the `*AsBytes` representations).
//!
//! Invariants: nothing panics; public keys decode iff the bytes are 32 bytes that an independent
//! ZIP215 decoder accepts; signatures, private keys, key pairs and aggregates decode iff they have
//! the right length; every decoded value keeps its bytes; public keys compare and hash by their
//! bytes; key pairs derive the RFC 8032 public key; BCS and JSON agree with `from_bytes`.

#![no_main]

#[path = "ed25519_common.rs"]
mod ed25519_common;

use ed25519_common::{reference_decodes, reference_public_key, PK_LENGTH, SIG_LENGTH, SK_LENGTH};
use fastcrypto::ed25519::{
    Ed25519AggregateSignature, Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey,
    Ed25519PublicKeyAsBytes, Ed25519Signature, Ed25519SignatureAsBytes,
};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::traits::{KeyPair, ToFromBytes};
use libfuzzer_sys::fuzz_target;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fuzz_target!(|data: &[u8]| {
    let json = format!("\"{}\"", Base64::encode(data));

    // Public keys.
    let pk = Ed25519PublicKey::from_bytes(data);
    assert_eq!(pk.is_ok(), reference_decodes(data));
    if let Ok(pk) = &pk {
        assert_eq!(pk.as_bytes(), data);
        assert_eq!(hash_of(pk), hash_of(data));
        assert_eq!(bcs::to_bytes(pk).unwrap(), data);
    }
    assert_eq!(
        bcs::from_bytes::<Ed25519PublicKey>(data).ok(),
        pk.as_ref().ok().cloned()
    );
    assert_eq!(
        serde_json::from_str::<Ed25519PublicKey>(&json).ok(),
        pk.as_ref().ok().cloned()
    );
    let pk_bytes = bcs::from_bytes::<Ed25519PublicKeyAsBytes>(data);
    assert_eq!(pk_bytes.is_ok(), data.len() == PK_LENGTH);
    if let Ok(pk_bytes) = &pk_bytes {
        assert_eq!(
            Ed25519PublicKey::try_from(pk_bytes).ok(),
            pk.as_ref().ok().cloned()
        );
    }
    let _ = bincode::deserialize::<Ed25519PublicKey>(data);

    // Signatures and aggregate signatures.
    let sig = <Ed25519Signature as ToFromBytes>::from_bytes(data);
    assert_eq!(sig.is_ok(), data.len() == SIG_LENGTH);
    if let Ok(sig) = &sig {
        assert_eq!(sig.as_bytes(), data);
    }
    assert_eq!(
        bcs::from_bytes::<Ed25519Signature>(data).ok(),
        sig.as_ref().ok().cloned()
    );
    assert_eq!(
        serde_json::from_str::<Ed25519Signature>(&json).ok(),
        sig.as_ref().ok().cloned()
    );
    if let Ok(sig_bytes) = bcs::from_bytes::<Ed25519SignatureAsBytes>(data) {
        assert_eq!(Ed25519Signature::try_from(&sig_bytes).ok(), sig.ok());
    }
    let aggregate = Ed25519AggregateSignature::from_bytes(data);
    assert_eq!(aggregate.is_ok(), data.len().is_multiple_of(SIG_LENGTH));
    if let Ok(aggregate) = &aggregate {
        assert_eq!(aggregate.as_bytes(), data);
    }
    // BCS of an aggregate is a vector of length-prefixed signatures, and is canonical.
    if let Ok(aggregate) = bcs::from_bytes::<Ed25519AggregateSignature>(data) {
        assert_eq!(bcs::to_bytes(&aggregate).unwrap(), data);
    }
    let _ = bincode::deserialize::<Ed25519AggregateSignature>(data);

    // Private keys and key pairs: any 32 bytes are a seed.
    let kp = Ed25519KeyPair::from_bytes(data);
    assert_eq!(kp.is_ok(), data.len() == SK_LENGTH);
    assert_eq!(Ed25519PrivateKey::from_bytes(data).is_ok(), kp.is_ok());
    if let Ok(kp) = &kp {
        assert_eq!(kp.as_bytes(), data);
        assert_eq!(
            kp.public().as_bytes(),
            reference_public_key(data.try_into().unwrap())
        );
    }
    assert_eq!(bcs::from_bytes::<Ed25519KeyPair>(data).is_ok(), kp.is_ok());
    assert_eq!(
        serde_json::from_str::<Ed25519KeyPair>(&json).is_ok(),
        kp.is_ok()
    );

    // Any string as JSON.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<Ed25519PublicKey>(s);
        let _ = serde_json::from_str::<Ed25519Signature>(s);
        let _ = serde_json::from_str::<Ed25519AggregateSignature>(s);
        let _ = serde_json::from_str::<Ed25519KeyPair>(s);
    }
});
