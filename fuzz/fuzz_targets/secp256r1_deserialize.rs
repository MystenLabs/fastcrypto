// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Decodes bytes as every secp256r1 type, through every decoding path (`from_bytes`, BCS, bincode,
//! JSON and the `*AsBytes` representations). The bytes are arbitrary or derived from the encodings
//! of a fixed key pair and its signatures.
//!
//! Invariants: nothing panics; public keys decode iff p256 accepts them, to the same point, except
//! that `from_bytes_strict` rejects the compact format; a key decoded from 33 bytes keeps them and
//! one decoded from 65 bytes is encoded compressed; a decoded key is equal to, hashes like and
//! compares equal to the key decoded from its compressed encoding; signatures decode iff they are
//! 64 bytes r || s with r and s in [1, n - 1], and recoverable signatures iff they are such a
//! signature followed by a recovery id in 0..=3; private keys and key pairs decode iff they are 32
//! bytes in [1, n - 1], and derive p256's public key; every decoded signature and private key keeps
//! its bytes; BCS, bincode, JSON and the `*AsBytes` types agree with `from_bytes`.

#![no_main]

#[path = "secp256r1_common.rs"]
mod secp256r1_common;

use arbitrary::Arbitrary;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::secp256r1::recoverable::Secp256r1RecoverableSignature;
use fastcrypto::secp256r1::{
    Secp256r1KeyPair, Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1PublicKeyAsBytes,
    Secp256r1Signature, Secp256r1SignatureAsBytes,
};
use fastcrypto::traits::{KeyPair, RecoverableSigner, Signer, ToFromBytes};
use libfuzzer_sys::fuzz_target;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use secp256r1_common::{
    GROUP_ORDER, KEY, PK_LENGTH, RECOVERABLE_SIG_LENGTH, SIG_LENGTH, SK_LENGTH,
};
use serde::de::DeserializeOwned;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

#[derive(Arbitrary, Debug)]
enum Base {
    Raw(Vec<u8>),
    CompressedPublicKey,
    UncompressedPublicKey,
    Signature,
    RecoverableSignature,
    PrivateKey,
}

#[derive(Arbitrary, Debug)]
struct Input {
    base: Base,
    /// A byte of the base to replace, and its new value.
    set_byte: Option<(u8, u8)>,
    /// A new length for the base, padding with zeros.
    resize: Option<u8>,
}

impl Input {
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = match &self.base {
            Base::Raw(raw) => raw.clone(),
            Base::CompressedPublicKey => KEY.public().as_bytes().to_vec(),
            Base::UncompressedPublicKey => KEY
                .public()
                .pubkey
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            Base::Signature => KEY.sign(b"").as_bytes().to_vec(),
            Base::RecoverableSignature => KEY.sign_recoverable(b"").as_bytes().to_vec(),
            Base::PrivateKey => KEY.secret.as_bytes().to_vec(),
        };
        if let (Some((index, value)), false) = (self.set_byte, bytes.is_empty()) {
            let len = bytes.len();
            bytes[index as usize % len] = value;
        }
        if let Some(len) = self.resize {
            bytes.resize(len as usize, 0);
        }
        bytes
    }
}

fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// BCS and bincode (which, unlike BCS, ignores trailing bytes) of a type encoded as a fixed-size
/// array, and JSON, which uses Base64, agree with `from_bytes`.
fn check_serde<T: DeserializeOwned + PartialEq + Debug>(
    data: &[u8],
    length: usize,
    from_bytes: impl Fn(&[u8]) -> Option<T>,
) {
    let expected = match data.len() == length {
        true => from_bytes(data),
        false => None,
    };
    assert_eq!(bcs::from_bytes::<T>(data).ok(), expected);
    let expected_bincode = match data.len() >= length {
        true => from_bytes(&data[..length]),
        false => None,
    };
    assert_eq!(bincode::deserialize::<T>(data).ok(), expected_bincode);
    let json = format!("\"{}\"", Base64::encode(data));
    assert_eq!(serde_json::from_str::<T>(&json).ok(), from_bytes(data));
}

fuzz_target!(|input: Input| {
    let data = &input.bytes()[..];

    // Public keys.
    let pk = Secp256r1PublicKey::from_bytes(data);
    let expected = p256::PublicKey::from_sec1_bytes(data);
    assert_eq!(pk.is_ok(), expected.is_ok());
    assert_eq!(
        Secp256r1PublicKey::from_bytes_strict(data).is_ok(),
        pk.is_ok() && data[0] != 0x05
    );
    if let Ok(pk) = &pk {
        let expected = expected.unwrap();
        assert_eq!(pk.pubkey.as_affine(), expected.as_affine());
        let compressed = expected.to_encoded_point(true);
        match data.len() {
            PK_LENGTH => assert_eq!(pk.as_bytes(), data),
            _ => assert_eq!(pk.as_bytes(), compressed.as_bytes()),
        }
        let compressed_pk = Secp256r1PublicKey::from_bytes(compressed.as_bytes()).unwrap();
        assert_eq!(pk, &compressed_pk);
        assert_eq!(hash_of(pk), hash_of(&compressed_pk));
        assert_eq!(pk.cmp(&compressed_pk), Ordering::Equal);
        assert_eq!(&Secp256r1PublicKey::from_bytes(pk.as_bytes()).unwrap(), pk);
    }
    check_serde(data, PK_LENGTH, |bytes| {
        Secp256r1PublicKey::from_bytes(bytes).ok()
    });
    if let Ok(pk_bytes) = bcs::from_bytes::<Secp256r1PublicKeyAsBytes>(data) {
        assert_eq!(
            Secp256r1PublicKey::try_from(&pk_bytes).ok(),
            pk.as_ref().ok().cloned()
        );
    }

    // Signatures.
    let sig = <Secp256r1Signature as ToFromBytes>::from_bytes(data);
    assert_eq!(
        sig.is_ok(),
        data.len() == SIG_LENGTH && p256::ecdsa::Signature::from_slice(data).is_ok()
    );
    if let Ok(sig) = &sig {
        assert_eq!(sig.as_bytes(), data);
    }
    check_serde(data, SIG_LENGTH, |bytes| {
        <Secp256r1Signature as ToFromBytes>::from_bytes(bytes).ok()
    });
    if let Ok(sig_bytes) = bcs::from_bytes::<Secp256r1SignatureAsBytes>(data) {
        assert_eq!(Secp256r1Signature::try_from(&sig_bytes).ok(), sig.ok());
    }

    // Recoverable signatures.
    let recoverable = <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(data);
    assert_eq!(
        recoverable.is_ok(),
        data.len() == RECOVERABLE_SIG_LENGTH
            && data[SIG_LENGTH] <= 3
            && p256::ecdsa::Signature::from_slice(&data[..SIG_LENGTH]).is_ok()
    );
    if let Ok(recoverable) = &recoverable {
        assert_eq!(recoverable.as_bytes(), data);
    }
    // Recoverable signatures compare without the recovery id, so compare their bytes.
    let recoverable_bytes = |bytes: &[u8]| {
        <Secp256r1RecoverableSignature as ToFromBytes>::from_bytes(bytes)
            .ok()
            .map(|sig| sig.as_bytes().to_vec())
    };
    assert_eq!(
        bcs::from_bytes::<Secp256r1RecoverableSignature>(data)
            .ok()
            .map(|sig| sig.as_bytes().to_vec()),
        match data.len() == RECOVERABLE_SIG_LENGTH {
            true => recoverable_bytes(data),
            false => None,
        }
    );
    let json = format!("\"{}\"", Base64::encode(data));
    assert_eq!(
        serde_json::from_str::<Secp256r1RecoverableSignature>(&json)
            .ok()
            .map(|sig| sig.as_bytes().to_vec()),
        recoverable_bytes(data)
    );

    // Private keys and key pairs.
    let sk = Secp256r1PrivateKey::from_bytes(data);
    let valid = data.len() == SK_LENGTH && data != [0; SK_LENGTH] && data < &GROUP_ORDER[..];
    assert_eq!(sk.is_ok(), valid);
    let kp = Secp256r1KeyPair::from_bytes(data);
    assert_eq!(kp.is_ok(), valid);
    if let (Ok(sk), Ok(kp)) = (&sk, &kp) {
        assert_eq!(sk.as_bytes(), data);
        assert_eq!(kp.as_bytes(), data);
        let expected = p256::ecdsa::SigningKey::from_slice(data).unwrap();
        assert_eq!(
            kp.public().as_bytes(),
            expected.verifying_key().to_encoded_point(true).as_bytes()
        );
    }
    check_serde(data, SK_LENGTH, |bytes| {
        Secp256r1PrivateKey::from_bytes(bytes).ok()
    });
    check_serde(data, SK_LENGTH, |bytes| {
        Secp256r1KeyPair::from_bytes(bytes).ok()
    });
});
