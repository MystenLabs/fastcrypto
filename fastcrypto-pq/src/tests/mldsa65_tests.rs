// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the fastcrypto trait layer over ML-DSA-65.
//!
//! The scheme itself is tested in the `mysten-mldsa-native-rs` wrapper, against
//! cross-implementation known-answer vectors. What is exercised here is everything this
//! crate adds on top: the trait implementations, serialization, encoding, and the
//! seed-as-private-key contract that the rest of Sui relies on.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use rand::rngs::StdRng;
use rand::SeedableRng as _;

use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::error::FastCryptoError;
use fastcrypto::traits::{
    EncodeDecodeBase64, InsecureDefault, KeyPair, Signer, ToFromBytes, VerifyingKey,
};

use crate::mldsa65::{
    MLDSA65KeyPair, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA65Signature,
    MLDSA65_PRIVATE_KEY_LENGTH, MLDSA65_PUBLIC_KEY_LENGTH, MLDSA65_SIGNATURE_LENGTH,
};

const MSG: &[u8] = b"Hello, world!";

fn keys() -> Vec<MLDSA65KeyPair> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    (0..4).map(|_| MLDSA65KeyPair::generate(&mut rng)).collect()
}

/// A key pair from a fixed seed, so a test can name the same key twice.
fn keypair_from_seed(byte: u8) -> MLDSA65KeyPair {
    MLDSA65PrivateKey::from_bytes(&[byte; MLDSA65_PRIVATE_KEY_LENGTH])
        .unwrap()
        .into()
}

#[test]
fn sign_verify_roundtrip() {
    let keypair = keys().pop().unwrap();
    let signature = keypair.sign(MSG);
    assert!(keypair.public().verify(MSG, &signature).is_ok());
}

#[test]
fn verify_rejects_wrong_message_and_wrong_key() {
    let keypair = keys().pop().unwrap();
    let other = keypair_from_seed(9);
    let signature = keypair.sign(MSG);

    assert_eq!(
        keypair.public().verify(b"Hello, world?", &signature),
        Err(FastCryptoError::InvalidSignature)
    );
    assert_eq!(
        other.public().verify(MSG, &signature),
        Err(FastCryptoError::InvalidSignature)
    );
}

#[test]
fn verify_rejects_tampered_signature() {
    let keypair = keys().pop().unwrap();
    let signature = keypair.sign(MSG);

    // Flip a bit in each region of the FIPS 204 encoding (c~, z, hints), not just the head.
    for offset in [
        0,
        MLDSA65_SIGNATURE_LENGTH / 2,
        MLDSA65_SIGNATURE_LENGTH - 1,
    ] {
        let mut bytes = signature.as_ref().to_vec();
        bytes[offset] ^= 1;
        let tampered = MLDSA65Signature::from_bytes(&bytes).unwrap();
        assert_eq!(
            keypair.public().verify(MSG, &tampered),
            Err(FastCryptoError::InvalidSignature),
            "tampering at offset {offset} was accepted"
        );
    }
}

#[test]
fn signing_is_hedged() {
    // Signing draws fresh randomness per call (the FIPS 204 default), so two signatures over
    // the same message differ while both verify. A deterministic scheme would break the
    // assumption Sui makes about signature uniqueness.
    let keypair = keys().pop().unwrap();
    let first = keypair.sign(MSG);
    let second = keypair.sign(MSG);
    assert_ne!(first, second);
    assert!(keypair.public().verify(MSG, &first).is_ok());
    assert!(keypair.public().verify(MSG, &second).is_ok());
}

#[test]
fn private_key_is_the_seed_and_expansion_is_deterministic() {
    // The private key's serialized form is the 32-byte FIPS 204 seed, and FIPS 204 fixes the
    // seed to key expansion. Both properties are load-bearing: wallets store the seed, and
    // the same recovery phrase must yield the same account everywhere.
    let seed = [7u8; MLDSA65_PRIVATE_KEY_LENGTH];
    let first = MLDSA65PrivateKey::from_bytes(&seed).unwrap();
    let second = MLDSA65PrivateKey::from_bytes(&seed).unwrap();

    assert_eq!(first.as_ref(), &seed);
    assert_eq!(first, second);
    assert_eq!(
        MLDSA65PublicKey::from(&first),
        MLDSA65PublicKey::from(&second)
    );
}

#[test]
fn keypair_bytes_are_only_the_private_key() {
    // Deserializing a key pair always re-derives the public key rather than trusting bytes
    // on the wire, so a mismatched pair cannot be constructed.
    let keypair = keys().pop().unwrap();
    assert_eq!(keypair.as_ref().len(), MLDSA65_PRIVATE_KEY_LENGTH);

    let restored = MLDSA65KeyPair::from_bytes(keypair.as_ref()).unwrap();
    assert_eq!(restored.public(), keypair.public());
    assert!(restored.public().verify(MSG, &restored.sign(MSG)).is_ok());
}

#[test]
fn to_from_bytes_roundtrip() {
    let keypair = keys().pop().unwrap();
    let signature = keypair.sign(MSG);

    let pk = MLDSA65PublicKey::from_bytes(keypair.public().as_ref()).unwrap();
    assert_eq!(&pk, keypair.public());

    let sig = MLDSA65Signature::from_bytes(signature.as_ref()).unwrap();
    assert_eq!(sig, signature);

    let sk = MLDSA65PrivateKey::from_bytes(keypair.as_ref()).unwrap();
    assert_eq!(sk.as_ref(), keypair.as_ref());
}

#[test]
fn from_bytes_rejects_wrong_lengths() {
    let keypair = keys().pop().unwrap();
    let signature = keypair.sign(MSG);

    for len in [
        0,
        MLDSA65_PUBLIC_KEY_LENGTH - 1,
        MLDSA65_PUBLIC_KEY_LENGTH + 1,
    ] {
        assert!(MLDSA65PublicKey::from_bytes(&vec![0u8; len]).is_err());
    }
    for len in [
        0,
        MLDSA65_SIGNATURE_LENGTH - 1,
        MLDSA65_SIGNATURE_LENGTH + 1,
    ] {
        assert!(MLDSA65Signature::from_bytes(&vec![0u8; len]).is_err());
    }
    for len in [
        0,
        MLDSA65_PRIVATE_KEY_LENGTH - 1,
        MLDSA65_PRIVATE_KEY_LENGTH + 1,
    ] {
        assert!(MLDSA65PrivateKey::from_bytes(&vec![0u8; len]).is_err());
    }

    // A correct-length signature that is not a valid encoding parses but must not verify.
    let mut bytes = signature.as_ref().to_vec();
    bytes.iter_mut().for_each(|b| *b = 0xff);
    if let Ok(sig) = MLDSA65Signature::from_bytes(&bytes) {
        assert!(keypair.public().verify(MSG, &sig).is_err());
    }
}

#[test]
fn serialize_deserialize() {
    let keypair = keys().pop().unwrap();
    let signature = keypair.sign(MSG);

    verify_serialization(keypair.public(), Some(keypair.public().as_ref()));
    verify_serialization(&signature, Some(signature.as_ref()));
}

/// Mirrors `fastcrypto::tests::test_helpers::verify_serialization`, which is not exported
/// across crate boundaries.
fn verify_serialization<T>(obj: &T, expected: Option<&[u8]>)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let bytes = bincode::serialize(obj).unwrap();
    let restored: T = bincode::deserialize(&bytes).unwrap();
    if let Some(exp) = expected {
        assert_eq!(bytes, exp);
    }
    assert_eq!(*obj, restored);
    // bincode and bcs must agree, so either can be swapped in later.
    assert_eq!(bytes, bcs::to_bytes(obj).unwrap());
    assert_eq!(restored, bcs::from_bytes::<T>(&bytes).unwrap());
}

#[test]
fn serde_human_readable_is_base64() {
    let keypair = keys().pop().unwrap();
    let signature = keypair.sign(MSG);

    let json = serde_json::to_string(&signature).unwrap();
    assert_eq!(json, format!("\"{}\"", Base64::encode(signature.as_ref())));
    let restored: MLDSA65Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, signature);

    let json = serde_json::to_string(keypair.public()).unwrap();
    assert_eq!(
        json,
        format!("\"{}\"", Base64::encode(keypair.public().as_ref()))
    );
}

#[test]
fn base64_encode_decode_roundtrip() {
    let keypair = keys().pop().unwrap();
    let encoded = keypair.public().encode_base64();
    let decoded = MLDSA65PublicKey::decode_base64(&encoded).unwrap();
    assert_eq!(&decoded, keypair.public());

    assert!(MLDSA65PublicKey::decode_base64("not base64!").is_err());
}

#[test]
fn keypair_from_str_roundtrip() {
    let keypair = keys().pop().unwrap();
    let encoded = keypair.encode_base64();
    let restored = MLDSA65KeyPair::from_str(&encoded).unwrap();
    assert_eq!(restored.public(), keypair.public());
}

#[test]
fn copy_key_pair_preserves_identity() {
    let keypair = keys().pop().unwrap();
    let copied = keypair.copy();
    assert_eq!(copied.public(), keypair.public());
    assert_eq!(copied.as_ref(), keypair.as_ref());
    assert!(keypair.public().verify(MSG, &copied.sign(MSG)).is_ok());
}

#[test]
fn generate_is_random() {
    let generated = keys();
    for (i, a) in generated.iter().enumerate() {
        for b in generated.iter().skip(i + 1) {
            assert_ne!(a.public(), b.public());
        }
    }
}

#[test]
fn insecure_default_is_not_a_usable_key() {
    let default = MLDSA65PublicKey::insecure_default();
    assert_eq!(default.as_ref(), &[0u8; MLDSA65_PUBLIC_KEY_LENGTH]);

    let keypair = keys().pop().unwrap();
    assert_eq!(
        default.verify(MSG, &keypair.sign(MSG)),
        Err(FastCryptoError::InvalidSignature)
    );
}

#[test]
fn public_key_ordering_and_hashing() {
    // Sui stores public keys in ordered and hashed collections, so both must be consistent
    // with equality.
    let keypair = keys().pop().unwrap();
    let same = MLDSA65PublicKey::from_bytes(keypair.public().as_ref()).unwrap();

    let hash = |pk: &MLDSA65PublicKey| {
        let mut h = DefaultHasher::new();
        pk.hash(&mut h);
        h.finish()
    };
    assert_eq!(hash(keypair.public()), hash(&same));
    assert_eq!(keypair.public().cmp(&same), std::cmp::Ordering::Equal);
}

#[test]
fn debug_output_is_redacted_for_secrets() {
    let keypair = keys().pop().unwrap();

    // Secret material must never appear in formatted output.
    let private = keypair.copy().private();
    assert!(!format!("{private:?}").contains(&Base64::encode(keypair.as_ref())));

    // Public types print their base64 form, which assertion failures rely on.
    assert_eq!(
        format!("{:?}", keypair.public()),
        Base64::encode(keypair.public().as_ref())
    );
}

#[test]
fn lengths_match_the_scheme() {
    assert_eq!(MLDSA65_PRIVATE_KEY_LENGTH, 32);
    assert_eq!(MLDSA65_PUBLIC_KEY_LENGTH, 1952);
    assert_eq!(MLDSA65_SIGNATURE_LENGTH, 3309);

    let keypair = keys().pop().unwrap();
    assert_eq!(keypair.public().as_ref().len(), MLDSA65_PUBLIC_KEY_LENGTH);
    assert_eq!(keypair.sign(MSG).as_ref().len(), MLDSA65_SIGNATURE_LENGTH);
}
