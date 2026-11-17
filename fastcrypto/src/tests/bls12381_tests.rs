// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::Encoding;
use crate::error::FastCryptoError;
use crate::test_helpers::{signature_test_inputs_different_msg, verify_serialization};
use crate::traits::InsecureDefault;
use crate::traits::Signer;
use crate::{
    bls12381::{BLS_G1_LENGTH, BLS_G2_LENGTH, BLS_PRIVATE_KEY_LENGTH},
    encoding::{Base64, Hex},
    hash::{HashFunction, Sha256, Sha3_256},
    hmac::hkdf_generate_from_ikm,
    traits::{
        AggregateAuthenticator, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey,
        ToFromBytes, VerifyingKey,
    },
};
use proptest::{collection, prelude::*};
use rand::{rngs::StdRng, RngCore, SeedableRng as _};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

// We use the following macro in order to run all tests for both min_sig and min_pk.
macro_rules! define_tests { () => {
//
// Helper functions
//

pub fn keys() -> Vec<BLS12381KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| BLS12381KeyPair::generate(&mut rng))
        .collect()
}

const PK_LENGTH: usize = <BLS12381PublicKey as VerifyingKey>::LENGTH;
const SIG_LENGTH: usize = <BLS12381Signature as Authenticator>::LENGTH;

/// The BLS12-381 scalar field modulus r, big-endian.
const GROUP_ORDER: [u8; 32] =
    hex_literal("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

// Flags in the first byte of a serialized point (see https://github.com/supranational/blst#serialization-format).
const COMPRESSION_FLAG: u8 = 0x80;
const INFINITY_FLAG: u8 = 0x40;
const SORT_FLAG: u8 = 0x20;

const fn hex_literal<const N: usize>(s: &str) -> [u8; N] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len() == 2 * N);
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

fn infinity_encoding(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    bytes[0] = COMPRESSION_FLAG | INFINITY_FLAG;
    bytes
}

/// Compressed G1 point with x = 4. It is on the curve but not in the prime order subgroup.
const NON_SUBGROUP_G1: [u8; BLS_G1_LENGTH] = hex_literal(
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004",
);

/// Compressed G2 point with x = 2 (that is, c1 = 0 and c0 = 2). It is on the curve but not in the
/// prime order subgroup.
const NON_SUBGROUP_G2: [u8; BLS_G2_LENGTH] = hex_literal(
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
);

/// `NON_SUBGROUP_G1` with x = p + 4 instead of 4, that is, the same field element not reduced
/// modulo p (p ends in ...aaab, so adding 4 does not carry).
const UNREDUCED_G1: [u8; BLS_G1_LENGTH] = hex_literal(
    "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaf",
);

/// `NON_SUBGROUP_G2` with c0 = p + 2 instead of 2.
const UNREDUCED_G2: [u8; BLS_G2_LENGTH] = hex_literal(
    "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaad",
);

/// A public key of this mode that is on the curve but not in the prime order subgroup.
const NON_SUBGROUP_PUBLIC_KEY: &[u8] =
    if PK_LENGTH == BLS_G1_LENGTH { &NON_SUBGROUP_G1 } else { &NON_SUBGROUP_G2 };

/// A signature of this mode that is on the curve but not in the prime order subgroup.
const NON_SUBGROUP_SIGNATURE: &[u8] =
    if SIG_LENGTH == BLS_G1_LENGTH { &NON_SUBGROUP_G1 } else { &NON_SUBGROUP_G2 };

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn uncompressed_public_key(pk: &BLS12381PublicKey) -> Vec<u8> {
    pk.pubkey.serialize().to_vec()
}

fn uncompressed_signature(sig: &BLS12381Signature) -> Vec<u8> {
    sig.sig.serialize().to_vec()
}

fn signature_test_inputs() -> (Vec<u8>, Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let (pubkeys, signatures): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();

    (message.to_vec(), pubkeys, signatures)
}

fn verify_batch_aggregate_signature_inputs() -> (
    Vec<u8>,
    Vec<u8>,
    Vec<BLS12381PublicKey>,
    Vec<BLS12381PublicKey>,
    BLS12381AggregateSignature,
    BLS12381AggregateSignature,
) {
    // Make signatures.
    let message1: &[u8] = b"Hello, world!";
    let (pubkeys1, signatures1): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message1);
            (kp.public().clone(), sig)
        })
        .unzip();
    let aggregated_signature1 = BLS12381AggregateSignature::aggregate(&signatures1).unwrap();

    // Make signatures.
    let message2: &[u8] = b"Hello, world?";
    let (pubkeys2, signatures2): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(2)
        .map(|kp| {
            let sig = kp.sign(message2);
            (kp.public().clone(), sig)
        })
        .unzip();

    let aggregated_signature2 = BLS12381AggregateSignature::aggregate(&signatures2).unwrap();
    (
        message1.to_vec(),
        message2.to_vec(),
        pubkeys1,
        pubkeys2,
        aggregated_signature1,
        aggregated_signature2,
    )
}

/// Builds an aggregate the way Sui does: start from the default (infinity) and add signatures.
fn aggregate_from_default(sigs: &[BLS12381Signature]) -> BLS12381AggregateSignature {
    let mut aggregate = BLS12381AggregateSignature::default();
    for sig in sigs {
        aggregate.add_signature(sig.clone()).unwrap();
    }
    aggregate
}

/// Aggregates the two halves recursively and then combines them with `add_aggregate`.
fn aggregate_treewise(sigs: &[BLS12381Signature]) -> BLS12381AggregateSignature {
    if sigs.len() <= 1 {
        return aggregate_from_default(sigs);
    }
    let (left, right) = sigs.split_at(sigs.len() / 2);
    let mut res = BLS12381AggregateSignature::default();
    res.add_aggregate(aggregate_treewise(left)).unwrap();
    res.add_aggregate(aggregate_treewise(right)).unwrap();
    res
}

/// Aggregates the signatures of three fixed keys on a fixed message and compares with `expected`.
/// Called from the mode-specific regression tests below.
fn check_aggregate_regression(expected: &str) {
    let secrets = [
        "266f9708fd8d3b462b10cdbf5498076c021eb3acfdd47cb1fef647967fe194fb",
        "0bd9b34ac8b5d8ec5e1a8b4a5c1bbd74fbbd2a0d8f5ea1f3ff2e1c3b4a597886",
        "3a7c2ea5e04f0c6c8bd3e6c4e9e4c0b5f2c1d1a2b3c4d5e6f708192a3b4c5d6e",
    ];
    let message = b"hello, narwhal";
    let (pks, sigs): (Vec<_>, Vec<_>) = secrets
        .iter()
        .map(|s| {
            let sk = BLS12381PrivateKey::from_bytes(&hex::decode(s).unwrap()).unwrap();
            (BLS12381PublicKey::from(&sk), sk.sign(message))
        })
        .unzip();
    let aggregate = BLS12381AggregateSignature::aggregate(&sigs).unwrap();
    assert_eq!(Hex::encode(aggregate.as_bytes()), expected);
    assert!(aggregate.verify(&pks, message).is_ok());
}

//
// Serialization tests
//

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = BLS12381PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(&import.unwrap(), public_key);
}

#[test]
#[cfg(feature = "copy_key")]
fn serialize_private_key_only_for_keypair() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|kp| {
        let sk = kp.copy().private();
        let serialized_kp = bincode::serialize(&kp).unwrap();
        let serialized_sk = bincode::serialize(&sk).unwrap();
        assert_eq!(serialized_sk, serialized_kp);
    });
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = BLS12381PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <BLS12381Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig, signature);
}

#[test]
fn test_serialize_deserialize_standard_sig() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    pk.validate().unwrap(); // just a sanity check
    let sk = kp.private();
    let message = b"hello, narwhal";
    let sig = keys().pop().unwrap().sign(message);
    let default_sig = BLS12381Signature::default();

    verify_serialization(&pk, Some(pk.as_bytes()));
    verify_serialization(&sk, Some(sk.as_bytes()));
    verify_serialization(&sig, Some(sig.as_bytes()));
    verify_serialization(&default_sig, Some(default_sig.as_bytes()));

    let kp = keys().pop().unwrap();
    verify_serialization(&kp, Some(kp.as_bytes()));
    let kp_b64 = kp.encode_base64();
    assert_eq!(BLS12381KeyPair::from_str(&kp_b64).unwrap(), kp);
}

#[test]
fn test_serialize_deserialize_aggregate_signatures() {
    // Default aggregated sig
    let default_sig = BLS12381AggregateSignature::default();
    verify_serialization(&default_sig, Some(default_sig.as_bytes()));
    assert_eq!(default_sig.as_bytes(), BLS12381Signature::default().as_bytes());
    // Standard aggregated sig
    let message = b"hello, narwhal";
    let (_, signatures): (Vec<BLS12381PublicKey>, Vec<BLS12381Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(message);
            (kp.public().clone(), sig)
        })
        .unzip();
    let sig = BLS12381AggregateSignature::aggregate(&signatures).unwrap();
    verify_serialization(&sig, Some(sig.as_bytes()));
    // BLS12381AggregateSignatureAsBytes
    let sig_as_bytes = BLS12381AggregateSignatureAsBytes::from(&sig);
    verify_serialization(&sig_as_bytes, Some(sig.as_bytes()));
}

#[test]
fn test_human_readable_signatures() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);

    let serialized = serde_json::to_string(&signature).unwrap();
    assert_eq!(
        format!(
            "\"{}\"",
            Base64::encode(&signature.sig.to_bytes())
        ),
        serialized
    );
    let deserialized: BLS12381Signature = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, signature);
}

// `from_bytes` (and therefore base64 and human-readable serde) accepts both the compressed and the
// uncompressed encodings, while `as_bytes` and binary serde always use the compressed one. Callers
// must therefore not use raw input bytes as an identity. These tests pin that behaviour.
#[test]
fn test_uncompressed_encodings_are_accepted_and_reencoded_compressed() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let sig = kp.sign(b"message");
    let aggregate = BLS12381AggregateSignature::from(sig.clone());

    let pk_uncompressed = uncompressed_public_key(&pk);
    assert_eq!(pk_uncompressed.len(), 2 * PK_LENGTH);
    let pk2 = BLS12381PublicKey::from_bytes(&pk_uncompressed).unwrap();
    assert_eq!(pk2, pk);
    assert_eq!(pk2.as_bytes(), pk.as_bytes());
    assert_eq!(pk2.as_bytes().len(), PK_LENGTH);
    assert!(pk2.validate().is_ok());

    let sig_uncompressed = uncompressed_signature(&sig);
    assert_eq!(sig_uncompressed.len(), 2 * SIG_LENGTH);
    let sig2 = <BLS12381Signature as ToFromBytes>::from_bytes(&sig_uncompressed).unwrap();
    assert_eq!(sig2, sig);
    assert_eq!(sig2.as_bytes(), sig.as_bytes());
    assert!(pk.verify(b"message", &sig2).is_ok());

    let aggregate2 = BLS12381AggregateSignature::from_bytes(&sig_uncompressed).unwrap();
    assert_eq!(aggregate2, aggregate);
    assert_eq!(aggregate2.as_bytes(), aggregate.as_bytes());

    // Hash and Ord agree with Eq whatever the input encoding, because both use the compressed bytes.
    assert_eq!(hash_of(&pk2), hash_of(&pk));
    assert_eq!(pk2.cmp(&pk), std::cmp::Ordering::Equal);
    assert_eq!(hash_of(&sig2), hash_of(&sig));

    // Base64 and human-readable serde go through from_bytes, so they accept it as well.
    let pk3 = BLS12381PublicKey::decode_base64(&Base64::encode(&pk_uncompressed)).unwrap();
    assert_eq!(pk3, pk);
    let json = format!("\"{}\"", Base64::encode(&sig_uncompressed));
    let sig3: BLS12381Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig3, sig);
    // ... but serializing again gives the compressed encoding.
    assert_eq!(
        serde_json::to_string(&sig3).unwrap(),
        format!("\"{}\"", Base64::encode(sig.as_bytes()))
    );

    // Binary serde reads exactly the compressed length, so it rejects the uncompressed encoding
    // (its first half lacks the compression flag, and the second half is trailing data).
    assert!(bcs::from_bytes::<BLS12381PublicKey>(&pk_uncompressed).is_err());
    assert!(bcs::from_bytes::<BLS12381Signature>(&sig_uncompressed).is_err());
    assert!(bcs::from_bytes::<BLS12381AggregateSignature>(&sig_uncompressed).is_err());
}

#[test]
fn test_bytes_representations() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let aggregate = BLS12381AggregateSignature::from(kp.sign(b"message"));

    // A bytes representation holds the compressed encoding and converts back to the same value.
    let pk_bytes = BLS12381PublicKeyAsBytes::from(&pk);
    assert_eq!(pk_bytes.0, pk.as_bytes());
    assert_eq!(BLS12381PublicKey::try_from(&pk_bytes).unwrap(), pk);
    let aggregate_bytes = BLS12381AggregateSignatureAsBytes::from(&aggregate);
    assert_eq!(aggregate_bytes.0, aggregate.as_bytes());
    assert_eq!(
        BLS12381AggregateSignature::try_from(&aggregate_bytes).unwrap(),
        aggregate
    );

    // Deserializing a bytes representation does not validate it: any bytes of the right length
    // are accepted, and only the conversion to the key or signature can fail.
    let pk_bytes: BLS12381PublicKeyAsBytes = bcs::from_bytes(&[0xff; PK_LENGTH]).unwrap();
    assert!(BLS12381PublicKey::try_from(&pk_bytes).is_err());
    let aggregate_bytes: BLS12381AggregateSignatureAsBytes =
        bcs::from_bytes(&[0xff; SIG_LENGTH]).unwrap();
    assert!(BLS12381AggregateSignature::try_from(&aggregate_bytes).is_err());

    // Like from_bytes, the conversion does not check subgroup membership.
    let pk_bytes: BLS12381PublicKeyAsBytes = bcs::from_bytes(NON_SUBGROUP_PUBLIC_KEY).unwrap();
    assert!(BLS12381PublicKey::try_from(&pk_bytes).unwrap().validate().is_err());

    // Human-readable serde uses base64 of exactly the compressed length, so the uncompressed
    // encoding is rejected.
    let pk_bytes = BLS12381PublicKeyAsBytes::from(&pk);
    let json = serde_json::to_string(&pk_bytes).unwrap();
    assert_eq!(json, format!("\"{}\"", Base64::encode(pk.as_bytes())));
    assert_eq!(serde_json::from_str::<BLS12381PublicKeyAsBytes>(&json).unwrap(), pk_bytes);
    let json = format!("\"{}\"", Base64::encode(uncompressed_public_key(&pk)));
    assert!(serde_json::from_str::<BLS12381PublicKeyAsBytes>(&json).is_err());
}

#[test]
fn test_reject_wrong_lengths() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().as_bytes().to_vec();
    let sig = kp.sign(b"message").as_bytes().to_vec();
    // Only the compressed and the uncompressed lengths are accepted.
    let wrong_lengths = |compressed: usize| {
        (0..=3 * compressed).filter(move |&len| len != compressed && len != 2 * compressed)
    };
    for len in wrong_lengths(PK_LENGTH) {
        let bytes: Vec<u8> = pk.iter().cycle().take(len).copied().collect();
        assert!(BLS12381PublicKey::from_bytes(&bytes).is_err(), "pk length {}", len);
    }
    for len in wrong_lengths(SIG_LENGTH) {
        let bytes: Vec<u8> = sig.iter().cycle().take(len).copied().collect();
        assert!(
            <BLS12381Signature as ToFromBytes>::from_bytes(&bytes).is_err(),
            "sig length {}",
            len
        );
        assert!(
            BLS12381AggregateSignature::from_bytes(&bytes).is_err(),
            "aggregate sig length {}",
            len
        );
    }
}

#[test]
fn test_reject_non_canonical_point_encodings() {
    fn check(name: &str, valid: &[u8], decode: impl Fn(&[u8]) -> bool) {
        let len = valid.len();
        assert!(decode(valid), "{}: the valid encoding must decode", name);

        // Compressed length without the compression flag.
        let mut bytes = valid.to_vec();
        bytes[0] &= !COMPRESSION_FLAG;
        assert!(!decode(&bytes), "{}: missing compression flag", name);

        // Uncompressed length with the compression flag set.
        let mut bytes = valid.to_vec();
        bytes.extend_from_slice(valid);
        bytes[0] |= COMPRESSION_FLAG;
        assert!(!decode(&bytes), "{}: compression flag on uncompressed length", name);

        // Infinity flag with a non-zero body.
        let mut bytes = infinity_encoding(len);
        bytes[len - 1] = 1;
        assert!(!decode(&bytes), "{}: infinity with non-zero body", name);

        // Infinity flag on top of a valid point.
        let mut bytes = valid.to_vec();
        bytes[0] |= INFINITY_FLAG;
        assert!(!decode(&bytes), "{}: infinity flag on a point", name);

        // Infinity flag without the compression flag at the compressed length.
        let mut bytes = infinity_encoding(len);
        bytes[0] &= !COMPRESSION_FLAG;
        assert!(!decode(&bytes), "{}: infinity without compression flag", name);

        // Sort flag on the infinity point.
        let mut bytes = infinity_encoding(len);
        bytes[0] |= SORT_FLAG;
        assert!(!decode(&bytes), "{}: sort flag on infinity", name);

        // A coordinate that is not reduced modulo p: x + p encodes the same field element as x.
        let (reduced, unreduced): (&[u8], &[u8]) = if len == BLS_G1_LENGTH {
            (&NON_SUBGROUP_G1, &UNREDUCED_G1)
        } else {
            (&NON_SUBGROUP_G2, &UNREDUCED_G2)
        };
        assert!(decode(reduced), "{}: x", name);
        assert!(!decode(unreduced), "{}: x + p", name);
    }

    let kp = keys().pop().unwrap();
    let sig = kp.sign(b"message");
    check("public key", kp.public().as_bytes(), |b| {
        BLS12381PublicKey::from_bytes(b).is_ok()
    });
    check("signature", sig.as_bytes(), |b| {
        <BLS12381Signature as ToFromBytes>::from_bytes(b).is_ok()
    });
    check("aggregate signature", sig.as_bytes(), |b| {
        BLS12381AggregateSignature::from_bytes(b).is_ok()
    });
}

#[test]
fn test_infinity_encodings() {
    // The canonical compressed encoding of infinity decodes, for both keys and signatures.
    let pk = BLS12381PublicKey::from_bytes(&infinity_encoding(PK_LENGTH)).unwrap();
    assert_eq!(pk.as_bytes(), infinity_encoding(PK_LENGTH).as_slice());
    // ... but it is not a valid public key.
    assert!(pk.validate().is_err());

    let sig = <BLS12381Signature as ToFromBytes>::from_bytes(&infinity_encoding(SIG_LENGTH)).unwrap();
    assert_eq!(sig, BLS12381Signature::default());
    assert_eq!(sig.as_bytes(), infinity_encoding(SIG_LENGTH).as_slice());

    // The uncompressed encoding of infinity (only the infinity flag, all zero body) decodes too.
    let mut uncompressed = vec![0u8; 2 * PK_LENGTH];
    uncompressed[0] = INFINITY_FLAG;
    assert_eq!(BLS12381PublicKey::from_bytes(&uncompressed).unwrap(), pk);

    // The default public key is infinity as well.
    assert_eq!(BLS12381PublicKey::insecure_default(), pk);
}

#[test]
fn test_non_subgroup_points_decode_but_do_not_validate() {
    // from_bytes does not check subgroup membership (documented), validate does.
    let pk = BLS12381PublicKey::from_bytes(NON_SUBGROUP_PUBLIC_KEY).unwrap();
    assert!(pk.validate().is_err());
    let sig = <BLS12381Signature as ToFromBytes>::from_bytes(NON_SUBGROUP_SIGNATURE).unwrap();
    assert!(sig.sig.validate(false).is_err());

    // Points from honest key generation and signing are in the subgroup.
    let kp = keys().pop().unwrap();
    assert!(kp.public().validate().is_ok());
    assert!(kp.sign(b"message").sig.validate(false).is_ok());
}

#[test]
fn test_private_key_range() {
    let zero = [0u8; BLS_PRIVATE_KEY_LENGTH];
    assert!(BLS12381PrivateKey::from_bytes(&zero).is_err());

    let mut one = zero;
    one[BLS_PRIVATE_KEY_LENGTH - 1] = 1;
    assert!(BLS12381PrivateKey::from_bytes(&one).is_ok());

    assert!(BLS12381PrivateKey::from_bytes(&GROUP_ORDER).is_err());

    let mut order_minus_one = GROUP_ORDER;
    order_minus_one[BLS_PRIVATE_KEY_LENGTH - 1] -= 1;
    let sk = BLS12381PrivateKey::from_bytes(&order_minus_one).unwrap();
    assert_eq!(sk.as_bytes(), order_minus_one);

    let mut order_plus_one = GROUP_ORDER;
    order_plus_one[BLS_PRIVATE_KEY_LENGTH - 1] += 1;
    assert!(BLS12381PrivateKey::from_bytes(&order_plus_one).is_err());

    assert!(BLS12381PrivateKey::from_bytes(&[0xff; BLS_PRIVATE_KEY_LENGTH]).is_err());

    for len in [0, 1, BLS_PRIVATE_KEY_LENGTH - 1, BLS_PRIVATE_KEY_LENGTH + 1, 64] {
        assert!(BLS12381PrivateKey::from_bytes(&vec![1u8; len]).is_err(), "length {}", len);
        assert!(BLS12381KeyPair::from_bytes(&vec![1u8; len]).is_err(), "length {}", len);
    }
}

//
// Signature verification tests
//

#[test]
fn test_pk_verify() {
    let kp = keys().pop().unwrap();
    let message: &[u8] = b"Hello, world!";
    let signature = kp.sign(message);
    assert!(kp.public().verify(message, &signature).is_ok());

    // Invalid signatures - different message and an empty message.
    let other_message: &[u8] = b"Bad message!";
    assert!(kp.public().verify(other_message, &signature).is_err());
    assert!(kp.public().verify(&[], &signature).is_err());
}

#[test]
fn test_verify_rejects_signature_from_other_key() {
    let keys = keys();
    let sig = keys[0].sign(b"message");
    assert!(keys[0].public().verify(b"message", &sig).is_ok());
    for kp in &keys[1..] {
        assert!(kp.public().verify(b"message", &sig).is_err());
    }
}

#[test]
fn test_verify_empty_and_long_messages() {
    let kp = keys().pop().unwrap();
    let long_message = vec![0xab; 1 << 20];
    for message in [&[][..], &[0u8][..], &long_message[..]] {
        let sig = kp.sign(message);
        assert!(kp.public().verify(message, &sig).is_ok());
    }
    let sig = kp.sign(&long_message);
    assert!(kp.public().verify(&long_message[1..], &sig).is_err());
}

#[test]
fn test_verify_rejects_infinity_and_non_subgroup_public_keys() {
    let message = b"message";
    let valid_sig = keys().pop().unwrap().sign(message);
    let infinity_pk = BLS12381PublicKey::from_bytes(&infinity_encoding(PK_LENGTH)).unwrap();
    let non_subgroup_pk = BLS12381PublicKey::from_bytes(NON_SUBGROUP_PUBLIC_KEY).unwrap();
    let signatures = [
        valid_sig.clone(),
        BLS12381Signature::default(),
        <BLS12381Signature as ToFromBytes>::from_bytes(NON_SUBGROUP_SIGNATURE).unwrap(),
    ];
    for pk in [&infinity_pk, &non_subgroup_pk] {
        for sig in &signatures {
            assert!(pk.verify(message, sig).is_err());
            let aggregate = BLS12381AggregateSignature::from(sig.clone());
            assert!(aggregate.verify(std::slice::from_ref(pk), message).is_err());
        }
    }
}

#[test]
fn test_verify_rejects_non_subgroup_signature() {
    let kp = keys().pop().unwrap();
    let sig = <BLS12381Signature as ToFromBytes>::from_bytes(NON_SUBGROUP_SIGNATURE).unwrap();
    assert!(kp.public().verify(b"message", &sig).is_err());
    let aggregate = BLS12381AggregateSignature::from(sig);
    assert!(aggregate.verify(std::slice::from_ref(kp.public()), b"message").is_err());
    assert!(aggregate
        .verify_different_msg(std::slice::from_ref(kp.public()), &[b"message"])
        .is_err());
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures[0] = BLS12381Signature::default();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = BLS12381PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = BLS12381PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = signature_test_inputs_different_msg::<BLS12381KeyPair>();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {

    // Should fail on empty inputs
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg::<&[u8]>(
        &[],
        &[],
        &[],
    );
    assert!(res.is_err(), "{:?}", res);

    // Should fail on mismatch in input sizes
    let mut inputs = signature_test_inputs_different_msg::<BLS12381KeyPair>();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests[0..2],
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);

    // Should fail with one invalid signature
    inputs.signatures[0] = BLS12381Signature::default();
    let res = BLS12381PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

//
// Aggregated signatures and batch verification tests
//

#[test]
fn batch_verify_aggregate_signature() {
    let (msg1, msg2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&msg1[..], &msg2[..]]
    )
    .is_ok());

    // Test failure when checking with a wrong message.
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&msg1[..], &msg1[..]]
    )
    .is_err());
}

#[test]
fn batch_verify_missing_parameters_length_mismatch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // Fewer PubKeys than signatures
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());

    // Fewer messages than signatures
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2.iter()],
        &[&digest1[..]]
    )
    .is_err());
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter()],
        &[&digest1[..]]
    )
    .is_err());
}

#[test]
fn batch_verify_missing_keys_in_batch() {
    let (digest1, digest2, pubkeys1, pubkeys2, aggregated_signature1, aggregated_signature2) =
        verify_batch_aggregate_signature_inputs();

    // PubKeys missing at the end
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[1..].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // PubKeys missing at the start
    assert!(BLS12381AggregateSignature::batch_verify(
        &[&aggregated_signature1, &aggregated_signature2],
        vec![pubkeys1.iter(), pubkeys2[..pubkeys2.len() - 1].iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());

    // add an extra signature to both aggregated_signature that batch_verify takes in
    let mut signatures1_with_extra = aggregated_signature1;
    let kp = &keys()[0];
    let sig = kp.sign(&digest1);
    let res = signatures1_with_extra.add_signature(sig);
    assert!(res.is_ok());

    let mut signatures2_with_extra = aggregated_signature2;
    let kp = &keys()[0];
    let sig2 = kp.sign(&digest1);
    let res = signatures2_with_extra.add_signature(sig2);
    assert!(res.is_ok());

    assert!(BLS12381AggregateSignature::batch_verify(
        &[&signatures1_with_extra, &signatures2_with_extra],
        vec![pubkeys1.iter()],
        &[&digest1[..], &digest2[..]]
    )
    .is_err());
}

#[test]
fn test_add_signatures_to_aggregate() {
    let pks: Vec<BLS12381PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let message = b"hello, narwhal";

    // Test 'add signature'
    let mut sig1 = BLS12381AggregateSignature::default();
    assert!(sig1.verify(&pks, message).is_err());

    // Test populated aggregate signature
    keys().into_iter().take(3).enumerate().for_each(|(i, kp)| {
        let sig = kp.sign(message);
        sig1.add_signature(sig).unwrap();

        // Verify that the binary representation (the OnceCell) is updated for each added signature
        let reconstructed = BLS12381AggregateSignature::from_bytes(sig1.as_ref()).unwrap();
        assert!(reconstructed.verify(&pks[..i], message).is_err());
        assert!(reconstructed.verify(&pks[..i+1], message).is_ok());
    });

    assert!(sig1.verify(&pks, message).is_ok());
    let other_message = b"hello, narwhal2";
    assert!(sig1.verify(&pks, other_message).is_err());

    // Test 'add aggregate signature'
    let mut sig2 = BLS12381AggregateSignature::default();

    let kp = &keys()[0];
    let sig = BLS12381AggregateSignature::aggregate(&[kp.sign(message)]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2.verify(&pks[0..1], message).is_ok());

    let aggregated_signature = BLS12381AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .take(3)
            .skip(1)
            .map(|kp| kp.sign(message))
            .collect::<Vec<BLS12381Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();
    assert!(sig2.verify(&pks, message).is_ok());
}

#[test]
fn test_add_signatures_to_aggregate_different_messages() {
    let pks: Vec<BLS12381PublicKey> = keys()
        .into_iter()
        .take(3)
        .map(|kp| kp.public().clone())
        .collect();
    let messages: Vec<&[u8]> = vec![b"hello", b"world", b"!!!!!"];

    // Test 'add signature'
    let mut sig1 = BLS12381AggregateSignature::default();
    // Test populated aggregate signature
    for (i, kp) in keys().into_iter().take(3).enumerate() {
        let sig = kp.sign(messages[i]);
        sig1.add_signature(sig).unwrap();
    }

    assert!(sig1.verify_different_msg(&pks, &messages).is_ok());
    let other_messages: Vec<&[u8]> = vec![b"hello", b"world!", b"!!!!"];
    assert!(sig1.verify_different_msg(&pks, &other_messages).is_err());

    // Test 'add aggregate signature'
    let mut sig2 = BLS12381AggregateSignature::default();

    let kp = &keys()[0];
    let sig = BLS12381AggregateSignature::aggregate(&[kp.sign(messages[0])]).unwrap();
    sig2.add_aggregate(sig).unwrap();

    assert!(sig2
        .verify_different_msg(&pks[0..1], &messages[0..1])
        .is_ok());

    let aggregated_signature = BLS12381AggregateSignature::aggregate(
        &keys()
            .into_iter()
            .zip(&messages)
            .take(3)
            .skip(1)
            .map(|(kp, message)| kp.sign(message))
            .collect::<Vec<BLS12381Signature>>(),
    )
    .unwrap();

    sig2.add_aggregate(aggregated_signature).unwrap();
    assert!(sig2.verify_different_msg(&pks, &messages).is_ok());
}

#[test]
fn test_signature_aggregation() {
    let mut rng = StdRng::from_seed([0; 32]);
    let msg = b"message";

    // Valid number of signatures
    for size in [1, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192] {
        let blst_keypairs: Vec<_> = (0..size)
            .map(|_| BLS12381KeyPair::generate(&mut rng))
            .collect();
        let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(msg)).collect();
        assert!(BLS12381AggregateSignature::aggregate(&blst_signatures).is_ok());
    }

    // Invalid number of signatures
    let blst_keypairs: Vec<_> = (0..0)
        .map(|_| BLS12381KeyPair::generate(&mut rng))
        .collect();
    let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(msg)).collect();
    assert!(BLS12381AggregateSignature::aggregate(&blst_signatures).is_err());
}

#[test]
fn test_aggregate_verify_with_wrong_number_of_inputs() {
    let (message, pks, sigs) = signature_test_inputs();
    let aggregate = BLS12381AggregateSignature::aggregate(&sigs).unwrap();
    assert!(aggregate.verify(&pks, &message).is_ok());
    assert!(aggregate.verify(&[], &message).is_err());
    assert!(aggregate.verify(&pks[1..], &message).is_err());

    let messages: Vec<&[u8]> = vec![&message; 3];
    assert!(aggregate.verify_different_msg(&pks, &messages).is_ok());
    assert!(aggregate.verify_different_msg(&pks, &messages[1..]).is_err());
    assert!(aggregate.verify_different_msg(&pks[1..], &messages).is_err());
    assert!(aggregate.verify_different_msg(&[], &[]).is_err());
}

#[test]
fn test_aggregate_does_not_validate_but_verify_does() {
    let (message, pks, mut sigs) = signature_test_inputs();
    // Aggregation accepts a signature outside the subgroup (it does not validate its inputs) ...
    sigs.push(<BLS12381Signature as ToFromBytes>::from_bytes(NON_SUBGROUP_SIGNATURE).unwrap());
    let aggregate = BLS12381AggregateSignature::aggregate(&sigs).unwrap();
    assert_eq!(aggregate_from_default(&sigs), aggregate);
    // ... but no verification function accepts the result.
    assert!(aggregate.verify(&pks, &message).is_err());
    let messages: Vec<&[u8]> = vec![&message; pks.len()];
    assert!(aggregate.verify_different_msg(&pks, &messages).is_err());
    assert!(BLS12381AggregateSignature::batch_verify(&[&aggregate], vec![pks.iter()], &[&message])
        .is_err());
}

#[test]
fn test_add_aggregate_to_non_default_aggregate() {
    let (message, pks, sigs) = signature_test_inputs();
    let mut aggregate = BLS12381AggregateSignature::aggregate(&sigs[..1]).unwrap();
    // Populate the bytes cache before modifying the aggregate.
    let before = aggregate.as_bytes().to_vec();
    aggregate
        .add_aggregate(BLS12381AggregateSignature::aggregate(&sigs[1..]).unwrap())
        .unwrap();
    assert_ne!(aggregate.as_bytes(), before.as_slice());
    assert_eq!(aggregate, BLS12381AggregateSignature::aggregate(&sigs).unwrap());
    assert_eq!(
        BLS12381AggregateSignature::from_bytes(aggregate.as_bytes()).unwrap(),
        aggregate
    );
    assert!(aggregate.verify(&pks, &message).is_ok());
}

#[test]
fn test_batch_verify_edge_cases() {
    let keys = keys();
    let pks: Vec<BLS12381PublicKey> = keys.iter().map(|kp| kp.public().clone()).collect();
    let messages: [&[u8]; 3] = [b"first", b"second", b"first"];
    // Group i is signed by keys[..=i] over messages[i]. Groups 0 and 2 share a message.
    let aggregates: Vec<BLS12381AggregateSignature> = messages
        .iter()
        .enumerate()
        .map(|(i, m)| {
            aggregate_from_default(&keys[..=i].iter().map(|kp| kp.sign(m)).collect::<Vec<_>>())
        })
        .collect();
    let groups = || (0..3).map(|i| pks[..=i].iter()).collect::<Vec<_>>();
    let all: Vec<&BLS12381AggregateSignature> = aggregates.iter().collect();

    assert!(BLS12381AggregateSignature::batch_verify(&all, groups(), &messages).is_ok());
    // A single entry.
    assert!(BLS12381AggregateSignature::batch_verify(
        &all[..1],
        vec![pks[..1].iter()],
        &messages[..1]
    )
    .is_ok());

    // An empty batch is accepted.
    assert!(BLS12381AggregateSignature::batch_verify(
        &[],
        Vec::<std::slice::Iter<'_, BLS12381PublicKey>>::new(),
        &[]
    )
    .is_ok());

    // An entry without public keys is rejected.
    let mut no_keys = groups();
    no_keys[1] = pks[..0].iter();
    assert_eq!(
        BLS12381AggregateSignature::batch_verify(&all, no_keys, &messages),
        Err(FastCryptoError::InvalidInput)
    );

    // Swapped key groups are rejected.
    let mut swapped = groups();
    swapped.swap(0, 1);
    assert_eq!(
        BLS12381AggregateSignature::batch_verify(&all, swapped, &messages),
        Err(FastCryptoError::GeneralOpaqueError)
    );

    // Swapped messages are rejected.
    let swapped_messages = [messages[1], messages[0], messages[2]];
    assert!(BLS12381AggregateSignature::batch_verify(&all, groups(), &swapped_messages).is_err());

    // One invalid entry among valid ones is rejected, wherever it is.
    let invalid_entries = [
        BLS12381AggregateSignature::default(),
        BLS12381AggregateSignature::from_bytes(NON_SUBGROUP_SIGNATURE).unwrap(),
        aggregate_from_default(&[keys[0].sign(b"other")]),
    ];
    for invalid in &invalid_entries {
        for position in 0..3 {
            let mut entries = all.clone();
            entries[position] = invalid;
            assert!(
                BLS12381AggregateSignature::batch_verify(&entries, groups(), &messages).is_err()
            );
        }
    }

    // Length mismatches.
    assert_eq!(
        BLS12381AggregateSignature::batch_verify(&all[..2], groups(), &messages),
        Err(FastCryptoError::InputLengthWrong(2))
    );
    assert_eq!(
        BLS12381AggregateSignature::batch_verify(&all, groups(), &messages[..2]),
        Err(FastCryptoError::InputLengthWrong(3))
    );

    // Public keys are not validated (callers must validate them and check proofs of possession),
    // so an infinity key in a group does not change the aggregated key and the entry still verifies.
    let infinity_pk = BLS12381PublicKey::from_bytes(&infinity_encoding(PK_LENGTH)).unwrap();
    let with_infinity = vec![vec![&pks[0], &infinity_pk].into_iter()];
    assert!(BLS12381AggregateSignature::batch_verify(&all[..1], with_infinity, &messages[..1])
        .is_ok());
}

//
// Other tests
//

#[test]
fn test_hkdf_generate_from_ikm() {
    let seed = &[
        0, 0, 1, 1, 2, 2, 4, 4, 8, 2, 0, 9, 3, 2, 4, 1, 1, 1, 2, 0, 1, 1, 3, 4, 1, 2, 9, 8, 7, 6,
        5, 4,
    ];
    let salt = &[3, 2, 1];
    let kp = hkdf_generate_from_ikm::<Sha3_256, BLS12381KeyPair>(seed, salt, &[]).unwrap();
    let kp2 = hkdf_generate_from_ikm::<Sha3_256, BLS12381KeyPair>(seed, salt, &[]).unwrap();

    let sk = kp.private();
    assert_eq!(sk.as_bytes(), kp2.private().as_bytes());
    // Regression value: the private key does not depend on the mode.
    assert_eq!(
        Hex::encode(sk.as_bytes()),
        "32bb2d63d68d695bf6461f8794150c80475364aa6f0a7be55625390e4dab1bdc"
    );
}

// Checks if the private keys zeroed out
#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = BLS12381KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, BLS12381PrivateKey::LENGTH) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that self.privkey is zeroized
    unsafe {
        for i in 0..BLS12381PrivateKey::LENGTH {
            assert_eq!(*ptr.add(i), 0);
        }
    }

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, BLS12381PrivateKey::LENGTH) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for BLS12381PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for BLS12381PrivateKey>"
        );
    });
}

#[test]
fn test_verify_with_default_values() {
    let valid_kp = keys().pop().unwrap();
    let valid_sig = valid_kp.sign(b"message");
    let default_sig = BLS12381Signature::default();
    let valid_pk = valid_kp.public().clone();
    let default_pk = BLS12381PublicKey::insecure_default();
    let valid_agg_sig = BLS12381AggregateSignature::aggregate(std::slice::from_ref(&valid_sig)).unwrap();
    let default_agg_sig = BLS12381AggregateSignature::default();

    // Default sig should fail (for both types of keys)
    assert!(valid_pk.verify(b"message", &default_sig).is_err());
    assert!(default_pk.verify(b"message", &default_sig).is_err());

    // Verification with default pk should fail.
    assert!(default_pk.verify(b"message", &valid_sig).is_err());

    // Verifications with one of the default values should fail.
    assert!(valid_agg_sig.verify(std::slice::from_ref(&valid_pk), b"message").is_ok());
    assert!(valid_agg_sig.verify(std::slice::from_ref(&default_pk), b"message").is_err());
    assert!(default_agg_sig.verify(std::slice::from_ref(&valid_pk), b"message").is_err());
    assert!(default_agg_sig.verify(std::slice::from_ref(&default_pk), b"message").is_err());
}

#[test]
 fn public_key_ordering() {
     let pk1 = keys().pop().unwrap().public().clone();
     let pk2 = keys().pop().unwrap().public().clone();
     assert_eq!(pk1.as_bytes().cmp(pk2.as_bytes()), pk1.cmp(&pk2));
     assert_eq!(
         pk1.as_bytes().cmp(pk2.as_bytes()),
         pk1.partial_cmp(&pk2).unwrap()
     );
 }

#[test]
 fn fmt_public_key() {
     let kpref = keys().pop().unwrap();
     let public_key = kpref.public();

     // Display
     assert_eq!(
         format!("{}", public_key),
         Base64::encode(public_key.as_bytes())
     );

     // Debug
     assert_eq!(
         format!("{:?}", public_key),
         Base64::encode(public_key.as_bytes())
     );
 }

#[test]
 fn hash_signature() {
     let sig = keys().pop().unwrap().sign(b"Hello, world!");

     let mut hasher = DefaultHasher::new();
     sig.hash(&mut hasher);
     let digest = hasher.finish();

     let mut other_hasher = DefaultHasher::new();
     sig.as_bytes().hash(&mut other_hasher);
     let expected = other_hasher.finish();
     assert_eq!(expected, digest);
 }

#[test]
 fn fmt_signature() {
     let sig = keys().pop().unwrap().sign(b"Hello, world!");
     assert_eq!(format!("{}", sig), Base64::encode(sig.as_bytes()));

     let aggregate_sig = BLS12381AggregateSignature::aggregate(std::slice::from_ref(&sig)).unwrap();
     assert_eq!(format!("{}", aggregate_sig), Base64::encode(aggregate_sig.as_bytes()));
 }

//
// Proptests
//

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = BLS12381KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            BLS12381KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

prop_compose! {
    fn valid_signature(pk: BLS12381PrivateKey)
                      (msg in any::<[u8; 32]>()) -> ([u8; 32], BLS12381Signature) {
            (msg, pk.sign(&msg))
    }
}

prop_compose! {
  fn maybe_valid_sig(pk: BLS12381PrivateKey)
                    (disc in bool::arbitrary(),
                    (msg, sig) in valid_signature(pk))
                       -> ([u8; 32], BLS12381Signature) {
    if disc {
      (msg, sig)
    } else {
      let mut rng = StdRng::from_seed([0; 32]);
      let mut msg = msg;
      rng.fill_bytes(&mut msg);
      (msg, sig)
    }
  }
}

fn arb_sig_triplet() -> impl Strategy<Value = (BLS12381PublicKey, [u8; 32], BLS12381Signature)> {
    arb_keypair()
        .prop_flat_map(|kp| {
            let pk: BLS12381PublicKey = kp.public().clone();
            (Just(pk), maybe_valid_sig(kp.private()))
        })
        .prop_flat_map(|(pk, (msg, sig))| (Just(pk), Just(msg), Just(sig)))
        .no_shrink()
}

/// Byte strings shaped like point encodings, to reach deeper than the length check: random flag
/// bits in the first byte, and either a random body or a small x-coordinate (which is on the curve
/// about half of the time), at the compressed length, the uncompressed length or any length.
fn arb_point_bytes(compressed_length: usize) -> impl Strategy<Value = Vec<u8>> {
    let length = prop_oneof![
        3 => Just(compressed_length),
        1 => Just(2 * compressed_length),
        1 => 0..=3 * compressed_length,
    ];
    // Mostly flags of a compressed, non-infinity point, so that many inputs decode.
    let flags = prop_oneof![
        3 => prop_oneof![Just(COMPRESSION_FLAG), Just(COMPRESSION_FLAG | SORT_FLAG)],
        1 => any::<u8>(),
    ];
    (
        length,
        flags,
        0..4096u64,
        proptest::bool::weighted(0.75),
        collection::vec(any::<u8>(), 3 * compressed_length),
    )
        .prop_map(|(length, flags, x, small_x, body)| {
            let mut bytes = if small_x && length >= 8 {
                let mut bytes = vec![0u8; length];
                bytes[length - 8..].copy_from_slice(&x.to_be_bytes());
                bytes
            } else {
                body[..length].to_vec()
            };
            if let Some(first) = bytes.first_mut() {
                *first = (flags & 0xe0) | (*first & 0x1f);
            }
            bytes
        })
}

/// One entry of a batch: the indices (into `keys()`) of the signers, the message, and optionally
/// the position of a signer that signs a different message instead.
type BatchEntry = (Vec<usize>, [u8; 8], Option<usize>);

fn arb_batch_entry() -> impl Strategy<Value = BatchEntry> {
    (
        collection::vec(0..4usize, 1..=4),
        any::<[u8; 8]>(),
        proptest::option::weighted(0.3, 0..4usize),
    )
}

const BLS_MAX_SIGNATURES: usize = 100;

proptest! {
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: BLS12381KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }

    // Test compatibility between aggregate and iterated verification
    #[test]
    fn test_aggregate_verify_distinct_messages(
        triplets in collection::vec(arb_sig_triplet(), 1..=BLS_MAX_SIGNATURES)
    ){
        let mut aggr = BLS12381AggregateSignature::default();
        let (pks_n_msgs, sigs): (Vec<_>, Vec<_>) = triplets.into_iter().map(|(pk, msg, sig)| ((pk, msg), sig)).unzip();
        for sig in sigs.clone() {
            aggr.add_signature(sig).unwrap();
        }
        let (pks, msgs): (Vec<_>, Vec<_>) = pks_n_msgs.into_iter().unzip();

        let res_aggregated = aggr.verify_different_msg(&pks, &msgs.iter().map(|m| m.as_ref()).collect::<Vec<_>>());
        let iterated_bits = sigs.iter().zip(pks.iter().zip(msgs.iter())).map(|(sig, (pk, msg))| pk.verify(msg, sig)).collect::<Vec<_>>();
        let res_iterated = iterated_bits.iter().all(|b| b.is_ok());

        assert_eq!(res_aggregated.is_ok(), res_iterated, "Aggregated: {:?}, iterated: {:?}", res_aggregated, iterated_bits);
    }

    #[test]
    fn test_aggregate_verify_distinct_messages_treewise(
        triplets in collection::vec(arb_sig_triplet(), 1..=BLS_MAX_SIGNATURES)
    ){
        let (pks_n_msgs, sigs): (Vec<_>, Vec<_>) = triplets.into_iter().map(|(pk, msg, sig)| ((pk, msg), sig)).unzip();
        let aggr = aggregate_treewise(&sigs);
        let (pks, msgs): (Vec<_>, Vec<_>) = pks_n_msgs.into_iter().unzip();

        let res_aggregated = aggr.verify_different_msg(&pks, &msgs.iter().map(|m| m.as_ref()).collect::<Vec<_>>());
        let iterated_bits = sigs.iter().zip(pks.iter().zip(msgs.iter())).map(|(sig, (pk, msg))| pk.verify(msg, sig)).collect::<Vec<_>>();
        let res_iterated = iterated_bits.iter().all(|b| b.is_ok());

        assert_eq!(res_aggregated.is_ok(), res_iterated, "Aggregated: {:?}, iterated: {:?}", res_aggregated, iterated_bits);
    }

    // Decoding never panics on adversarial bytes, every accepted encoding is the canonical
    // compressed or uncompressed encoding of the decoded point, and decoded values that are not
    // honestly generated never verify.
    #[test]
    fn test_decode_adversarial_point_encodings(
        pk_bytes in arb_point_bytes(PK_LENGTH),
        sig_bytes in arb_point_bytes(SIG_LENGTH),
        // Optionally replace the inputs by a valid encoding (compressed or not) with one bit flipped.
        pk_mutation in proptest::option::weighted(0.5, (any::<bool>(), any::<usize>())),
        sig_mutation in proptest::option::weighted(0.5, (any::<bool>(), any::<usize>())),
        msg in any::<[u8; 8]>(),
    ) {
        let keys = keys();
        let kp = &keys[0];
        let honest_sig = kp.sign(&msg);
        let flip = |mut bytes: Vec<u8>, bit: usize| {
            let bit = bit % (bytes.len() * 8);
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        };
        let pk_bytes = match pk_mutation {
            Some((true, bit)) => flip(uncompressed_public_key(keys[1].public()), bit),
            Some((false, bit)) => flip(keys[1].public().as_bytes().to_vec(), bit),
            None => pk_bytes,
        };
        let other_sig = keys[1].sign(&msg);
        let sig_bytes = match sig_mutation {
            Some((true, bit)) => flip(uncompressed_signature(&other_sig), bit),
            Some((false, bit)) => flip(other_sig.as_bytes().to_vec(), bit),
            None => sig_bytes,
        };

        if let Ok(pk) = BLS12381PublicKey::from_bytes(&pk_bytes) {
            if pk_bytes.len() == PK_LENGTH {
                prop_assert_eq!(pk.as_bytes(), &pk_bytes[..]);
            } else {
                prop_assert_eq!(uncompressed_public_key(&pk), pk_bytes.clone());
            }
            // Eq, Hash and Ord agree with the canonical encoding.
            let canonical = BLS12381PublicKey::from_bytes(pk.as_bytes()).unwrap();
            prop_assert_eq!(&canonical, &pk);
            prop_assert_eq!(hash_of(&canonical), hash_of(&pk));
            prop_assert_eq!(canonical.cmp(&pk), std::cmp::Ordering::Equal);
            if &pk != kp.public() {
                prop_assert!(pk.verify(&msg, &honest_sig).is_err());
            }
            let _ = pk.validate();
        }
        // Binary serde accepts exactly the compressed encodings that from_bytes accepts.
        if let Ok(pk) = bcs::from_bytes::<BLS12381PublicKey>(&pk_bytes) {
            prop_assert_eq!(pk.as_bytes(), &pk_bytes[..]);
        }
        prop_assert_eq!(
            bcs::from_bytes::<BLS12381PublicKey>(&pk_bytes).is_ok(),
            pk_bytes.len() == PK_LENGTH && BLS12381PublicKey::from_bytes(&pk_bytes).is_ok()
        );

        if let Ok(sig) = <BLS12381Signature as ToFromBytes>::from_bytes(&sig_bytes) {
            if sig_bytes.len() == SIG_LENGTH {
                prop_assert_eq!(sig.as_bytes(), &sig_bytes[..]);
            } else {
                prop_assert_eq!(uncompressed_signature(&sig), sig_bytes.clone());
            }
            let canonical = <BLS12381Signature as ToFromBytes>::from_bytes(sig.as_bytes()).unwrap();
            prop_assert_eq!(&canonical, &sig);
            prop_assert_eq!(hash_of(&canonical), hash_of(&sig));
            prop_assert!(kp.public().verify(&msg, &sig).is_err());
            let aggregate = BLS12381AggregateSignature::from_bytes(&sig_bytes).unwrap();
            prop_assert_eq!(aggregate.as_bytes(), sig.as_bytes());
            prop_assert!(aggregate.verify(std::slice::from_ref(kp.public()), &msg).is_err());
        } else {
            prop_assert!(BLS12381AggregateSignature::from_bytes(&sig_bytes).is_err());
        }

        // Human-readable serde goes through from_bytes.
        let json = format!("\"{}\"", Base64::encode(&sig_bytes));
        prop_assert_eq!(
            serde_json::from_str::<BLS12381Signature>(&json).ok(),
            <BLS12381Signature as ToFromBytes>::from_bytes(&sig_bytes).ok()
        );
    }

    #[test]
    fn test_deser_private_key_arbitrary_bytes(bytes in collection::vec(any::<u8>(), 0..=64)) {
        if let Ok(sk) = BLS12381PrivateKey::from_bytes(&bytes) {
            prop_assert_eq!(sk.as_bytes(), &bytes[..]);
            prop_assert!(bytes.len() == BLS_PRIVATE_KEY_LENGTH);
        }
    }

    // Flipping any single bit of a valid signature never gives another valid signature.
    #[test]
    fn test_verify_rejects_tampered_signatures(
        kp in arb_keypair(),
        msg in any::<[u8; 32]>(),
        bit in 0..SIG_LENGTH * 8,
    ) {
        let mut bytes = kp.sign(&msg).as_bytes().to_vec();
        bytes[bit / 8] ^= 1 << (bit % 8);
        if let Ok(sig) = <BLS12381Signature as ToFromBytes>::from_bytes(&bytes) {
            prop_assert!(kp.public().verify(&msg, &sig).is_err());
        }
    }

    // aggregate, add_signature from the default, and tree-wise add_aggregate agree.
    #[test]
    fn test_aggregation_methods_agree(
        triplets in collection::vec(arb_sig_triplet(), 1..=16)
    ) {
        let sigs: Vec<_> = triplets.into_iter().map(|(_, _, sig)| sig).collect();
        let flat = BLS12381AggregateSignature::aggregate(&sigs).unwrap();
        prop_assert_eq!(&aggregate_from_default(&sigs), &flat);
        let treewise = aggregate_treewise(&sigs);
        prop_assert_eq!(&treewise, &flat);
        prop_assert_eq!(treewise.as_bytes(), flat.as_bytes());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // batch_verify (used by Sui for certificates) accepts exactly when every entry verifies on
    // its own (up to the 2^-96 soundness error of the random linear combination).
    #[test]
    fn test_batch_verify_matches_individual_verification(
        entries in collection::vec(arb_batch_entry(), 1..=4)
    ) {
        let keys = keys();
        let mut aggregates = Vec::new();
        let mut key_groups = Vec::new();
        for (signers, msg, corrupt) in &entries {
            let sigs: Vec<_> = signers
                .iter()
                .enumerate()
                .map(|(position, &i)| {
                    if *corrupt == Some(position) {
                        keys[i].sign(b"another message")
                    } else {
                        keys[i].sign(msg)
                    }
                })
                .collect();
            aggregates.push(aggregate_from_default(&sigs));
            key_groups.push(
                signers.iter().map(|&i| keys[i].public().clone()).collect::<Vec<_>>(),
            );
        }
        let messages: Vec<&[u8]> = entries.iter().map(|(_, msg, _)| &msg[..]).collect();

        let individually = aggregates
            .iter()
            .zip(&key_groups)
            .zip(&messages)
            .all(|((aggregate, pks), msg)| aggregate.verify(pks, msg).is_ok());
        let expected = entries
            .iter()
            .all(|(signers, _, corrupt)| corrupt.map_or(true, |p| p >= signers.len()));
        prop_assert_eq!(individually, expected);

        let batched = BLS12381AggregateSignature::batch_verify(
            &aggregates.iter().collect::<Vec<_>>(),
            key_groups.iter().map(|pks| pks.iter()).collect(),
            &messages,
        );
        prop_assert_eq!(batched.is_ok(), individually);
    }
}
}} // macro_rules! define_tests

pub mod min_sig {
    use super::*;
    use crate::bls12381::min_sig::{
        BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
        BLS12381PrivateKey, BLS12381PublicKey, BLS12381PublicKeyAsBytes, BLS12381Signature,
    };
    define_tests!();

    #[test]
    fn regression_test() {
        // Generated from a random secret key and stored here for regression testing.
        let secret =
            hex::decode("266f9708fd8d3b462b10cdbf5498076c021eb3acfdd47cb1fef647967fe194fb")
                .unwrap();
        let public = hex::decode("8c66dc2c1ea9e53f0985c17b4e7af19912b6d3c40e0c5920a5a12509b4eb3619f5e07ec56ea77f0b30629ba1cc72d75b139460782a5f0e2f89fb4c42b4b8a5fae3d260102220e63d0754e7e1846deefd3988eade4ed37f1385437d19de1a1618").unwrap();
        let signature = hex::decode("89dff2dc1e9428b9437d50b37f8160eca790110ea2a79b6c88a43a16953466f8e391ff65842b067a1c9441c7c2cebce0").unwrap();

        let sk = BLS12381PrivateKey::from_bytes(&secret).unwrap();
        let pk = BLS12381PublicKey::from(&sk);
        let message = b"hello, narwhal";
        let sig = sk.sign(message);

        assert_eq!(sk.as_bytes(), secret);
        assert_eq!(pk.as_bytes(), public);
        assert_eq!(sig.as_bytes(), signature);
    }

    #[test]
    fn aggregate_regression_test() {
        let expected = "aedb61ea3ca1451dd6b726985d54c294af9fb4c5b9f4ddf4bbcf6757ff54ce6608062883565ae63700f3bdbbbface083";
        check_aggregate_regression(expected);
    }

    #[test]
    fn test_verify_drand_quicknet_signatures() {
        // drand's quicknet ("bls-unchained-g1-rfc9380") signs sha256(round) with signatures in G1
        // and the same DST as this module, so its beacons are external test vectors for min_sig.
        // Chain info: https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info
        let key = BLS12381PublicKey::from_bytes(&hex::decode("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a").unwrap()).unwrap();
        assert!(key.validate().is_ok());
        let beacons: [(u64, &str, &str); 2] = [
            (
                1000,
                "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39",
                "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd",
            ),
            (
                20000000,
                "96892582a33552a7b67ba44ef09c3ccd535bbebe760c93ecf45be8958d0c0f06390c6d19d7bf492eb806af7eef6b125c",
                "f39c98df5525968e6622e0c63edb3d1f9c5607cf780db78abdded36e4b3dba95",
            ),
        ];
        for (round, sig, randomness) in beacons {
            let sig_bytes = hex::decode(sig).unwrap();
            let sig = <BLS12381Signature as ToFromBytes>::from_bytes(&sig_bytes).unwrap();
            let msg = Sha256::digest(round.to_be_bytes()).digest;
            assert!(key.verify(&msg, &sig).is_ok());
            assert!(key
                .verify(&Sha256::digest((round + 1).to_be_bytes()).digest, &sig)
                .is_err());
            // The beacon randomness is sha256 of the signature.
            assert_eq!(Hex::encode(Sha256::digest(&sig_bytes).digest), randomness);
        }
    }

    #[test]
    fn test_verify_sui_checkpoint_certificate() {
        // A Sui mainnet checkpoint certificate, verified the way Sui verifies certificates. See the
        // "description" field of the JSON file for where the data comes from.
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("sui_checkpoint_test_vector.json")).unwrap();
        let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();

        let committee: Vec<(BLS12381PublicKey, u64)> = vector["committee"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| {
                let pk = BLS12381PublicKey::from_bytes(&bytes(&member["protocol_pubkey"])).unwrap();
                (pk, member["voting_power"].as_u64().unwrap())
            })
            .collect();
        // Sui orders the committee by public key, and validates every key (with a proof of
        // possession) before it joins.
        assert!(committee.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(committee.iter().all(|(pk, _)| pk.validate().is_ok()));
        assert_eq!(
            committee.iter().map(|(_, power)| power).sum::<u64>(),
            10_000
        );

        let signers: Vec<usize> = vector["signers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect();
        let signer_keys: Vec<BLS12381PublicKey> =
            signers.iter().map(|&i| committee[i].0.clone()).collect();
        // The signers hold a quorum (more than 2/3) of the voting power.
        assert!(signers.iter().map(|&i| committee[i].1).sum::<u64>() >= 6_667);

        // The signed message: intent (scope CheckpointSummary = 2, version 0, app Sui = 0), the BCS
        // of the checkpoint summary, and the epoch.
        let epoch = vector["epoch"].as_u64().unwrap();
        let message_for_epoch = |epoch: u64| {
            let mut message = vec![2, 0, 0];
            message.extend(bytes(&vector["summary_bcs"]));
            message.extend(epoch.to_le_bytes());
            message
        };
        let message = message_for_epoch(epoch);
        let signature =
            BLS12381AggregateSignature::from_bytes(&bytes(&vector["aggregate_signature"])).unwrap();

        // Sui adds the certificate's signature to a default aggregate and calls batch_verify.
        let mut aggregate = BLS12381AggregateSignature::default();
        aggregate.add_aggregate(signature.clone()).unwrap();
        assert!(BLS12381AggregateSignature::batch_verify(
            &[&aggregate],
            vec![signer_keys.iter()],
            &[&message]
        )
        .is_ok());
        assert!(signature.verify(&signer_keys, &message).is_ok());

        // Another epoch, a missing signer or an extra signer are rejected.
        assert!(signature
            .verify(&signer_keys, &message_for_epoch(epoch + 1))
            .is_err());
        assert!(signature.verify(&signer_keys[1..], &message).is_err());
        let non_signer = (0..committee.len()).find(|i| !signers.contains(i)).unwrap();
        let mut with_extra_signer = signer_keys.clone();
        with_extra_signer.push(committee[non_signer].0.clone());
        assert!(signature.verify(&with_extra_signer, &message).is_err());
    }
}

pub mod min_pk {
    use super::*;
    use crate::bls12381::min_pk::{
        BLS12381AggregateSignature, BLS12381AggregateSignatureAsBytes, BLS12381KeyPair,
        BLS12381PrivateKey, BLS12381PublicKey, BLS12381PublicKeyAsBytes, BLS12381Signature,
    };
    define_tests!();

    #[test]
    fn regression_test() {
        // Generated from a random secret key and stored here for regression testing.
        let secret =
            hex::decode("266f9708fd8d3b462b10cdbf5498076c021eb3acfdd47cb1fef647967fe194fb")
                .unwrap();
        let public = hex::decode("b157f238403a5b980546fd19ca48f79a2613e3e3a91d14ee69908b8816e4c53665370b2fbd0db62cc4aa0e8caeedc9b5").unwrap();
        let signature = hex::decode("8dec0b9a1a629cc96c57144ee8e7dd5c93acb465286f1214df3b8482c3f16e10db4277ead785f5d5bc77b4e51affd2580dead4d0d21cf20fc5e2b4bec2586c2bd6c73fee76c11f214871f77dada4c578034c3b978f1cccb82bdd78fe5ee67de1").unwrap();

        let sk = BLS12381PrivateKey::from_bytes(&secret).unwrap();
        let pk = BLS12381PublicKey::from(&sk);
        let message = b"hello, narwhal";
        let sig = sk.sign(message);

        assert_eq!(sk.as_bytes(), secret);
        assert_eq!(pk.as_bytes(), public);
        assert_eq!(sig.as_bytes(), signature);
    }

    #[test]
    fn aggregate_regression_test() {
        let expected = "aba1be4b22c0352b2060d96fd316a7110c68ad31d037086adb9dacff99460253f2f78e372f4a2574665268f7d48f212218fa678270aaa810674280b21948cf9df339400be2c2ca4b265f949b566c1d488e3651118cb8915db9f39ee55c8ff6af";
        check_aggregate_regression(expected);
    }

    #[test]
    fn test_verify_drand_signature() {
        // Regression test of an actual response from Drand.
        let key = hex::decode("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31").unwrap();
        let sig = hex::decode("a2cd8577944b84484ef557a7f92f0d5092779497cc470b1b97680b8f7c807d97250d310b801c7c2185c7c8a21032d45403b97530ca87bd8f05d0cf4ffceb4bcb9bf7184fb604967db7e9e6ea555bc51b25a9e41fbd51181f712aa73aaec749fe").unwrap();

        let round: u64 = 2373935;
        let prev_sig = hex::decode("a96aace596906562dc525dba4dff734642d71b334d51324f9c9bcb5a3d6caf14b05cde91d6507bf4615cb4285e5b4efd1358ebc46b80b51e338f9dc46cca17cf2e046765ba857c04101a560887fa81aef101a5bb3b2350884558bd3adc72be37").unwrap();

        let mut sha = Sha256::new();
        sha.update(prev_sig);
        sha.update(round.to_be_bytes());
        let msg = sha.finalize().digest;

        let key = BLS12381PublicKey::from_bytes(&key).unwrap();
        let sig = <BLS12381Signature as ToFromBytes>::from_bytes(&sig).unwrap();
        assert!(key.verify(&msg, &sig).is_ok());
    }
}
