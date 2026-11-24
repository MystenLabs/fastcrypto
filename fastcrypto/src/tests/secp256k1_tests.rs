// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest::{collection, prelude::*};
use rand::{rngs::StdRng, SeedableRng as _};
use rust_secp256k1::{constants, ecdsa::Signature, SecretKey};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use wycheproof::ecdsa::{TestName, TestSet};
use wycheproof::TestResult;

use crate::encoding::{Base58, Base64};
use crate::hash::{Blake2b256, Keccak256, Sha3_256};
use crate::secp256k1::{Secp256k1PublicKeyAsBytes, Secp256k1SignatureAsBytes};
use crate::test_helpers::verify_serialization;
use crate::traits::Signer;
use crate::{
    encoding::{Encoding, Hex},
    hash::{HashFunction, Sha256},
    secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey, Secp256k1PublicKey, Secp256k1Signature},
    signature_service::SignatureService,
    test_helpers,
    traits::{EncodeDecodeBase64, KeyPair, ToFromBytes, VerifyingKey},
};

//
// Helper functions
//

pub(crate) const MSG: &[u8] = b"Hello, world!";

pub(crate) const PK_LENGTH: usize = <Secp256k1PublicKey as VerifyingKey>::LENGTH;
const UNCOMPRESSED_PK_LENGTH: usize = constants::UNCOMPRESSED_PUBLIC_KEY_SIZE;
pub(crate) const SIG_LENGTH: usize = constants::COMPACT_SIGNATURE_SIZE;
const SK_LENGTH: usize = constants::SECRET_KEY_SIZE;

/// The order n of the secp256k1 group, big-endian.
pub(crate) const GROUP_ORDER: [u8; 32] =
    hex_literal::hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// floor(n / 2), big-endian. A signature is low-s if s <= floor(n / 2).
const HALF_GROUP_ORDER: [u8; 32] =
    hex_literal::hex!("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

/// The secp256k1 field modulus p, big-endian.
const FIELD_MODULUS: [u8; 32] =
    hex_literal::hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// SEC1 prefixes of public key encodings.
const PREFIX_EVEN_Y: u8 = 0x02;
const PREFIX_ODD_Y: u8 = 0x03;
const PREFIX_UNCOMPRESSED: u8 = 0x04;
const PREFIX_HYBRID_EVEN_Y: u8 = 0x06;
const PREFIX_HYBRID_ODD_Y: u8 = 0x07;

/// The compressed encoding of the point with x = 1 (the smallest x-coordinate on the curve).
const X_ONE_COMPRESSED: [u8; PK_LENGTH] =
    hex_literal::hex!("020000000000000000000000000000000000000000000000000000000000000001");

/// The uncompressed encoding of the same point. Its y-coordinate is even.
const X_ONE_UNCOMPRESSED: [u8; UNCOMPRESSED_PK_LENGTH] = hex_literal::hex!(
    "0400000000000000000000000000000000000000000000000000000000000000014218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee"
);

/// `X_ONE_COMPRESSED` with x = p + 1 instead of 1, that is, the same field element not reduced
/// modulo p.
const X_ONE_UNREDUCED: [u8; PK_LENGTH] =
    hex_literal::hex!("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30");

/// The compressed encoding of the generator, which is the public key of the private key 1.
const GENERATOR_COMPRESSED: [u8; PK_LENGTH] =
    hex_literal::hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

/// A Sui mainnet transaction signed with secp256k1, fetched from https://graphql.mainnet.sui.io/graphql
/// (transaction 5AiDPBBP8mMdQfXK98kSANaXq9KLKhiDsJSBYHJBosqc, checkpoint 345838965, epoch 1313).
/// `SUI_TX_DATA` is the BCS of the `TransactionData` (field `transactionBcs`) and
/// `SUI_TX_SIGNATURE` is the user signature (field `signatures.signatureBytes`).
const SUI_TX_DIGEST: &str = "5AiDPBBP8mMdQfXK98kSANaXq9KLKhiDsJSBYHJBosqc";
const SUI_TX_SENDER: &str = "d5ccdf77cab59778ad6c6d599af3819b0281c3fe434f7df4b82290620331bb01";
const SUI_TX_DATA: &str = "AAACAAglv10iAAAAAAAgE8B1ZE2tIb8QyxJEe4JbU1wk3a5CjierxYWNFRHiTG0CAgABAQAAAQECAAABAQDVzN93yrWXeK1sbVma84GbAoHD/kNPffS4IpBiAzG7AQPw/967SD39QNXwBXVf+iLyJcgKtB6qHFmjYMegj2+dH1dpfUAAAAAAICq33KdvcuFdIWBIQVzxq0q0Q323e9PXvYYeo+9FhyTolM4VWzksQWCOHQKIhsiTsK62fCaD8oV6Ef2TPQ401gJHkAZBAAAAACBebzE5GZIjUTxm4O+jUiMkWPnwSQPTFuRSfNidXKoatHq774VGGKfDOrog2Y4HIDG3wwfwTg7L+4opF+ngZvAaV2l9QAAAAAAg9/i+rhfKgb6R6/o98VOqRCkYJfOMAvsrNFAeRDZ2D/TVzN93yrWXeK1sbVma84GbAoHD/kNPffS4IpBiAzG7AW4AAAAAAAAAYOxTAAAAAAAA";
const SUI_TX_SIGNATURE: &str = "AbC6hpyEeo49YV3ksbs7/pUFQMB4FyZfTLXYQD+42eg/NBCqMGbDiv42Q/rPer1jyCdw0i5AjGzXxp+hZk87k8wDeuMit0IkVlfKERsFi8q1Z6epE6C9v80hls+FwShmPvw=";

/// The signature scheme flag of secp256k1 in Sui.
const SUI_SECP256K1_FLAG: u8 = 0x01;

pub fn keys() -> Vec<Secp256k1KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);

    (0..4)
        .map(|_| Secp256k1KeyPair::generate(&mut rng))
        .collect()
}

pub(crate) fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn uncompressed(pk: &Secp256k1PublicKey) -> [u8; UNCOMPRESSED_PK_LENGTH] {
    pk.pubkey.serialize_uncompressed()
}

/// The hybrid encoding of a public key: like the uncompressed one, but the prefix also gives the
/// parity of y (0x06 for even, 0x07 for odd).
fn hybrid(pk: &Secp256k1PublicKey) -> [u8; UNCOMPRESSED_PK_LENGTH] {
    let mut bytes = uncompressed(pk);
    bytes[0] = PREFIX_HYBRID_EVEN_Y | (bytes[64] & 1);
    bytes
}

/// Whether the s in a 64-byte r || s signature is greater than n / 2.
pub(crate) fn is_high_s(signature: &[u8]) -> bool {
    signature[32..64] > HALF_GROUP_ORDER[..]
}

/// Replaces s by n - s in an r || s signature (followed by anything). The result verifies under
/// plain ECDSA iff the input does, so it is the other signature from ECDSA's malleability.
pub(crate) fn negate_s(signature: &[u8]) -> Vec<u8> {
    let s = SecretKey::from_slice(&signature[32..64]).unwrap();
    let mut bytes = signature.to_vec();
    bytes[32..64].copy_from_slice(&s.negate().secret_bytes());
    bytes
}

/// The Sui address of a secp256k1 public key: blake2b(flag || compressed public key).
fn sui_address(pk: &Secp256k1PublicKey) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update([SUI_SECP256K1_FLAG]);
    hasher.update(pk.as_bytes());
    hasher.finalize().digest
}

/// Verification with k256, an independent implementation, given the digest of the message.
fn k256_verify(pk: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    match (
        k256::ecdsa::VerifyingKey::from_sec1_bytes(pk),
        k256::ecdsa::Signature::try_from(signature),
    ) {
        (Ok(pk), Ok(signature)) => pk.verify_prehash(digest, &signature).is_ok(),
        _ => false,
    }
}

/// The tests of a Wycheproof ECDSA test set as (public key, message, signature as r || s, result).
/// The signature is `None` if it is DER-encoded and the DER encoding does not parse.
pub(crate) type WycheproofTest = (Secp256k1PublicKey, Vec<u8>, Option<Vec<u8>>, TestResult);

pub(crate) fn wycheproof_tests(name: TestName, p1363: bool) -> Vec<WycheproofTest> {
    let test_set = TestSet::load(name).unwrap();
    let mut tests = Vec::new();
    for test_group in test_set.test_groups {
        // Wycheproof gives the public keys in uncompressed form.
        assert_eq!(test_group.key.key.len(), UNCOMPRESSED_PK_LENGTH);
        let pk = Secp256k1PublicKey::from_bytes(&test_group.key.key).unwrap();
        for test in test_group.tests {
            let signature = if p1363 {
                Some(test.sig.to_vec())
            } else {
                Signature::from_der(&test.sig)
                    .ok()
                    .map(|s| s.serialize_compact().to_vec())
            };
            tests.push((pk.clone(), test.msg.to_vec(), signature, test.result));
        }
    }
    assert!(!tests.is_empty());
    tests
}

/// Checks that `verify_with_hash::<H>` accepts a Wycheproof test iff it is valid and low-s, and, for
/// the test sets of plain ECDSA, that it accepts a test with s normalized iff it is valid. Returns the
/// number of valid tests that were rejected because they are high-s.
fn check_wycheproof<H: HashFunction<32>>(name: TestName, p1363: bool) -> usize {
    let mut rejected_high_s = 0;
    for (pk, msg, signature, result) in wycheproof_tests(name, p1363) {
        let verify = |bytes: &[u8]| {
            <Secp256k1Signature as ToFromBytes>::from_bytes(bytes)
                .is_ok_and(|sig| pk.verify_with_hash::<H>(&msg, &sig).is_ok())
        };
        let verified = signature.as_deref().is_some_and(verify);
        // Otherwise the invalid high-s tests would only be rejected for their s. The high-s tests of
        // the Bitcoin test set are invalid, but valid with s normalized.
        let parsed = signature
            .as_deref()
            .and_then(|bytes| Signature::from_compact(bytes).ok());
        if let (Some(mut sig), false) = (parsed, name == TestName::EcdsaSecp256k1Sha256Bitcoin) {
            sig.normalize_s();
            assert_eq!(
                verify(&sig.serialize_compact()),
                result == TestResult::Valid,
                "{:?}",
                name
            );
        }
        match result {
            TestResult::Valid => {
                // The DER encoding of valid tests always parses.
                let signature = signature.unwrap();
                assert_eq!(verified, !is_high_s(&signature), "{:?}", name);
                if is_high_s(&signature) {
                    rejected_high_s += 1;
                }
            }
            TestResult::Invalid => assert!(!verified, "{:?}", name),
            TestResult::Acceptable => unreachable!("these test sets have no acceptable tests"),
        }
    }
    rejected_high_s
}

fn signature_test_inputs() -> (Vec<u8>, Vec<Secp256k1PublicKey>, Vec<Secp256k1Signature>) {
    // Make signatures.
    let (pubkeys, signatures): (Vec<Secp256k1PublicKey>, Vec<Secp256k1Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(MSG);
            (kp.public().clone(), sig)
        })
        .unzip();

    (MSG.to_vec(), pubkeys, signatures)
}

//
// Serialization tests
//

#[test]
fn serialize_deserialize() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let sk = kp.private();
    let sig = keys().pop().unwrap().sign(MSG);

    verify_serialization(&pk, Some(pk.as_bytes()));
    verify_serialization(&sk, Some(sk.as_bytes()));
    verify_serialization(&sig, Some(sig.as_bytes()));

    let kp = keys().pop().unwrap();
    verify_serialization(&kp, Some(kp.as_bytes()));

    // Human-readable serde uses base64 of the same bytes as binary serde.
    let json = serde_json::to_string(&pk).unwrap();
    assert_eq!(json, format!("\"{}\"", Base64::encode(pk.as_bytes())));
    assert_eq!(
        serde_json::from_str::<Secp256k1PublicKey>(&json).unwrap(),
        pk
    );
    let json = serde_json::to_string(&sig).unwrap();
    assert_eq!(json, format!("\"{}\"", Base64::encode(sig.as_bytes())));
    assert_eq!(
        serde_json::from_str::<Secp256k1Signature>(&json).unwrap(),
        sig
    );
}

#[test]
fn bytes_representation() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let sig = kp.sign(MSG);

    // A bytes representation holds the same bytes as as_bytes and converts back to the same value.
    let pk_bytes = Secp256k1PublicKeyAsBytes::from(&pk);
    assert_eq!(pk_bytes.0, pk.as_bytes());
    assert_eq!(Secp256k1PublicKey::try_from(&pk_bytes).unwrap(), pk);
    let sig_bytes = Secp256k1SignatureAsBytes::from(&sig);
    assert_eq!(sig_bytes.0, sig.as_bytes());
    assert_eq!(Secp256k1Signature::try_from(&sig_bytes).unwrap(), sig);

    // Deserializing a bytes representation does not validate it: any bytes of the right length
    // are accepted, and only the conversion to the key or signature can fail.
    let pk_bytes: Secp256k1PublicKeyAsBytes = bcs::from_bytes(&[0xff; PK_LENGTH]).unwrap();
    assert!(Secp256k1PublicKey::try_from(&pk_bytes).is_err());
    let sig_bytes: Secp256k1SignatureAsBytes = bcs::from_bytes(&[0xff; SIG_LENGTH]).unwrap();
    assert!(Secp256k1Signature::try_from(&sig_bytes).is_err());

    // A public key bytes representation always holds the compressed encoding, also when the key
    // was decoded from another encoding.
    let from_uncompressed = Secp256k1PublicKey::from_bytes(&uncompressed(&pk)).unwrap();
    assert_eq!(
        Secp256k1PublicKeyAsBytes::from(&from_uncompressed),
        Secp256k1PublicKeyAsBytes::from(&pk)
    );

    // Human-readable serde uses base64 of exactly the compressed length, so the uncompressed
    // encoding is rejected.
    let json = serde_json::to_string(&Secp256k1PublicKeyAsBytes::from(&pk)).unwrap();
    assert_eq!(json, format!("\"{}\"", Base64::encode(pk.as_bytes())));
    let json = format!("\"{}\"", Base64::encode(uncompressed(&pk)));
    assert!(serde_json::from_str::<Secp256k1PublicKeyAsBytes>(&json).is_err());
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = Secp256k1PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap(), *public_key);
}

// `from_bytes` (and therefore base64 and human-readable serde, and the `secp256k1_verify` and
// `decompress_pubkey` Move natives in Sui) accepts exactly the compressed (0x02 / 0x03), the
// uncompressed (0x04) and the hybrid (0x06 / 0x07) encodings of a point other than the identity.
#[test]
fn public_key_from_bytes() {
    let decode = |bytes: &[u8]| Secp256k1PublicKey::from_bytes(bytes).is_ok();
    let pk = keys().pop().unwrap().public().clone();
    let compressed = pk.as_bytes().to_vec();
    let uncompressed_bytes = uncompressed(&pk);
    let hybrid_bytes = hybrid(&pk);
    assert!(decode(&X_ONE_COMPRESSED));
    assert!(decode(&X_ONE_UNCOMPRESSED));

    // The 33-byte encodings use exactly the prefixes 0x02 and 0x03, and the 65-byte encodings the
    // prefix 0x04 or the hybrid prefix that matches the parity of y.
    let accepted_prefixes = |encoding: &[u8]| -> Vec<u8> {
        (0..=255u8)
            .filter(|&prefix| decode(&[&[prefix][..], &encoding[1..]].concat()))
            .collect()
    };
    assert_eq!(
        accepted_prefixes(&compressed),
        vec![PREFIX_EVEN_Y, PREFIX_ODD_Y]
    );
    assert_eq!(
        accepted_prefixes(&uncompressed_bytes),
        vec![PREFIX_UNCOMPRESSED, hybrid_bytes[0]]
    );
    // So the 33-byte "compact" encoding with prefix 0x05, which some other implementations like
    // k256 accept, is rejected.
    let compact = [&[0x05][..], &compressed[1..]].concat();
    assert!(k256::ecdsa::VerifyingKey::from_sec1_bytes(&compact).is_ok());

    // Other lengths are rejected, also with a valid prefix, and so is the uncompressed encoding
    // without its prefix.
    for len in (0..=3 * PK_LENGTH).filter(|&len| len != PK_LENGTH && len != UNCOMPRESSED_PK_LENGTH)
    {
        for encoding in [&compressed[..], &uncompressed_bytes[..]] {
            let bytes: Vec<u8> = encoding.iter().cycle().take(len).copied().collect();
            assert!(!decode(&bytes), "{}", len);
        }
    }
    assert!(!decode(&uncompressed_bytes[1..]));

    // The point at infinity has no encoding: SEC1 encodes it as a single 0x00 byte.
    assert!(!decode(&[0x00]));
    assert!(!decode(&[0x00; PK_LENGTH]));
    assert!(!decode(&[0x00; UNCOMPRESSED_PK_LENGTH]));

    // x-coordinates that are not reduced modulo p.
    assert!(!decode(&X_ONE_UNREDUCED));
    let mut bytes = X_ONE_UNCOMPRESSED;
    bytes[1..33].copy_from_slice(&X_ONE_UNREDUCED[1..]);
    assert!(!decode(&bytes));
    for prefix in [PREFIX_EVEN_Y, PREFIX_ODD_Y] {
        assert!(!decode(&[&[prefix][..], &FIELD_MODULUS].concat()));
        assert!(!decode(&[&[prefix][..], &[0xff; 32]].concat()));
        // y^2 = 7 has no solution, so there is no point with x = 0.
        assert!(!decode(&[&[prefix][..], &[0x00; 32]].concat()));
    }

    // A y-coordinate that does not match x.
    let mut bytes = uncompressed_bytes;
    bytes[64] ^= 1;
    assert!(!decode(&bytes));
}

// The key decoded from any accepted encoding is the same: it is encoded compressed, and Eq, Hash,
// Ord, the Sui address and verification do not depend on the input encoding.
#[test]
fn test_public_key_encodings() {
    let keys = keys();
    let pk = keys[0].public().clone();
    let compressed = pk.as_bytes().to_vec();
    let uncompressed_bytes = uncompressed(&pk);

    // The prefix of a compressed encoding gives the parity of y, so changing it gives another key.
    let mut negated = compressed.clone();
    negated[0] ^= 1;
    assert_ne!(Secp256k1PublicKey::from_bytes(&negated).unwrap(), pk);

    for encoding in [&uncompressed_bytes[..], &hybrid(&pk)[..]] {
        let decoded = Secp256k1PublicKey::from_bytes(encoding).unwrap();
        assert_eq!(decoded, pk);
        assert_eq!(decoded.as_bytes(), compressed);
        assert_eq!(uncompressed(&decoded), uncompressed_bytes);
        assert_eq!(hash_of(&decoded), hash_of(&pk));
        assert_eq!(decoded.cmp(&pk), std::cmp::Ordering::Equal);
        assert_eq!(sui_address(&decoded), sui_address(&pk));
        assert!(decoded.verify(MSG, &keys[0].sign(MSG)).is_ok());
        assert!(decoded.verify(MSG, &keys[1].sign(MSG)).is_err());

        // Base64 and human-readable serde go through from_bytes, so they accept it as well...
        assert_eq!(
            Secp256k1PublicKey::decode_base64(&Base64::encode(encoding)).unwrap(),
            pk
        );
        let json = format!("\"{}\"", Base64::encode(encoding));
        let from_json: Secp256k1PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(from_json, pk);
        // ... but serializing again gives the compressed encoding.
        assert_eq!(
            serde_json::to_string(&from_json).unwrap(),
            format!("\"{}\"", Base64::encode(&compressed))
        );

        // Binary serde reads exactly the compressed length, so it rejects these encodings.
        assert!(bcs::from_bytes::<Secp256k1PublicKey>(encoding).is_err());
        assert!(bincode::deserialize::<Secp256k1PublicKey>(encoding).is_err());
    }

    // A key whose y is even uses the prefixes 0x02 and 0x06, and one whose y is odd uses 0x03
    // and 0x07. The key x = 1 has an even y.
    let x_one = Secp256k1PublicKey::from_bytes(&X_ONE_COMPRESSED).unwrap();
    assert_eq!(uncompressed(&x_one), X_ONE_UNCOMPRESSED);
    assert_eq!(hybrid(&x_one)[0], PREFIX_HYBRID_EVEN_Y);
    let odd_key = keys
        .iter()
        .map(|kp| kp.public())
        .find(|pk| pk.as_bytes()[0] == PREFIX_ODD_Y)
        .unwrap();
    assert_eq!(hybrid(odd_key)[0], PREFIX_HYBRID_ODD_Y);
    // A hybrid prefix that does not match the parity of y is rejected.
    let mut bytes = hybrid(odd_key);
    bytes[0] = PREFIX_HYBRID_EVEN_Y;
    assert!(Secp256k1PublicKey::from_bytes(&bytes).is_err());
}

#[test]
fn private_key_from_bytes() {
    let kp = keys().pop().unwrap();
    let sk = kp.private();
    let sk_bytes = sk.as_ref();
    let rebuilt_sk = <Secp256k1PrivateKey as ToFromBytes>::from_bytes(sk_bytes).unwrap();
    assert_eq!(rebuilt_sk, sk);

    // Only 32 bytes are accepted, for private keys and key pairs.
    for len in (0..=3 * SK_LENGTH).filter(|&len| len != SK_LENGTH) {
        let bytes: Vec<u8> = sk_bytes.iter().cycle().take(len).copied().collect();
        assert!(Secp256k1PrivateKey::from_bytes(&bytes).is_err(), "{}", len);
        assert!(Secp256k1KeyPair::from_bytes(&bytes).is_err(), "{}", len);
    }
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = Secp256k1PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
fn non_canonical_secret_key() {
    // Private keys are big-endian integers in [1, n), for private keys and key pairs.
    let zero = [0u8; SK_LENGTH];
    let mut one = [0u8; SK_LENGTH];
    one[SK_LENGTH - 1] = 1;
    let mut order_minus_one = GROUP_ORDER;
    order_minus_one[SK_LENGTH - 1] -= 1;
    let mut order_plus_one = GROUP_ORDER;
    order_plus_one[SK_LENGTH - 1] += 1;

    for bytes in [one, order_minus_one] {
        let sk = Secp256k1PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.as_bytes(), bytes);
        assert!(Secp256k1KeyPair::from_bytes(&bytes).is_ok());
    }
    for bytes in [zero, GROUP_ORDER, order_plus_one, [0xff; SK_LENGTH]] {
        assert!(Secp256k1PrivateKey::from_bytes(&bytes).is_err());
        assert!(Secp256k1KeyPair::from_bytes(&bytes).is_err());
    }

    // The public key of 1 is the generator.
    let kp = Secp256k1KeyPair::from_bytes(&one).unwrap();
    assert_eq!(kp.public().as_bytes(), GENERATOR_COMPRESSED);
}

#[test]
#[cfg(feature = "copy_key")]
fn test_copy_key_pair() {
    let kp = keys().pop().unwrap();
    let kp_copied = kp.copy();

    assert_eq!(kp.public().as_bytes(), kp_copied.public().as_bytes());
    assert_eq!(kp.private().as_bytes(), kp_copied.private().as_bytes());
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
fn key_pair_from_string_roundtrip() {
    let kp = keys().pop().unwrap();
    let kp_str = Base64::encode(kp.as_ref());
    let recovered = Secp256k1KeyPair::from_str(&kp_str).unwrap();
    assert_eq!(kp, recovered);
}

// `from_bytes` accepts r || s with r and s in [0, n), and does not normalize s: `as_bytes` returns
// the input. Signatures with r = 0 or s = 0 decode but never verify, and neither do high-s ones.
#[test]
fn to_from_bytes_signature() {
    let kp = keys().pop().unwrap();
    let signature = kp.sign(MSG);
    let bytes = signature.as_bytes().to_vec();
    let decode = |bytes: &[u8]| <Secp256k1Signature as ToFromBytes>::from_bytes(bytes);
    assert_eq!(decode(&bytes).unwrap(), signature);

    // Only 64 bytes are accepted.
    for len in (0..=3 * SIG_LENGTH).filter(|&len| len != SIG_LENGTH) {
        let bytes: Vec<u8> = bytes.iter().cycle().take(len).copied().collect();
        assert!(decode(&bytes).is_err(), "{}", len);
    }

    let with_r = |r: &[u8]| [r, &bytes[32..]].concat();
    let with_s = |s: &[u8]| [&bytes[..32], s].concat();
    let mut order_minus_one = GROUP_ORDER;
    order_minus_one[31] -= 1;
    for bytes in [
        with_r(&[0; 32]),
        with_s(&[0; 32]),
        [[0; 32], [0; 32]].concat(),
        with_r(&order_minus_one),
        with_s(&order_minus_one),
        with_s(&HALF_GROUP_ORDER),
        negate_s(&bytes),
    ] {
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.as_bytes(), bytes);
        assert!(kp.public().verify(MSG, &decoded).is_err());
        // Eq and Hash agree with the bytes.
        let again = decode(decoded.as_bytes()).unwrap();
        assert_eq!(again, decoded);
        assert_eq!(hash_of(&again), hash_of(&decoded));
    }

    for bytes in [
        with_r(&GROUP_ORDER),
        with_s(&GROUP_ORDER),
        with_r(&FIELD_MODULUS),
        with_s(&[0xff; 32]),
    ] {
        assert!(decode(&bytes).is_err());
    }
}

//
// Signature verification tests
//

#[test]
fn verify_valid_signature() {
    let kp: Secp256k1KeyPair = Secp256k1PrivateKey::from_bytes(&[
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107, 94, 203, 174, 253,
        102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ])
    .unwrap()
    .into();

    // Sign over raw message
    let message: &[u8] = b"Hello, world!";

    // Pin a signature using a deterministic private key bytes. This is useful to compare test result with typescript implementation.
    // See: https://github.com/MystenLabs/sui/tree/main/sdk/typescript/test/unit/cryptography/secp256k1-keypair.test.ts
    let signature = kp.sign(message);
    assert_eq!(Hex::encode(signature.clone()), "25d450f191f6d844bf5760c5c7b94bc67acc88be76398129d7f43abdef32dc7f7f1a65b7d65991347650f3dd3fa3b3a7f9892a0608521cbcf811ded433b31f8b");

    // Verify the signature.
    assert!(kp.public().verify(message, &signature).is_ok());
}

#[test]
fn verify_hashed_failed_if_different_hash() {
    let kp = keys().pop().unwrap();
    let pk = kp.public();

    // A signature only verifies with the hash function it was made with. The default is SHA-256.
    let signatures = [
        kp.sign_with_hash::<Sha256>(MSG),
        kp.sign_with_hash::<Keccak256>(MSG),
        kp.sign_with_hash::<Sha3_256>(MSG),
        kp.sign_with_hash::<Blake2b256>(MSG),
    ];
    assert_eq!(kp.sign(MSG), signatures[0]);
    for (i, sig) in signatures.iter().enumerate() {
        assert_eq!(pk.verify(MSG, sig).is_ok(), i == 0);
        assert_eq!(pk.verify_with_hash::<Sha256>(MSG, sig).is_ok(), i == 0);
        assert_eq!(pk.verify_with_hash::<Keccak256>(MSG, sig).is_ok(), i == 1);
        assert_eq!(pk.verify_with_hash::<Sha3_256>(MSG, sig).is_ok(), i == 2);
        assert_eq!(pk.verify_with_hash::<Blake2b256>(MSG, sig).is_ok(), i == 3);
    }

    // The empty message and long messages work as well.
    for msg in [&[][..], &[0xab; 1000][..]] {
        assert!(pk
            .verify_with_hash::<Keccak256>(msg, &kp.sign_with_hash::<Keccak256>(msg))
            .is_ok());
        assert!(pk.verify(msg, &kp.sign(msg)).is_ok());
        assert!(pk.verify(msg, &kp.sign(MSG)).is_err());
    }
}

#[test]
fn test_verify_sui_mainnet_transaction() {
    // A Sui user signature is flag || signature || compressed public key.
    let signature = Base64::decode(SUI_TX_SIGNATURE).unwrap();
    assert_eq!(signature.len(), 1 + SIG_LENGTH + PK_LENGTH);
    assert_eq!(signature[0], SUI_SECP256K1_FLAG);
    let sig = <Secp256k1Signature as ToFromBytes>::from_bytes(&signature[1..65]).unwrap();
    let pk = Secp256k1PublicKey::from_bytes(&signature[65..]).unwrap();
    assert_eq!(pk.as_bytes(), &signature[65..]);

    // The transaction digest is blake2b("TransactionData::" || BCS of the transaction data).
    let tx_data = Base64::decode(SUI_TX_DATA).unwrap();
    let mut hasher = Blake2b256::new();
    hasher.update(b"TransactionData::");
    hasher.update(&tx_data);
    assert_eq!(Base58::encode(hasher.finalize().digest), SUI_TX_DIGEST);

    // The sender is the address of the public key.
    assert_eq!(Hex::encode(sui_address(&pk)), SUI_TX_SENDER);

    // The signed message is blake2b of the intent message: the intent (scope TransactionData = 0,
    // version 0, app Sui = 0) followed by the transaction data. It is hashed again with the default
    // hash (SHA-256) before signing.
    let intent_message_digest = |intent: [u8; 3]| {
        let mut hasher = Blake2b256::new();
        hasher.update(intent);
        hasher.update(&tx_data);
        hasher.finalize().digest
    };
    assert!(pk.verify(&intent_message_digest([0, 0, 0]), &sig).is_ok());
    assert!(!is_high_s(sig.as_bytes()));
    // Any other intent, or another hash function, is rejected.
    assert!(pk.verify(&intent_message_digest([3, 0, 0]), &sig).is_err());
    assert!(pk
        .verify_with_hash::<Keccak256>(&intent_message_digest([0, 0, 0]), &sig)
        .is_err());
    // So is the high-s form of the same signature.
    let high_s =
        <Secp256k1Signature as ToFromBytes>::from_bytes(&negate_s(sig.as_bytes())).unwrap();
    assert!(pk
        .verify(&intent_message_digest([0, 0, 0]), &high_s)
        .is_err());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let kp = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);

    // Verify the signature against good digest passes.
    let signature = kp.sign(digest.as_ref());
    assert!(kp.public().verify(digest.as_ref(), &signature).is_ok());

    // Verify the signature against bad digest fails.
    let bad_message: &[u8] = b"Bad message!";
    let digest = Sha256::digest(bad_message);

    assert!(kp.public().verify(digest.as_ref(), &signature).is_err());
}

// ECDSA signatures are malleable: if (r, s) is valid, then so is (r, n - s). Like Bitcoin and
// Ethereum transactions, verification only accepts the one with s <= n / 2, which is the one that
// signing produces. k256 does the same.
#[test]
fn fail_to_verify_if_upper_s() {
    // Test case from https://github.com/fjl/go-ethereum/blob/41c854a60fad2ad9bb732857445624c7214541db/crypto/signature_test.go#L79
    // Note that keccak256(msg) = d301ce462d3e639518f482c7f03821fec1e602018630ce621e1e7851c12343a6.
    let msg =
        hex::decode("f854018664697363763582765f82696490736563703235366b312d6b656363616b83697034847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap();
    let pk = Secp256k1PublicKey::from_bytes(
        &hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138").unwrap(),
    )
    .unwrap();

    let mut internal_sig = Signature::from_compact(&hex::decode("638a54215d80a6713c8d523a6adc4e6e73652d859103a36b700851cb0e61b66b8ebfc1a610c57d732ec6e0a8f06a9a7a28df5051ece514702ff9cdff0b11f454").unwrap()).unwrap();

    let sig =
        <Secp256k1Signature as ToFromBytes>::from_bytes(&internal_sig.serialize_compact()).unwrap();

    // Failed to verify with upper S.
    assert!(pk.verify_with_hash::<Keccak256>(&msg, &sig).is_err());

    // Normalize S to be less than N/2.
    internal_sig.normalize_s();
    let normalized_sig =
        <Secp256k1Signature as ToFromBytes>::from_bytes(&internal_sig.serialize_compact()).unwrap();
    assert!(pk
        .verify_with_hash::<Keccak256>(&msg, &normalized_sig)
        .is_ok());

    // Signatures by this module are low-s, and negating s gives a signature that is rejected.
    let kp = keys().pop().unwrap();
    for msg in [&b"a"[..], b"b", b"c", b"d"] {
        let sig = kp.sign_with_hash::<Keccak256>(msg);
        assert!(!is_high_s(sig.as_bytes()));
        let high_s_bytes = negate_s(sig.as_bytes());
        assert!(is_high_s(&high_s_bytes));
        let high_s = <Secp256k1Signature as ToFromBytes>::from_bytes(&high_s_bytes).unwrap();
        assert_ne!(high_s, sig);
        assert!(kp
            .public()
            .verify_with_hash::<Keccak256>(msg, &high_s)
            .is_err());

        let digest = Keccak256::digest(msg).digest;
        assert!(k256_verify(kp.public().as_bytes(), &digest, sig.as_bytes()));
        assert!(!k256_verify(kp.public().as_bytes(), &digest, &high_s_bytes));

        // Normalizing s gives the original signature back.
        let mut normalized = high_s.sig;
        normalized.normalize_s();
        assert_eq!(normalized.serialize_compact(), sig.as_bytes());
    }
}

#[test]
fn wycheproof_test() {
    // Wycheproof's ECDSA test sets follow plain ECDSA, where both (r, s) and (r, n - s) are valid,
    // so its valid high-s tests are rejected here. Every other test gives the expected result.
    // The Bitcoin test set requires low-s like this module, so it matches exactly.
    assert!(check_wycheproof::<Sha256>(TestName::EcdsaSecp256k1Sha256, false) > 0);
    assert!(check_wycheproof::<Sha256>(TestName::EcdsaSecp256k1Sha256P1363, true) > 0);
    assert!(check_wycheproof::<Sha3_256>(TestName::EcdsaSecp256k1Sha3_256, false) > 0);
    assert_eq!(
        check_wycheproof::<Sha256>(TestName::EcdsaSecp256k1Sha256Bitcoin, false),
        0
    );
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures.swap(0, 1);

    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = Secp256k1PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = Secp256k1PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = test_helpers::signature_test_inputs_different_msg::<Secp256k1KeyPair>();
    let res = Secp256k1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = test_helpers::signature_test_inputs_different_msg::<Secp256k1KeyPair>();
    inputs.signatures.swap(0, 1);
    let res = Secp256k1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

//
// Other tests
//

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();

    // Spawn the signature service.
    let service = SignatureService::new(kp);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let signature = service.request_signature(digest).await;

    // Verify the signature we received.
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = Secp256k1KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        let sk_memory: &[u8] =
            unsafe { std::slice::from_raw_parts(bytes_ptr, constants::SECRET_KEY_SIZE) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that self.privkey is set to 1 (see DUMMY_KEYPAIR)
    unsafe {
        for i in 0..constants::SECRET_KEY_SIZE {
            assert_eq!(*ptr.add(i), 1);
        }
    }

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] =
        unsafe { std::slice::from_raw_parts(bytes_ptr, constants::SECRET_KEY_SIZE) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for Secp256k1PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for Secp256k1PrivateKey>"
        );
    });
}

#[test]
fn public_key_ordering() {
    // Keys are ordered like their compressed encodings, so sorting keys and sorting their bytes
    // gives the same order.
    let mut rng = StdRng::from_seed([1; 32]);
    let pks: Vec<Secp256k1PublicKey> = (0..20)
        .map(|_| Secp256k1KeyPair::generate(&mut rng).public().clone())
        .collect();
    for pk1 in &pks {
        for pk2 in &pks {
            assert_eq!(pk1.as_bytes().cmp(pk2.as_bytes()), pk1.cmp(pk2));
            assert_eq!(
                pk1.as_bytes().cmp(pk2.as_bytes()),
                pk1.partial_cmp(pk2).unwrap()
            );
            assert_eq!(pk1 == pk2, pk1.as_bytes() == pk2.as_bytes());
        }
    }
}

#[test]
fn hash_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    assert_eq!(hash_of(public_key), hash_of(&public_key.as_bytes()));
}

#[test]
fn fmt_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    assert_eq!(
        public_key.to_string(),
        Base64::encode(public_key.as_bytes())
    );
}

#[test]
fn hash_signature() {
    let sig = keys().pop().unwrap().sign(MSG);
    assert_eq!(hash_of(&sig), hash_of(&sig.as_bytes()));
}

#[test]
fn fmt_signature() {
    let sig = keys().pop().unwrap().sign(MSG);
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

//
// Proptests
//

fn arb_keypair() -> impl Strategy<Value = Secp256k1KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Secp256k1KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

/// Either a valid encoding (compressed, uncompressed or hybrid) of the public key of `keys()[0]` or
/// `keys()[1]`, mostly with one bit flipped, or bytes shaped like a public key encoding, to reach
/// deeper than the length check: the compressed, the uncompressed or any length, a prefix that is
/// mostly a SEC1 prefix (0x00 to 0x07), and an x-coordinate that is either random or small (a small
/// x is on the curve about half of the time).
fn arb_public_key_bytes() -> impl Strategy<Value = Vec<u8>> {
    let encodings: Vec<Vec<u8>> = keys()[..2]
        .iter()
        .flat_map(|kp| {
            let pk = kp.public();
            [
                pk.as_bytes().to_vec(),
                uncompressed(pk).to_vec(),
                hybrid(pk).to_vec(),
            ]
        })
        .collect();
    let valid_or_flipped = (
        proptest::sample::select(encodings),
        proptest::option::weighted(0.8, any::<usize>()),
    )
        .prop_map(|(mut bytes, bit)| {
            if let Some(bit) = bit {
                let bit = bit % (bytes.len() * 8);
                bytes[bit / 8] ^= 1 << (bit % 8);
            }
            bytes
        });
    let length = prop_oneof![
        3 => Just(PK_LENGTH),
        1 => Just(UNCOMPRESSED_PK_LENGTH),
        1 => 0..=2 * UNCOMPRESSED_PK_LENGTH,
    ];
    let prefix = prop_oneof![3 => 0..=7u8, 1 => any::<u8>()];
    let shaped = (
        length,
        prefix,
        0..4096u64,
        any::<bool>(),
        collection::vec(any::<u8>(), 2 * UNCOMPRESSED_PK_LENGTH),
    )
        .prop_map(|(length, prefix, x, small_x, body)| {
            let mut bytes = body[..length].to_vec();
            if small_x && length >= PK_LENGTH {
                bytes[1..25].fill(0);
                bytes[25..33].copy_from_slice(&x.to_be_bytes());
            }
            if let Some(first) = bytes.first_mut() {
                *first = prefix;
            }
            bytes
        });
    prop_oneof![valid_or_flipped, shaped]
}

/// Scalars (r or s) that are random, small, or close to n or n / 2.
pub(crate) fn arb_scalar_bytes() -> impl Strategy<Value = [u8; 32]> {
    let near = |value: [u8; 32]| {
        any::<u8>().prop_map(move |last| {
            let mut bytes = value;
            bytes[31] = last;
            bytes
        })
    };
    prop_oneof![
        2 => any::<[u8; 32]>(),
        1 => near([0; 32]),
        1 => near(GROUP_ORDER),
        1 => near(HALF_GROUP_ORDER),
    ]
}

/// Either r || s with adversarial scalars, or the signature by `keys()[0]` on `MSG`, as is, with
/// one bit flipped or with s negated.
fn arb_signature_bytes() -> impl Strategy<Value = Vec<u8>> {
    let honest = keys()[0].sign(MSG).as_bytes().to_vec();
    prop_oneof![
        3 => (arb_scalar_bytes(), arb_scalar_bytes()).prop_map(|(r, s)| [r, s].concat()),
        1 => Just(honest.clone()),
        3 => flip_bit(honest.clone()),
        1 => Just(negate_s(&honest)),
    ]
}

/// The given bytes with one bit flipped.
pub(crate) fn flip_bit(bytes: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    (0..bytes.len() * 8).prop_map(move |bit| {
        let mut bytes = bytes.clone();
        bytes[bit / 8] ^= 1 << (bit % 8);
        bytes
    })
}

/// Private keys: scalars that are random, small, or close to n or n / 2, or bytes of any length.
fn arb_private_key_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        arb_scalar_bytes().prop_map(|s| s.to_vec()),
        collection::vec(any::<u8>(), 0..=2 * SK_LENGTH),
    ]
}

proptest! {
    // fastcrypto and k256 derive the same public key and the same (deterministic, low-s)
    // signatures, and agree on the verification of honest, tampered and high-s signatures with
    // SHA-256 and Keccak-256 (the hash functions of Sui's secp256k1_verify Move native).
    #[test]
    fn test_k256_against_secp256k1_lib(
        kp in arb_keypair(),
        msg in collection::vec(any::<u8>(), 0..100),
        keccak in any::<bool>(),
        tamper in proptest::option::of(prop_oneof![
            (0..SIG_LENGTH * 8).prop_map(Some),
            Just(None::<usize>),
        ]),
    ) {
        let k256_kp = k256::ecdsa::SigningKey::from_bytes(kp.as_bytes()).unwrap();
        let k256_pk = k256_kp.verifying_key().to_bytes();
        prop_assert_eq!(kp.public().as_bytes(), k256_pk.as_slice());

        let (sig, digest) = if keccak {
            (kp.sign_with_hash::<Keccak256>(&msg), Keccak256::digest(&msg).digest)
        } else {
            (kp.sign_with_hash::<Sha256>(&msg), Sha256::digest(&msg).digest)
        };
        let k256_sig: k256::ecdsa::Signature = k256_kp.sign_prehash(&digest).unwrap();
        prop_assert_eq!(sig.as_bytes(), k256_sig.as_ref());

        let bytes = match tamper {
            None => sig.as_bytes().to_vec(),
            Some(Some(bit)) => {
                let mut bytes = sig.as_bytes().to_vec();
                bytes[bit / 8] ^= 1 << (bit % 8);
                bytes
            }
            Some(None) => negate_s(sig.as_bytes()),
        };
        let verified = <Secp256k1Signature as ToFromBytes>::from_bytes(&bytes).is_ok_and(|sig| {
            if keccak {
                kp.public().verify_with_hash::<Keccak256>(&msg, &sig).is_ok()
            } else {
                kp.public().verify_with_hash::<Sha256>(&msg, &sig).is_ok()
            }
        });
        prop_assert_eq!(verified, tamper.is_none());
        prop_assert_eq!(verified, k256_verify(kp.public().as_bytes(), &digest, &bytes));
    }

    // Private keys decode iff they are 32 bytes in [1, n), like in k256, and give the same public
    // key as k256. A key pair is serialized as its private key.
    #[test]
    fn test_keypair_roundtrip(bytes in arb_private_key_bytes()) {
        let decoded = Secp256k1KeyPair::from_bytes(&bytes);
        prop_assert_eq!(Secp256k1PrivateKey::from_bytes(&bytes).is_ok(), decoded.is_ok());
        let k256_decoded = if bytes.len() == SK_LENGTH {
            k256::ecdsa::SigningKey::from_bytes(&bytes).ok()
        } else {
            None
        };
        prop_assert_eq!(decoded.is_ok(), k256_decoded.is_some());
        let from_bcs = bcs::from_bytes::<Secp256k1KeyPair>(&bytes).ok();
        prop_assert_eq!(
            from_bcs.as_ref(),
            decoded.as_ref().ok().filter(|_| bytes.len() == SK_LENGTH)
        );
        if let (Ok(kp), Some(k256_kp)) = (decoded, k256_decoded) {
            prop_assert_eq!(kp.as_bytes(), &bytes[..]);
            prop_assert_eq!(bincode::serialize(&kp).unwrap(), bytes);
            let k256_pk = k256_kp.verifying_key().to_bytes();
            prop_assert_eq!(kp.public().as_bytes(), k256_pk.as_slice());
        }
    }

    // Decoding never panics on adversarial bytes, every accepted encoding is the compressed,
    // uncompressed or hybrid encoding of the decoded key, Eq, Hash and Ord agree with the compressed
    // encoding, and the accepted encodings are the ones k256 accepts (up to the hybrid and compact
    // encodings that only one of them supports).
    #[test]
    fn test_decode_adversarial_public_keys(
        bytes in arb_public_key_bytes(),
        msg in any::<[u8; 8]>(),
    ) {
        let keys = keys();
        let decoded = Secp256k1PublicKey::from_bytes(&bytes);
        if let Ok(pk) = &decoded {
            let expected = match (bytes.len(), bytes[0]) {
                (PK_LENGTH, _) => pk.as_bytes().to_vec(),
                (UNCOMPRESSED_PK_LENGTH, PREFIX_UNCOMPRESSED) => uncompressed(pk).to_vec(),
                _ => hybrid(pk).to_vec(),
            };
            prop_assert_eq!(expected, bytes.clone());
            let compressed = Secp256k1PublicKey::from_bytes(pk.as_bytes()).unwrap();
            prop_assert_eq!(&compressed, pk);
            prop_assert_eq!(hash_of(&compressed), hash_of(pk));
            prop_assert_eq!(compressed.cmp(pk), std::cmp::Ordering::Equal);
            // Another key never verifies a signature by keys[0].
            prop_assert_eq!(
                pk.verify(&msg, &keys[0].sign(&msg)).is_ok(),
                pk == keys[0].public()
            );
        }

        let k256_decoded = k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes);
        match (bytes.len(), bytes.first()) {
            (UNCOMPRESSED_PK_LENGTH, Some(&(PREFIX_HYBRID_EVEN_Y | PREFIX_HYBRID_ODD_Y))) => {
                prop_assert!(k256_decoded.is_err())
            }
            (PK_LENGTH, Some(0x05)) => prop_assert!(decoded.is_err()),
            _ => {
                prop_assert_eq!(decoded.is_ok(), k256_decoded.is_ok());
                if let (Ok(pk), Ok(k256_pk)) = (&decoded, &k256_decoded) {
                    let k256_bytes = k256_pk.to_bytes();
                    prop_assert_eq!(pk.as_bytes(), k256_bytes.as_slice());
                }
            }
        }

        // Binary serde accepts exactly the compressed encodings that from_bytes accepts.
        prop_assert_eq!(
            bcs::from_bytes::<Secp256k1PublicKey>(&bytes).ok(),
            decoded.as_ref().ok().filter(|_| bytes.len() == PK_LENGTH).cloned()
        );
        // So do bytes representations, once converted.
        let as_bytes = bcs::from_bytes::<Secp256k1PublicKeyAsBytes>(&bytes);
        prop_assert_eq!(as_bytes.is_ok(), bytes.len() == PK_LENGTH);
        if let Ok(as_bytes) = &as_bytes {
            prop_assert_eq!(Secp256k1PublicKey::try_from(as_bytes).ok(), decoded.as_ref().ok().cloned());
        }
        // Human-readable serde goes through from_bytes.
        let json = format!("\"{}\"", Base64::encode(&bytes));
        prop_assert_eq!(serde_json::from_str::<Secp256k1PublicKey>(&json).ok(), decoded.ok());
    }

    // Signatures decode iff r < n and s < n, decoding does not change the bytes, and verification
    // agrees with k256 and only accepts the signature that keys[0] produces.
    #[test]
    fn test_decode_and_verify_adversarial_signatures(bytes in arb_signature_bytes()) {
        let kp = &keys()[0];
        let decoded = <Secp256k1Signature as ToFromBytes>::from_bytes(&bytes);
        prop_assert_eq!(
            decoded.is_ok(),
            bytes[..32] < GROUP_ORDER[..] && bytes[32..] < GROUP_ORDER[..]
        );
        if let Ok(sig) = &decoded {
            prop_assert_eq!(sig.as_bytes(), &bytes[..]);
        }
        let verified = decoded.as_ref().is_ok_and(|sig| kp.public().verify(MSG, sig).is_ok());
        prop_assert_eq!(verified, bytes == kp.sign(MSG).as_bytes());
        prop_assert_eq!(
            verified,
            k256_verify(kp.public().as_bytes(), &Sha256::digest(MSG).digest, &bytes)
        );

        // Binary serde, bytes representations and JSON agree with from_bytes.
        prop_assert_eq!(
            bcs::from_bytes::<Secp256k1Signature>(&bytes).ok(),
            decoded.as_ref().ok().cloned()
        );
        let as_bytes = bcs::from_bytes::<Secp256k1SignatureAsBytes>(&bytes).unwrap();
        prop_assert_eq!(Secp256k1Signature::try_from(&as_bytes).ok(), decoded.as_ref().ok().cloned());
        let json = format!("\"{}\"", Base64::encode(&bytes));
        prop_assert_eq!(serde_json::from_str::<Secp256k1Signature>(&json).ok(), decoded.ok());
    }
}

/// The fraction of `SAMPLES` values from a strategy for which `property` holds, with a fixed seed.
pub(crate) fn rate<T: std::fmt::Debug>(
    strategy: impl Strategy<Value = T>,
    property: impl Fn(&T) -> bool,
) -> f64 {
    const SAMPLES: usize = 1000;
    let mut runner = TestRunner::deterministic();
    (0..SAMPLES)
        .filter(|_| property(&strategy.new_tree(&mut runner).unwrap().current()))
        .count() as f64
        / SAMPLES as f64
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // The adversarial strategies above must produce enough inputs that decode and verify, and
    // enough that do not, for the proptests to check something.
    let decoded = rate(arb_public_key_bytes(), |bytes| {
        Secp256k1PublicKey::from_bytes(bytes).is_ok()
    });
    assert!((0.1..0.4).contains(&decoded), "{decoded}");

    let decoded = rate(arb_signature_bytes(), |bytes| {
        <Secp256k1Signature as ToFromBytes>::from_bytes(bytes).is_ok()
    });
    assert!((0.75..0.98).contains(&decoded), "{decoded}");
    let honest = keys()[0].sign(MSG);
    let verified = rate(arb_signature_bytes(), |bytes| bytes == honest.as_bytes());
    assert!((0.05..0.25).contains(&verified), "{verified}");

    let decoded = rate(arb_private_key_bytes(), |bytes| {
        Secp256k1PrivateKey::from_bytes(bytes).is_ok()
    });
    assert!((0.25..0.6).contains(&decoded), "{decoded}");
}
