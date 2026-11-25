// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding as _;
use itertools::iproduct;
use once_cell::sync::Lazy;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::Signature;
use p256::elliptic_curve::bigint::ArrayEncoding;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::scalar::IsHigh;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{Scalar, U256};
use proptest::collection;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use proptest::{prelude::*, strategy::Strategy};
use rand::{rngs::StdRng, SeedableRng as _};
use rust_secp256k1::constants::SECRET_KEY_SIZE;
use serde::Deserialize;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use wycheproof::ecdsa::{TestName, TestSet};
use wycheproof::TestResult;

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use crate::hash::{Blake2b256, HashFunction, Keccak256, Sha256, Sha3_256};
use crate::secp256r1::{
    Secp256r1KeyPair, Secp256r1PrivateKey, Secp256r1PublicKey, Secp256r1PublicKeyAsBytes,
    Secp256r1Signature, Secp256r1SignatureAsBytes, SECP256R1_PRIVATE_KEY_LENGTH,
    SECP256R1_PUBLIC_KEY_LENGTH, SECP256R1_SIGNATURE_LENGTH,
};
use crate::signature_service::SignatureService;
use crate::test_helpers::{self, verify_serialization};
use crate::traits::{EncodeDecodeBase64, KeyPair, Signer, ToFromBytes, VerifyingKey};

//
// Helper functions
//

pub(crate) const MSG: &[u8] = b"Hello, world!";

const PK_LENGTH: usize = SECP256R1_PUBLIC_KEY_LENGTH;
pub(crate) const SIG_LENGTH: usize = SECP256R1_SIGNATURE_LENGTH;
const SK_LENGTH: usize = SECP256R1_PRIVATE_KEY_LENGTH;

/// The order n of the P-256 group, big-endian.
pub(crate) const GROUP_ORDER: [u8; 32] =
    hex_literal::hex!("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

/// floor(n / 2), big-endian. A signature has a low s if s <= floor(n / 2).
const HALF_GROUP_ORDER: [u8; 32] =
    hex_literal::hex!("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");

/// The P-256 field modulus p, big-endian.
pub(crate) const FIELD_MODULUS: [u8; 32] =
    hex_literal::hex!("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

/// The compressed encoding of the generator, which is the public key of the private key 1.
const GENERATOR_COMPRESSED: [u8; PK_LENGTH] =
    hex_literal::hex!("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");

/// The compressed encoding of the point with x = 0, the smallest x-coordinate on the curve.
pub(crate) const X_ZERO_COMPRESSED: [u8; PK_LENGTH] =
    hex_literal::hex!("020000000000000000000000000000000000000000000000000000000000000000");

/// `X_ZERO_COMPRESSED` with x = p instead of 0, that is, the same field element not reduced
/// modulo the field modulus p.
const X_ZERO_UNREDUCED: [u8; PK_LENGTH] =
    hex_literal::hex!("02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

/// A compressed encoding with x = 3, which is not the x-coordinate of a point on the curve.
const X_THREE_COMPRESSED: [u8; PK_LENGTH] =
    hex_literal::hex!("020000000000000000000000000000000000000000000000000000000000000003");

/// The private key of RFC 6979, A.2.5, and its public key: Ux with tag 0x03 since Uy is odd.
pub(crate) const RFC6979_PRIVATE_KEY: [u8; SK_LENGTH] =
    hex_literal::hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
pub(crate) const RFC6979_PUBLIC_KEY: [u8; PK_LENGTH] =
    hex_literal::hex!("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");

/// The messages and signatures r || s with SHA-256 of RFC 6979, A.2.5. The s of "sample" is high.
pub(crate) const RFC6979_SHA256_SIGNATURES: [(&[u8], [u8; SIG_LENGTH]); 2] = [
    (
        b"sample",
        hex_literal::hex!("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"),
    ),
    (
        b"test",
        hex_literal::hex!("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"),
    ),
];

/// A real passkey signature, from an iCloud passkey via https://passkey-example.vercel.app, and the
/// Sui transaction it signs. Both are taken from `test_real_passkey_output` in Sui's
/// crates/sui-types/src/unit_tests/passkey_authenticator_test.rs. The signature is the passkey flag
/// followed by the BCS of a [PasskeyAuthenticator], and the transaction is the BCS of its
/// `TransactionData`.
const PASSKEY_SIGNATURE: &str = "BiUL6eJ3+l0jTWmL4buH5lE8Vxe1+ge6xSU0oczBPpmt+h0AAAAAkwF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCJjaGFsbGVuZ2UiOiJ5TzEtb3VBczFBRUsyOWd0X1dJTGM4ZndDdlFjMkhEQmEwX2dTU3RpU1FzIiwib3JpZ2luIjoiaHR0cHM6Ly9wYXNza2V5LWV4YW1wbGUudmVyY2VsLmFwcCIsImNyb3NzT3JpZ2luIjpmYWxzZX1iAu0JsgVDVgBZQJhsl9MUZmUfUkNTh1qCg0zNWFrXfTx3NKuakm8Wqaa3qnfo+s9K2KvfYp8jT8BazhK7bi9YSmsCATpOyeWH387SdhY7+172wODmilJnXx5QcaUnR+3QlEM=";
const PASSKEY_TX_DATA: &str = "AAAAAJwMAOkp8IQxWD2tDpQJta+yDNuuAEP6VXfyV32+iKDbARrKzR59iiRcEIbBEBlB283cnWUBeUeKCiMa3UKM6NURNRHQFAAAAAAgVLos3IwH9g4OHDSWiKyUZCvixybPtnDQIeML1f+ErGOcDADpKfCEMVg9rQ6UCbWvsgzbrgBD+lV38ld9voig2+gDAAAAAAAAgIQeAAAAAAAA";
const PASSKEY_SENDER: [u8; 32] =
    hex_literal::hex!("9c0c00e929f08431583dad0e9409b5afb20cdbae0043fa5577f2577dbe88a0db");

/// The signature scheme flags of secp256r1 and passkey in Sui.
const SUI_SECP256R1_FLAG: u8 = 0x02;
const SUI_PASSKEY_FLAG: u8 = 0x06;

/// The intent of a Sui transaction: scope `TransactionData`, version 0 and app id Sui.
const SUI_TRANSACTION_INTENT: [u8; 3] = [0, 0, 0];

/// The messages that the proptests sign.
pub(crate) const MESSAGES: [&[u8]; 3] = [b"", MSG, b"Another message"];

/// The key pairs that the proptests sign with, and their signatures on [MESSAGES]:
/// `HONEST_SIGNATURES[i][j]` is the signature of `HONEST_KEYS[i]` on `MESSAGES[j]`.
pub(crate) static HONEST_KEYS: Lazy<Vec<Secp256r1KeyPair>> = Lazy::new(keys);
static HONEST_SIGNATURES: Lazy<Vec<Vec<Vec<u8>>>> = Lazy::new(|| {
    HONEST_KEYS
        .iter()
        .map(|kp| {
            MESSAGES
                .iter()
                .map(|msg| kp.sign(msg).as_bytes().to_vec())
                .collect()
        })
        .collect()
});

/// The BCS layout of a passkey authenticator in Sui.
#[derive(Deserialize)]
struct PasskeyAuthenticator {
    authenticator_data: Vec<u8>,
    client_data_json: String,
    /// The secp256r1 flag followed by the signature and the public key.
    user_signature: Vec<u8>,
}

pub fn keys() -> Vec<Secp256r1KeyPair> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| Secp256r1KeyPair::generate(&mut rng))
        .collect()
}

pub(crate) fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Whether the s of an r || s signature (followed by anything) is greater than n / 2.
pub(crate) fn is_high_s(signature: &[u8]) -> bool {
    signature[32..SIG_LENGTH] > HALF_GROUP_ORDER[..]
}

/// Replaces s by n - s in an r || s signature (followed by anything). The result verifies under
/// plain ECDSA iff the input does, so it is the other signature from ECDSA's malleability.
pub(crate) fn negate_s(signature: &[u8]) -> Vec<u8> {
    let sig = Signature::from_slice(&signature[..SIG_LENGTH]).unwrap();
    let negated = Signature::from_scalars(sig.r(), -*sig.s()).unwrap();
    let mut bytes = signature.to_vec();
    bytes[..SIG_LENGTH].copy_from_slice(&negated.to_bytes());
    bytes
}

/// Adds a small signed integer to a 32-byte big-endian integer, modulo 2^256.
pub(crate) fn add_small(bytes: &[u8; 32], delta: i64) -> [u8; 32] {
    let x = U256::from_be_slice(bytes);
    let d = U256::from_u64(delta.unsigned_abs());
    match delta >= 0 {
        true => x.wrapping_add(&d),
        false => x.wrapping_sub(&d),
    }
    .to_be_byte_array()
    .into()
}

/// Whether the y-coordinate of a public key is at most p - y, that is, smaller than p / 2.
fn has_smaller_y(pk: &Secp256r1PublicKey) -> bool {
    let y = U256::from_be_slice(pk.pubkey.to_encoded_point(false).y().unwrap());
    y <= U256::from_be_slice(&FIELD_MODULUS).wrapping_sub(&y)
}

/// The uncompressed SEC1 encoding of a public key.
fn uncompressed(pk: &Secp256r1PublicKey) -> Vec<u8> {
    pk.pubkey.to_encoded_point(false).as_bytes().to_vec()
}

/// Verification with p256, an independent implementation, of an r || s signature on the message
/// hashed with `H`. Unlike fastcrypto, p256 accepts a high s.
pub(crate) fn p256_verify<H: HashFunction<32>>(pk: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    match (
        p256::ecdsa::VerifyingKey::from_sec1_bytes(pk),
        Signature::from_slice(signature),
    ) {
        (Ok(pk), Ok(signature)) => pk
            .verify_prehash(&H::digest(msg).digest, &signature)
            .is_ok(),
        _ => false,
    }
}

/// The deterministic (RFC 6979) signature of p256 on the message hashed with `H`, with s
/// normalized to the lower half.
fn p256_sign<H: HashFunction<32>>(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    let sk = p256::ecdsa::SigningKey::from_slice(sk).unwrap();
    let signature: Signature = sk.sign_prehash(&H::digest(msg).digest).unwrap();
    signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .to_vec()
}

/// The Sui address of a public key: blake2b(flag || compressed public key).
fn sui_address(flag: u8, pk: &Secp256r1PublicKey) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update([flag]);
    hasher.update(pk.as_bytes());
    hasher.finalize().digest
}

/// Runs a Wycheproof ECDSA suite for P-256 and checks that `verify(pk, msg, signature)` accepts
/// exactly the valid signatures, except those with a high s unless `accepts_high_s`. If a high s is
/// rejected, it must accept exactly the valid signatures once s is normalized. The signature is r || s,
/// converted from DER unless `p1363`. Returns the number of accepted signatures and the number of
/// valid signatures with a high s.
pub(crate) fn check_wycheproof(
    name: TestName,
    p1363: bool,
    accepts_high_s: bool,
    verify: impl Fn(&Secp256r1PublicKey, &[u8], &[u8]) -> bool,
) -> (usize, usize) {
    let (mut accepted, mut valid_high_s) = (0, 0);
    for test_group in TestSet::load(name).unwrap().test_groups {
        // The keys are given in the uncompressed format.
        let pk = Secp256r1PublicKey::from_bytes(&test_group.key.key).unwrap();
        for test in test_group.tests {
            let signature = match p1363 {
                true => test.sig.to_vec(),
                false => Signature::from_der(&test.sig).map_or(vec![], |s| s.to_bytes().to_vec()),
            };
            let ok = verify(&pk, &test.msg, &signature);
            let valid = test.result == TestResult::Valid;
            let high_s = valid && is_high_s(&signature);
            assert_eq!(
                ok,
                valid && (accepts_high_s || !high_s),
                "tc {}: {}",
                test.tc_id,
                test.comment
            );
            // Otherwise the invalid signatures with a high s would only be rejected for their s.
            let normalized = Signature::from_slice(&signature)
                .ok()
                .and_then(|s| s.normalize_s());
            if let (false, Some(normalized)) = (accepts_high_s, normalized) {
                assert_eq!(
                    verify(&pk, &test.msg, &normalized.to_bytes()),
                    valid,
                    "tc {} with a normalized s: {}",
                    test.tc_id,
                    test.comment
                );
            }
            accepted += ok as usize;
            valid_high_s += high_s as usize;
        }
    }
    (accepted, valid_high_s)
}

fn signature_test_inputs() -> (Vec<u8>, Vec<Secp256r1PublicKey>, Vec<Secp256r1Signature>) {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let (pubkeys, signatures): (Vec<Secp256r1PublicKey>, Vec<Secp256r1Signature>) = keys()
        .into_iter()
        .take(3)
        .map(|kp| {
            let sig = kp.sign(digest.as_ref());
            (kp.public().clone(), sig)
        })
        .unzip();

    (digest.to_vec(), pubkeys, signatures)
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
}

#[test]
fn serde_and_bytes_representations() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let signature = kp.sign(MSG);

    // Human-readable formats use Base64 and binary formats the bytes without a length prefix. A key
    // pair is encoded as its private key.
    for (json, bytes) in [
        (serde_json::to_string(&pk).unwrap(), pk.as_bytes()),
        (
            serde_json::to_string(&signature).unwrap(),
            signature.as_bytes(),
        ),
        (serde_json::to_string(&kp).unwrap(), kp.secret.as_bytes()),
    ] {
        assert_eq!(json, format!("\"{}\"", Base64::encode(bytes)));
    }
    assert_eq!(bcs::to_bytes(&pk).unwrap(), pk.as_bytes());
    assert_eq!(bcs::to_bytes(&signature).unwrap(), signature.as_bytes());
    assert_eq!(bcs::to_bytes(&kp).unwrap(), kp.secret.as_bytes());
    assert_eq!(
        bcs::from_bytes::<Secp256r1KeyPair>(&bcs::to_bytes(&kp).unwrap()).unwrap(),
        kp
    );

    // Deserialization validates like from_bytes, and BCS rejects trailing bytes.
    let mut long = signature.as_bytes().to_vec();
    long.push(0);
    assert!(bcs::from_bytes::<Secp256r1Signature>(&long).is_err());
    assert!(bcs::from_bytes::<Secp256r1Signature>(&[0; SIG_LENGTH]).is_err());
    assert!(serde_json::from_str::<Secp256r1Signature>(&format!(
        "\"{}\"",
        Base64::encode([0; SIG_LENGTH])
    ))
    .is_err());
    assert!(bcs::from_bytes::<Secp256r1PublicKey>(&X_THREE_COMPRESSED).is_err());
    let uncompressed = uncompressed(&pk);
    let json = format!("\"{}\"", Base64::encode(&uncompressed));
    assert_eq!(
        serde_json::from_str::<Secp256r1PublicKey>(&json).unwrap(),
        pk
    );
    assert!(bcs::from_bytes::<Secp256r1PublicKey>(&uncompressed).is_err());
    assert!(bcs::from_bytes::<Secp256r1PrivateKey>(&[0; SK_LENGTH]).is_err());
    assert!(bcs::from_bytes::<Secp256r1KeyPair>(&GROUP_ORDER).is_err());

    // The *AsBytes types hold any bytes of the right length, and converting them validates.
    let pk_bytes: Secp256r1PublicKeyAsBytes = bcs::from_bytes(&X_THREE_COMPRESSED).unwrap();
    assert!(Secp256r1PublicKey::try_from(&pk_bytes).is_err());
    let pk_bytes: Secp256r1PublicKeyAsBytes = bcs::from_bytes(pk.as_bytes()).unwrap();
    assert_eq!(Secp256r1PublicKey::try_from(&pk_bytes).unwrap(), pk);
    assert_eq!(Secp256r1PublicKeyAsBytes::from(&pk), pk_bytes);
    let signature_bytes: Secp256r1SignatureAsBytes = bcs::from_bytes(&[0; SIG_LENGTH]).unwrap();
    assert!(Secp256r1Signature::try_from(&signature_bytes).is_err());
    let signature_bytes: Secp256r1SignatureAsBytes = bcs::from_bytes(signature.as_bytes()).unwrap();
    assert_eq!(
        Secp256r1Signature::try_from(&signature_bytes).unwrap(),
        signature
    );
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    let import = Secp256r1PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), public_key.as_ref());
}

#[test]
fn public_key_from_bytes() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let pk_bytes = pk.as_ref();
    let rebuilt_pk = <Secp256r1PublicKey as ToFromBytes>::from_bytes(pk_bytes).unwrap();
    assert_eq!(rebuilt_pk, pk);

    // check for failure
    let mut pk_bytes = pk.as_ref().to_vec();
    pk_bytes.pop();
    assert!(<Secp256r1PublicKey as ToFromBytes>::from_bytes(&pk_bytes).is_err());

    // from_bytes accepts the SEC1 formats that p256 accepts: compressed (33 bytes with tag 0x02 or
    // 0x03), uncompressed (65 bytes with tag 0x04) and compact (33 bytes with tag 0x05, see
    // compact_encoding). A key decoded from the uncompressed format is encoded compressed.
    let mut pks: Vec<_> = keys().iter().map(|kp| kp.public().clone()).collect();
    pks.push(Secp256r1PublicKey::from_bytes(&GENERATOR_COMPRESSED).unwrap());
    pks.push(Secp256r1PublicKey::from_bytes(&X_ZERO_COMPRESSED).unwrap());
    for pk in pks {
        let compressed = pk.as_bytes().to_vec();
        assert_eq!(
            compressed,
            pk.pubkey.to_encoded_point(true).as_bytes().to_vec()
        );
        let uncompressed = uncompressed(&pk);
        for bytes in [&compressed, &uncompressed] {
            for decoded in [
                Secp256r1PublicKey::from_bytes(bytes).unwrap(),
                Secp256r1PublicKey::from_bytes_strict(bytes).unwrap(),
            ] {
                assert_eq!(decoded, pk);
                assert_eq!(decoded.as_bytes(), compressed);
            }
        }

        // Flipping the tag of the compressed format gives the negated key.
        let mut negated = compressed.clone();
        negated[0] ^= 1;
        assert_eq!(
            *Secp256r1PublicKey::from_bytes(&negated)
                .unwrap()
                .pubkey
                .as_affine(),
            -*pk.pubkey.as_affine()
        );

        // Other tags are rejected, including the hybrid tags 0x06 and 0x07.
        for tag in 0..=u8::MAX {
            let mut short = compressed.clone();
            short[0] = tag;
            assert_eq!(
                Secp256r1PublicKey::from_bytes(&short).is_ok(),
                [0x02, 0x03, 0x05].contains(&tag)
            );
            let mut long = uncompressed.clone();
            long[0] = tag;
            assert_eq!(Secp256r1PublicKey::from_bytes(&long).is_ok(), tag == 0x04);
        }

        // Other lengths are rejected.
        for len in [0, 1, 32, 34, 64, 66] {
            let mut bytes = compressed.clone();
            bytes.resize(len, 0);
            assert!(Secp256r1PublicKey::from_bytes(&bytes).is_err());
        }
    }

    // An x-coordinate that is not on the curve, x not reduced modulo p and the identity (a single
    // zero byte in SEC1) are rejected, also by p256.
    let mut x_three_odd = X_THREE_COMPRESSED;
    x_three_odd[0] ^= 1;
    for bytes in [
        &X_THREE_COMPRESSED[..],
        &x_three_odd,
        &X_ZERO_UNREDUCED,
        &[0x00],
        &[0; PK_LENGTH],
    ] {
        assert!(Secp256r1PublicKey::from_bytes(bytes).is_err());
        assert!(p256::PublicKey::from_sec1_bytes(bytes).is_err());
    }
}

#[test]
fn compact_encoding() {
    fn hash(pk: &Secp256r1PublicKey) -> u64 {
        let mut hasher = DefaultHasher::new();
        pk.hash(&mut hasher);
        hasher.finish()
    }

    // 0x05 || x decodes to either P or -P. Check that both cases occur.
    let mut seen = [false, false];
    let mut rng = StdRng::from_seed([0; 32]);
    for _ in 0..16 {
        let pk = Secp256r1KeyPair::generate(&mut rng).public().clone();
        let mut negated_bytes = pk.as_bytes().to_vec();
        negated_bytes[0] ^= 1;
        let negated = Secp256r1PublicKey::from_bytes(&negated_bytes).unwrap();
        let mut compact_bytes = pk.as_bytes().to_vec();
        compact_bytes[0] = 0x05;

        // The lenient parser accepts the compact encoding and keeps the input bytes.
        let compact = Secp256r1PublicKey::from_bytes(&compact_bytes).unwrap();
        assert_eq!(compact.as_bytes(), compact_bytes.as_slice());
        assert!(has_smaller_y(&compact));

        // Equal keys hash equally, regardless of the encoding they were parsed from.
        let same = if compact == pk { &pk } else { &negated };
        assert_eq!(&compact, same);
        assert_eq!(hash(&compact), hash(same));
        seen[(compact == pk) as usize] = true;

        // The strict parser rejects the compact encoding but accepts the other encodings.
        assert!(Secp256r1PublicKey::from_bytes_strict(&compact_bytes).is_err());
        assert_eq!(
            Secp256r1PublicKey::from_bytes_strict(pk.as_bytes()).unwrap(),
            pk
        );
        assert_eq!(
            Secp256r1PublicKey::from_bytes_strict(pk.pubkey.to_encoded_point(false).as_bytes())
                .unwrap(),
            pk
        );
    }
    assert_eq!(seen, [true, true]);
}

#[test]
fn import_export_secret_key() {
    let kpref = keys().pop().unwrap();
    let secret_key = kpref.private();
    let export = secret_key.encode_base64();
    let import = Secp256r1PrivateKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), secret_key.as_ref());
}

#[test]
fn private_key_from_bytes() {
    let kp = keys().pop().unwrap();
    let sk = kp.private();
    let sk_bytes = sk.as_ref();
    let rebuilt_sk = <Secp256r1PrivateKey as ToFromBytes>::from_bytes(sk_bytes).unwrap();
    assert_eq!(rebuilt_sk, sk);

    // check for failure
    let mut sk_bytes = sk.as_ref().to_vec();
    sk_bytes.pop();
    assert!(<Secp256r1PrivateKey as ToFromBytes>::from_bytes(&sk_bytes).is_err());
}

#[test]
fn non_canonical_secret_key() {
    // Secret keys should be scalars between 0 and the base point order

    let zero =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&zero).is_err());

    let one =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&one).is_ok());

    let order_minus_one =
        hex::decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&order_minus_one).is_ok());

    let order =
        hex::decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551").unwrap();
    assert!(Secp256r1PrivateKey::from_bytes(&order).is_err());

    let max = [0xff; SK_LENGTH];
    assert!(Secp256r1PrivateKey::from_bytes(&max).is_err());

    // Key pairs are decoded from their private key, so they reject the same values.
    for bytes in [&zero[..], &order, &max] {
        assert!(Secp256r1KeyPair::from_bytes(bytes).is_err());
    }

    // The public key of 1 is the generator, and the public key of n - 1 is its negation.
    let mut negated_generator = GENERATOR_COMPRESSED;
    negated_generator[0] ^= 1;
    for (sk, pk) in [
        (one, GENERATOR_COMPRESSED),
        (order_minus_one, negated_generator),
    ] {
        let kp = Secp256r1KeyPair::from_bytes(&sk).unwrap();
        assert_eq!(kp.public().as_bytes(), pk);
    }

    // Only 32 bytes are accepted. p256 also accepts 24 to 31 bytes and pads them with zeros.
    for len in 0..=2 * SK_LENGTH {
        let bytes = vec![1; len];
        assert_eq!(
            Secp256r1PrivateKey::from_bytes(&bytes).is_ok(),
            len == SK_LENGTH
        );
        assert_eq!(
            Secp256r1KeyPair::from_bytes(&bytes).is_ok(),
            len == SK_LENGTH
        );
        assert_eq!(
            p256::ecdsa::SigningKey::from_slice(&bytes).is_ok(),
            (24..=SK_LENGTH).contains(&len)
        );
    }
}

#[test]
fn key_pair_from_string_roundtrip() {
    let kp = keys().pop().unwrap();
    let kp_str = Base64::encode(kp.as_ref());
    let recovered = Secp256r1KeyPair::from_str(&kp_str).unwrap();
    assert_eq!(kp, recovered);
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
fn to_from_bytes_signature() {
    let kpref = keys().pop().unwrap();
    let signature = kpref.sign(b"Hello, world!");
    let sig_bytes = signature.as_ref();
    let rebuilt_sig = <Secp256r1Signature as ToFromBytes>::from_bytes(sig_bytes).unwrap();
    assert_eq!(rebuilt_sig.as_ref(), signature.as_ref());
    // check for failure
    let mut sig_bytes = signature.as_ref().to_vec();
    sig_bytes.pop();
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&sig_bytes).is_err());

    // Only 64 bytes r || s are accepted, so DER encoded signatures are rejected.
    for len in [0, 1, 32, 63, 65, 72] {
        let mut bytes = signature.as_ref().to_vec();
        bytes.resize(len, 0);
        assert_eq!(
            <Secp256r1Signature as ToFromBytes>::from_bytes(&bytes),
            Err(FastCryptoError::InputLengthWrong(SIG_LENGTH))
        );
    }
    let der = signature.sig.to_der();
    assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(der.as_bytes()).is_err());
    // So are the 65 bytes of a recoverable signature.
    for byte in [0, 4] {
        assert!(<Secp256r1Signature as ToFromBytes>::from_bytes(&[byte; SIG_LENGTH + 1]).is_err());
    }

    // r and s must be in [1, n - 1], as in p256, and accepted values are encoded as given. Zero must
    // be rejected here since verification (split_scalars) panics if r or s is zero.
    let mut one = [0; 32];
    one[31] = 1;
    for (value, valid) in [
        ([0; 32], false),
        (one, true),
        (add_small(&GROUP_ORDER, -1), true),
        (GROUP_ORDER, false),
        ([0xff; 32], false),
    ] {
        for offset in [0, 32] {
            let mut bytes = signature.as_ref().to_vec();
            bytes[offset..offset + 32].copy_from_slice(&value);
            let decoded = <Secp256r1Signature as ToFromBytes>::from_bytes(&bytes);
            assert_eq!(decoded.is_ok(), valid);
            assert_eq!(Signature::from_slice(&bytes).is_ok(), valid);
            if let Ok(decoded) = decoded {
                assert_eq!(decoded.as_bytes(), bytes);
            }
        }
    }

    // A high s is accepted here and rejected by verification, see fail_to_verify_if_upper_s.
    let high_s = negate_s(signature.as_ref());
    assert!(is_high_s(&high_s));
    let decoded = <Secp256r1Signature as ToFromBytes>::from_bytes(&high_s).unwrap();
    assert_eq!(decoded.as_bytes(), high_s);
}

//
// Signature verification tests
//

#[test]
fn verify_invalid_signature() {
    let kp = keys().pop().unwrap();
    let signature = kp.sign(MSG);
    assert!(kp.public().verify(MSG, &signature).is_ok());

    // Another message or another key fails.
    assert!(kp.public().verify(b"Bad message!", &signature).is_err());
    assert!(keys()[0].public().verify(MSG, &signature).is_err());
}

#[test]
fn verify_hashed_failed_if_different_hash() {
    // A signature made with one hash function only verifies with that hash function. The default is
    // SHA-256, and the Move natives also use Keccak-256. Each signature is the one of p256.
    let kp = keys().pop().unwrap();
    let pk = kp.public();
    let sk = kp.secret.as_bytes();
    let signatures = [
        kp.sign_with_hash::<Sha256>(MSG),
        kp.sign_with_hash::<Keccak256>(MSG),
        kp.sign_with_hash::<Sha3_256>(MSG),
        kp.sign_with_hash::<Blake2b256>(MSG),
    ];
    assert_eq!(kp.sign(MSG), signatures[0]);
    assert_eq!(signatures[0].as_bytes(), p256_sign::<Sha256>(sk, MSG));
    assert_eq!(signatures[1].as_bytes(), p256_sign::<Keccak256>(sk, MSG));
    assert_eq!(signatures[2].as_bytes(), p256_sign::<Sha3_256>(sk, MSG));
    assert_eq!(signatures[3].as_bytes(), p256_sign::<Blake2b256>(sk, MSG));
    for (i, signature) in signatures.iter().enumerate() {
        assert_eq!(pk.verify(MSG, signature).is_ok(), i == 0);
        assert_eq!(
            pk.verify_with_hash::<Sha256>(MSG, signature).is_ok(),
            i == 0
        );
        assert_eq!(
            pk.verify_with_hash::<Keccak256>(MSG, signature).is_ok(),
            i == 1
        );
        assert_eq!(
            pk.verify_with_hash::<Sha3_256>(MSG, signature).is_ok(),
            i == 2
        );
        assert_eq!(
            pk.verify_with_hash::<Blake2b256>(MSG, signature).is_ok(),
            i == 3
        );
    }
}

#[test]
fn fail_to_verify_if_upper_s() {
    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = Sha256::digest(message);
    let pk = Secp256r1PublicKey::from_bytes(
        &hex::decode("0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a").unwrap(),
    )
    .unwrap();
    let sig = <Secp256r1Signature as ToFromBytes>::from_bytes(&hex::decode("63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be9120b2963fe63a35b44847a7888db981d1ccf0753a4673b094fed274a6589deb982a").unwrap()).unwrap();

    // Assert that S is in upper half
    assert_ne!(sig.sig.s().is_high().unwrap_u8(), 0);

    // Failed to verify with upper S.
    assert!(pk.verify(&digest.digest, &sig).is_err());

    let normalized = sig.sig.normalize_s().unwrap();

    // Normalize S to be less than N/2.
    let normalized_sig = Secp256r1Signature::from_bytes(normalized.to_bytes().as_slice()).unwrap();

    // Verify with normalized lower S.
    assert!(pk.verify(&digest.digest, &normalized_sig).is_ok());

    // Signing always gives a low s. The high-s twin of a signature decodes and verifies under p256,
    // which does not require a low s, but it is rejected.
    for kp in keys() {
        let signature = kp.sign(MSG);
        assert!(!is_high_s(signature.as_ref()));
        let high_s = negate_s(signature.as_ref());
        assert!(p256_verify::<Sha256>(kp.public().as_bytes(), MSG, &high_s));
        let high_s = <Secp256r1Signature as ToFromBytes>::from_bytes(&high_s).unwrap();
        assert!(kp.public().verify(MSG, &high_s).is_err());
    }
}

#[test]
fn verify_fails_if_verification_point_is_identity() {
    // With r = -z / d, where z is the hash of the message and d the private key, the point u1 G + u2 Q
    // computed by verification is the identity, which has no x-coordinate.
    let kp = keys().pop().unwrap();
    let d = *kp.secret.privkey.as_nonzero_scalar();
    let z = <Scalar as Reduce<U256>>::reduce_bytes(&Sha256::digest(MSG).digest.into());
    let r = -(z * d.invert().unwrap());
    let bytes = Signature::from_scalars(r, Scalar::ONE).unwrap().to_bytes();
    assert!(!p256_verify::<Sha256>(kp.public().as_bytes(), MSG, &bytes));
    let signature = <Secp256r1Signature as ToFromBytes>::from_bytes(&bytes).unwrap();
    assert_eq!(
        kp.public().verify(MSG, &signature),
        Err(FastCryptoError::InvalidSignature)
    );
}

#[test]
fn sign_and_verify_with_small_keys() {
    // The private keys 1, 2, 3, n - 1 and n - 2, whose public keys are small multiples of the
    // generator, which is also the base point of the precomputed table used in verification.
    let small = |k: u8| {
        let mut bytes = [0; SK_LENGTH];
        bytes[SK_LENGTH - 1] = k;
        bytes
    };
    for sk in [
        small(1),
        small(2),
        small(3),
        add_small(&GROUP_ORDER, -1),
        add_small(&GROUP_ORDER, -2),
    ] {
        let kp = Secp256r1KeyPair::from_bytes(&sk).unwrap();
        let expected = p256::ecdsa::SigningKey::from_slice(&sk).unwrap();
        assert_eq!(
            kp.public().as_bytes(),
            expected.verifying_key().to_encoded_point(true).as_bytes()
        );
        for msg in MESSAGES {
            let signature = kp.sign(msg);
            assert_eq!(signature.as_bytes(), p256_sign::<Sha256>(&sk, msg));
            assert!(kp.public().verify(msg, &signature).is_ok());
        }
    }
}

#[test]
fn rfc6979_test_vectors() {
    // RFC 6979, A.2.5: deterministic signatures with P-256 and SHA-256. Signing normalizes s, so it
    // gives the RFC's signature with s replaced by n - s if the RFC's s is high.
    let kp = Secp256r1KeyPair::from_bytes(&RFC6979_PRIVATE_KEY).unwrap();
    assert_eq!(kp.public().as_bytes(), RFC6979_PUBLIC_KEY);
    assert!(is_high_s(&RFC6979_SHA256_SIGNATURES[0].1));
    assert!(!is_high_s(&RFC6979_SHA256_SIGNATURES[1].1));
    for (msg, expected) in RFC6979_SHA256_SIGNATURES {
        let normalized = match is_high_s(&expected) {
            true => negate_s(&expected),
            false => expected.to_vec(),
        };
        assert_eq!(kp.sign(msg).as_bytes(), normalized);

        // The RFC's signature only verifies if its s is low.
        let signature = <Secp256r1Signature as ToFromBytes>::from_bytes(&expected).unwrap();
        assert_eq!(
            kp.public().verify(msg, &signature).is_ok(),
            !is_high_s(&expected)
        );
    }
}

#[test]
fn wycheproof_test_nonrecoverable() {
    // Signatures are not normalized, so the valid signatures with a high s must be rejected. The
    // P1363 suite encodes signatures as r || s, like from_bytes.
    fn verify<H: HashFunction<32>>(pk: &Secp256r1PublicKey, msg: &[u8], signature: &[u8]) -> bool {
        <Secp256r1Signature as ToFromBytes>::from_bytes(signature)
            .is_ok_and(|signature| pk.verify_with_hash::<H>(msg, &signature).is_ok())
    }
    assert_eq!(
        check_wycheproof(
            TestName::EcdsaSecp256r1Sha256,
            false,
            false,
            verify::<Sha256>
        ),
        (103, 71)
    );
    assert_eq!(
        check_wycheproof(
            TestName::EcdsaSecp256r1Sha256P1363,
            true,
            false,
            verify::<Sha256>
        ),
        (103, 70)
    );
    assert_eq!(
        check_wycheproof(
            TestName::EcdsaSecp256r1Sha3_256,
            false,
            false,
            verify::<Sha3_256>
        ),
        (103, 75)
    );
}

#[test]
fn verify_real_passkey_signature() {
    // A passkey signs authenticatorData || SHA-256(clientDataJSON), with SHA-256, and Sui requires
    // the challenge in clientDataJSON to be the digest of the intent message.
    let bytes = Base64::decode(PASSKEY_SIGNATURE).unwrap();
    assert_eq!(bytes[0], SUI_PASSKEY_FLAG);
    let authenticator: PasskeyAuthenticator = bcs::from_bytes(&bytes[1..]).unwrap();
    let user_signature = &authenticator.user_signature;
    assert_eq!(user_signature.len(), 1 + SIG_LENGTH + PK_LENGTH);
    assert_eq!(user_signature[0], SUI_SECP256R1_FLAG);
    let signature =
        <Secp256r1Signature as ToFromBytes>::from_bytes(&user_signature[1..1 + SIG_LENGTH])
            .unwrap();
    let pk = Secp256r1PublicKey::from_bytes(&user_signature[1 + SIG_LENGTH..]).unwrap();

    // The sender is the address of the passkey.
    assert_eq!(sui_address(SUI_PASSKEY_FLAG, &pk), PASSKEY_SENDER);

    // The challenge is the digest of the intent message, in Base64 URL-safe without padding.
    let mut hasher = Blake2b256::new();
    hasher.update(SUI_TRANSACTION_INTENT);
    hasher.update(Base64::decode(PASSKEY_TX_DATA).unwrap());
    let client_data: serde_json::Value =
        serde_json::from_str(&authenticator.client_data_json).unwrap();
    assert_eq!(client_data["type"], "webauthn.get");
    assert_eq!(
        client_data["challenge"],
        base64ct::Base64UrlUnpadded::encode_string(&hasher.finalize().digest)
    );

    let mut msg = authenticator.authenticator_data.clone();
    msg.extend_from_slice(&Sha256::digest(authenticator.client_data_json.as_bytes()).digest);
    assert!(!is_high_s(signature.as_ref()));
    assert!(pk.verify(&msg, &signature).is_ok());
    assert!(p256_verify::<Sha256>(
        pk.as_bytes(),
        &msg,
        signature.as_ref()
    ));

    // Its high-s twin verifies under p256 but not here.
    let high_s = negate_s(signature.as_ref());
    assert!(p256_verify::<Sha256>(pk.as_bytes(), &msg, &high_s));
    let high_s = <Secp256r1Signature as ToFromBytes>::from_bytes(&high_s).unwrap();
    assert!(pk.verify(&msg, &high_s).is_err());
}

#[test]
fn verify_valid_batch() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    let res = Secp256r1PublicKey::verify_batch_empty_fail(&digest[..], &pubkeys, &signatures);
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch() {
    let (digest, pubkeys, mut signatures) = signature_test_inputs();
    // mangle one signature
    signatures.swap(0, 1);

    assert!(Secp256r1PublicKey::verify_batch_empty_fail(&digest, &pubkeys, &signatures).is_err())
}

#[test]
fn verify_empty_batch() {
    let (digest, _, _) = signature_test_inputs();

    let res = Secp256r1PublicKey::verify_batch_empty_fail(&digest[..], &[], &[]);
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_batch_missing_public_keys() {
    let (digest, pubkeys, signatures) = signature_test_inputs();

    // missing leading public keys
    let res = Secp256r1PublicKey::verify_batch_empty_fail(&digest, &pubkeys[1..], &signatures);
    assert!(res.is_err(), "{:?}", res);

    // missing trailing public keys
    let res = Secp256r1PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys[..pubkeys.len() - 1],
        &signatures,
    );
    assert!(res.is_err(), "{:?}", res);

    // missing trailing signatures
    let res = Secp256r1PublicKey::verify_batch_empty_fail(
        &digest,
        &pubkeys,
        &signatures[..signatures.len() - 1],
    );
    assert!(res.is_err(), "{:?}", res);
}

#[test]
fn verify_valid_batch_different_msg() {
    let inputs = test_helpers::signature_test_inputs_different_msg::<Secp256r1KeyPair>();
    let res = Secp256r1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_ok(), "{:?}", res);
}

#[test]
fn verify_invalid_batch_different_msg() {
    let mut inputs = test_helpers::signature_test_inputs_different_msg::<Secp256r1KeyPair>();

    // Empty inputs and length mismatches. All the entries are valid, so ignoring the end of a longer
    // list would accept it.
    let (msgs, pks, sigs) = (&inputs.digests, &inputs.pubkeys, &inputs.signatures);
    for (m, p, s) in iproduct!([0, 2, 3], [0, 2, 3], [0, 2, 3]) {
        assert_eq!(
            Secp256r1PublicKey::verify_batch_empty_fail_different_msg(
                &msgs[..m],
                &pks[..p],
                &sigs[..s]
            ),
            if m == p && p == s && s > 0 {
                Ok(())
            } else {
                Err(FastCryptoError::InvalidInput)
            }
        );
    }

    inputs.signatures.swap(0, 1);
    let res = Secp256r1PublicKey::verify_batch_empty_fail_different_msg(
        &inputs.digests,
        &inputs.pubkeys,
        &inputs.signatures,
    );
    assert!(res.is_err(), "{:?}", res);
}

//
// Other tests
//

#[test]
fn public_key_ordering() {
    // Ord compares the uncompressed encodings, that is x and then y, like p256. This is not the
    // order of the compressed encodings returned by as_bytes, which start with the parity of y. For
    // example, the generator has an odd y, which is smaller than the even y of its negation.
    let generator = Secp256r1PublicKey::from_bytes(&GENERATOR_COMPRESSED).unwrap();
    let mut negated_bytes = GENERATOR_COMPRESSED;
    negated_bytes[0] ^= 1;
    let negated = Secp256r1PublicKey::from_bytes(&negated_bytes).unwrap();
    assert!(generator < negated);
    assert!(generator.as_bytes() > negated.as_bytes());

    // Ord, Eq and Hash agree with each other.
    let mut pks: Vec<_> = keys().iter().map(|kp| kp.public().clone()).collect();
    pks.extend([
        generator,
        negated,
        Secp256r1PublicKey::from_bytes(&X_ZERO_COMPRESSED).unwrap(),
    ]);
    for pk1 in &pks {
        for pk2 in &pks {
            assert_eq!(pk1.cmp(pk2), uncompressed(pk1).cmp(&uncompressed(pk2)));
            assert_eq!(pk1.partial_cmp(pk2), Some(pk1.cmp(pk2)));
            assert_eq!(pk1.cmp(pk2) == Ordering::Equal, pk1 == pk2);
            assert_eq!(pk1 == pk2, pk1.as_bytes() == pk2.as_bytes());
            assert_eq!(pk1 == pk2, hash_of(pk1) == hash_of(pk2));
        }
    }
}

#[test]
fn hash_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();

    let mut hasher = DefaultHasher::new();
    public_key.hash(&mut hasher);
    let digest = hasher.finish();

    let mut other_hasher = DefaultHasher::new();
    public_key.as_bytes().hash(&mut other_hasher);
    let expected = other_hasher.finish();
    assert_eq!(expected, digest);
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
    let sig = keys().pop().unwrap().sign(MSG);
    assert_eq!(sig.to_string(), Base64::encode(sig.as_bytes()));
}

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

    //    digest.into()

    // Verify the signature we received.
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
    assert!(pk.verify(digest.as_ref(), &signature).is_ok());
}

#[test]
fn test_sk_zeroization_on_drop() {
    let ptr: *const u8;
    let bytes_ptr: *const u8;

    let mut sk_bytes = Vec::new();

    {
        let mut rng = StdRng::from_seed([9; 32]);
        let kp = Secp256r1KeyPair::generate(&mut rng);
        let sk = kp.private();
        sk_bytes.extend_from_slice(sk.as_ref());

        ptr = std::ptr::addr_of!(sk.privkey) as *const u8;
        bytes_ptr = &sk.as_ref()[0] as *const u8;

        let sk_memory: &[u8] = unsafe { std::slice::from_raw_parts(bytes_ptr, SECRET_KEY_SIZE) };
        // Assert that this is equal to sk_bytes before deletion
        assert_eq!(sk_memory, &sk_bytes[..]);
    }

    // Check that self.privkey is set to ONE_KEY (workaround to all zero SecretKey considered as invalid)
    unsafe {
        assert_eq!(*ptr, 1);
        for i in 1..SECRET_KEY_SIZE {
            assert_eq!(*ptr.add(i), 0);
        }
    }

    // Check that self.bytes is zeroized
    let sk_memory: &[u8] = unsafe { std::slice::from_raw_parts(bytes_ptr, SECRET_KEY_SIZE) };
    assert_ne!(sk_memory, &sk_bytes[..]);
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for Secp256r1PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for Secp256r1PrivateKey>"
        );
    });
}

//
// Proptests
//

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = Secp256r1KeyPair> {
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Secp256r1KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

/// One of the honest public keys.
fn arb_honest_public_key() -> impl Strategy<Value = Vec<u8>> {
    (0..HONEST_KEYS.len()).prop_map(|i| HONEST_KEYS[i].public().as_bytes().to_vec())
}

/// Public keys: honest keys, the same points in other encodings and with other tags, small and
/// unreduced x-coordinates, random x-coordinates (about half of them are on the curve), bit flips,
/// other lengths and arbitrary bytes.
fn arb_public_key_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        arb_honest_public_key(),
        (arb_honest_public_key(), any::<u8>()).prop_map(|(mut bytes, tag)| {
            bytes[0] = tag;
            bytes
        }),
        (0..HONEST_KEYS.len(), prop_oneof![Just(0x04), any::<u8>()]).prop_map(|(i, tag)| {
            let mut bytes = uncompressed(HONEST_KEYS[i].public());
            bytes[0] = tag;
            bytes
        }),
        prop_oneof![
            Just(GENERATOR_COMPRESSED),
            Just(X_ZERO_COMPRESSED),
            Just(X_ZERO_UNREDUCED),
            Just(X_THREE_COMPRESSED),
        ]
        .prop_map(|bytes| bytes.to_vec()),
        (prop_oneof![Just(0x02), Just(0x03)], any::<[u8; 32]>()).prop_map(|(tag, x)| {
            let mut bytes = vec![tag];
            bytes.extend_from_slice(&x);
            bytes
        }),
        (arb_honest_public_key(), 0..PK_LENGTH * 8).prop_map(|(mut bytes, bit)| {
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        }),
        (arb_honest_public_key(), 0..3 * PK_LENGTH).prop_map(|(mut bytes, len)| {
            bytes.resize(len, 0);
            bytes
        }),
        collection::vec(any::<u8>(), 0..3 * PK_LENGTH),
    ]
}

/// One of the honest signatures, as (key index, message index, signature).
fn arb_honest_signature() -> impl Strategy<Value = (usize, usize, Vec<u8>)> {
    (0..HONEST_KEYS.len(), 0..MESSAGES.len())
        .prop_map(|(i, j)| (i, j, HONEST_SIGNATURES[i][j].clone()))
}

/// Values of r or s: the bounds of [1, n - 1], n / 2 and arbitrary values.
fn arb_scalar_bytes() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![
        Just([0; 32]),
        Just(add_small(&[0; 32], 1)),
        Just(add_small(&GROUP_ORDER, -1)),
        Just(GROUP_ORDER),
        Just(HALF_GROUP_ORDER),
        Just(add_small(&HALF_GROUP_ORDER, 1)),
        Just([0xff; 32]),
        any::<[u8; 32]>(),
    ]
}

/// Signatures with the key and message to verify them with: honest signatures, their high-s
/// twins, signatures for another key or message, r or s replaced, bit flips, other lengths and
/// arbitrary bytes.
fn arb_signature_input() -> impl Strategy<Value = (usize, usize, Vec<u8>)> {
    prop_oneof![
        2 => arb_honest_signature(),
        1 => arb_honest_signature().prop_map(|(i, j, signature)| (i, j, negate_s(&signature))),
        1 => (arb_honest_signature(), 0..HONEST_KEYS.len(), 0..MESSAGES.len())
            .prop_map(|((_, _, signature), i, j)| (i, j, signature)),
        1 => (arb_honest_signature(), prop_oneof![Just(0), Just(32)], arb_scalar_bytes()).prop_map(
            |((i, j, mut signature), offset, value)| {
                signature[offset..offset + 32].copy_from_slice(&value);
                (i, j, signature)
            }
        ),
        1 => (arb_honest_signature(), 0..SIG_LENGTH * 8).prop_map(|((i, j, mut signature), bit)| {
            signature[bit / 8] ^= 1 << (bit % 8);
            (i, j, signature)
        }),
        1 => (arb_honest_signature(), 0..2 * SIG_LENGTH).prop_map(|((i, j, mut signature), len)| {
            signature.resize(len, 0);
            (i, j, signature)
        }),
        1 => (
            0..HONEST_KEYS.len(),
            0..MESSAGES.len(),
            collection::vec(any::<u8>(), SIG_LENGTH)
        ),
    ]
}

/// Private keys: arbitrary 32 bytes (almost all valid), values near 0, n and 2^256 and other
/// lengths.
fn arb_private_key_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        2 => any::<[u8; SK_LENGTH]>().prop_map(|bytes| bytes.to_vec()),
        1 => (
            prop_oneof![Just([0; 32]), Just(GROUP_ORDER), Just([0xff; 32])],
            -3i64..=3
        )
            .prop_map(|(base, delta)| add_small(&base, delta).to_vec()),
        1 => collection::vec(any::<u8>(), 0..2 * SK_LENGTH),
    ]
}

proptest! {
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: Secp256r1KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }

    #[test]
    fn test_decode_adversarial_public_keys(bytes in arb_public_key_bytes()) {
        // from_bytes accepts exactly the encodings that p256 accepts and decodes them to the same
        // point. from_bytes_strict also rejects the compact format.
        let decoded = Secp256r1PublicKey::from_bytes(&bytes);
        let expected = p256::PublicKey::from_sec1_bytes(&bytes);
        prop_assert_eq!(decoded.is_ok(), expected.is_ok());
        prop_assert_eq!(
            Secp256r1PublicKey::from_bytes_strict(&bytes).is_ok(),
            decoded.is_ok() && bytes[0] != 0x05
        );
        let Ok(pk) = decoded else {
            return Ok(());
        };
        let expected = expected.unwrap();
        prop_assert_eq!(pk.pubkey.as_affine(), expected.as_affine());
        if bytes[0] == 0x05 {
            prop_assert!(has_smaller_y(&pk));
        }

        // A key decoded from 33 bytes keeps them, and one decoded from 65 bytes is encoded
        // compressed. Either way, it is equal to, hashes like and compares equal to the key
        // decoded from the compressed encoding.
        let compressed = expected.to_encoded_point(true);
        match bytes.len() {
            PK_LENGTH => prop_assert_eq!(pk.as_bytes(), &bytes[..]),
            _ => prop_assert_eq!(pk.as_bytes(), compressed.as_bytes()),
        }
        let compressed_pk = Secp256r1PublicKey::from_bytes(compressed.as_bytes()).unwrap();
        prop_assert_eq!(&pk, &compressed_pk);
        prop_assert_eq!(hash_of(&pk), hash_of(&compressed_pk));
        prop_assert_eq!(pk.cmp(&compressed_pk), Ordering::Equal);

        // BCS has a fixed length of 33 bytes, while JSON goes through from_bytes.
        prop_assert_eq!(
            bcs::from_bytes::<Secp256r1PublicKey>(&bytes).ok(),
            (bytes.len() == PK_LENGTH).then(|| pk.clone())
        );
        let json = format!("\"{}\"", Base64::encode(&bytes));
        prop_assert_eq!(&serde_json::from_str::<Secp256r1PublicKey>(&json).unwrap(), &pk);
    }

    #[test]
    fn test_decode_and_verify_adversarial_signatures(
        (i, j, bytes) in arb_signature_input()
    ) {
        let pk = HONEST_KEYS[i].public();
        let msg = MESSAGES[j];

        // Decoding accepts exactly the 64-byte r || s with r and s in [1, n - 1], like p256.
        let decoded = <Secp256r1Signature as ToFromBytes>::from_bytes(&bytes);
        prop_assert_eq!(
            decoded.is_ok(),
            bytes.len() == SIG_LENGTH && Signature::from_slice(&bytes).is_ok()
        );
        let Ok(signature) = decoded else {
            return Ok(());
        };
        prop_assert_eq!(signature.as_bytes(), &bytes[..]);
        let bcs_bytes = bcs::to_bytes(&signature).unwrap();
        prop_assert_eq!(&bcs::from_bytes::<Secp256r1Signature>(&bcs_bytes).unwrap(), &signature);

        // Verification is ECDSA verification, as in p256, restricted to a low s.
        let verified = pk.verify(msg, &signature).is_ok();
        prop_assert_eq!(
            verified,
            p256_verify::<Sha256>(pk.as_bytes(), msg, &bytes) && !is_high_s(&bytes)
        );

        // The inputs never sign with the honest keys, so only the honest signature verifies.
        if verified {
            prop_assert_eq!(&bytes, &HONEST_SIGNATURES[i][j]);
        }
    }

    #[test]
    fn test_decode_adversarial_private_keys(bytes in arb_private_key_bytes()) {
        // Exactly 32 bytes encoding a value in [1, n - 1] are accepted.
        let decoded = Secp256r1PrivateKey::from_bytes(&bytes);
        let valid = bytes.len() == SK_LENGTH
            && bytes[..] != [0; SK_LENGTH]
            && bytes[..] < GROUP_ORDER[..];
        prop_assert_eq!(decoded.is_ok(), valid);
        prop_assert_eq!(Secp256r1KeyPair::from_bytes(&bytes).is_ok(), valid);
        let Ok(sk) = decoded else {
            return Ok(());
        };
        prop_assert_eq!(sk.as_bytes(), &bytes[..]);

        // The public key and the signatures are those of p256, and decoding a key pair derives
        // the same public key.
        let kp = Secp256r1KeyPair::from(sk);
        let expected = p256::ecdsa::SigningKey::from_slice(&bytes).unwrap();
        let expected_pk = expected.verifying_key().to_encoded_point(true);
        prop_assert_eq!(kp.public().as_bytes(), expected_pk.as_bytes());
        let signature = kp.sign(MSG);
        prop_assert_eq!(signature.as_bytes(), &p256_sign::<Sha256>(&bytes, MSG)[..]);
        prop_assert_eq!(&Secp256r1KeyPair::from_bytes(&bytes).unwrap(), &kp);
    }
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // A good part of the adversarial inputs above decode, and some signatures verify.
    const SAMPLES: usize = 500;
    let mut runner = TestRunner::deterministic();
    let mut sample = |strategy: &dyn Fn(&mut TestRunner) -> bool| {
        (0..SAMPLES).filter(|_| strategy(&mut runner)).count()
    };
    let public_keys = sample(&|runner| {
        let bytes = arb_public_key_bytes().new_tree(runner).unwrap().current();
        Secp256r1PublicKey::from_bytes(&bytes).is_ok()
    });
    let signatures = sample(&|runner| {
        let (_, _, bytes) = arb_signature_input().new_tree(runner).unwrap().current();
        <Secp256r1Signature as ToFromBytes>::from_bytes(&bytes).is_ok()
    });
    let verified = sample(&|runner| {
        let (i, j, bytes) = arb_signature_input().new_tree(runner).unwrap().current();
        <Secp256r1Signature as ToFromBytes>::from_bytes(&bytes).is_ok_and(|signature| {
            HONEST_KEYS[i]
                .public()
                .verify(MESSAGES[j], &signature)
                .is_ok()
        })
    });
    let private_keys = sample(&|runner| {
        let bytes = arb_private_key_bytes().new_tree(runner).unwrap().current();
        Secp256r1PrivateKey::from_bytes(&bytes).is_ok()
    });
    println!("public keys {public_keys}, signatures {signatures}, verified {verified}, private keys {private_keys}");
    assert!(public_keys > SAMPLES / 4, "{public_keys}");
    assert!(signatures > SAMPLES / 2, "{signatures}");
    assert!(verified > SAMPLES / 10, "{verified}");
    assert!(private_keys > SAMPLES / 2, "{private_keys}");
}
