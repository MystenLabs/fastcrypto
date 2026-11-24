// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the fastcrypto trait layer over ML-DSA-65: decoding, serialization, key handling, the
//! empty context and the error mapping. FIPS 204 itself (signature encoding, norm and hint bounds,
//! byte-exact signing, agreement of the portable and assembly backends) is tested in
//! mysten-mldsa-native-rs.

use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use mysten_mldsa_native_rs as mldsa;
use once_cell::sync::Lazy;
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng as _};
use serde::de::DeserializeOwned;
use serde::Serialize;

use fastcrypto::encoding::{Base64, Encoding, Hex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::{HashFunction, Sha256};
use fastcrypto::slip10::{derive_hardened, Slip10MasterKey, MAX_SEED_LENGTH, MIN_SEED_LENGTH};
use fastcrypto::traits::{
    EncodeDecodeBase64, InsecureDefault, KeyPair, Signer, ToFromBytes, VerifyingKey,
};

use crate::mldsa65::{
    MLDSA65KeyPair, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA65PublicKeyAsBytes, MLDSA65Signature,
    MLDSA65SignatureAsBytes, MLDSA65_KEYPAIR_LENGTH, MLDSA65_PRIVATE_KEY_LENGTH,
    MLDSA65_PUBLIC_KEY_LENGTH, MLDSA65_SIGNATURE_LENGTH,
};
use crate::slip10::derive_mldsa65_keypair;

//
// Helper functions
//

const MSG: &[u8] = b"Hello, world!";

const SK_LENGTH: usize = MLDSA65_PRIVATE_KEY_LENGTH;
const PK_LENGTH: usize = MLDSA65_PUBLIC_KEY_LENGTH;
const SIG_LENGTH: usize = MLDSA65_SIGNATURE_LENGTH;

/// A case of the cross-stack interop vectors, produced by the ts wallet stack
/// (`@noble/post-quantum` 0.6.1).
#[derive(serde::Deserialize)]
struct TsCase {
    name: String,
    #[serde(deserialize_with = "hex_bytes")]
    seed: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    ctx: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    rnd: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    pk: Vec<u8>,
    #[serde(deserialize_with = "hex_bytes")]
    sig: Vec<u8>,
}

static TS_CASES: Lazy<Vec<TsCase>> = Lazy::new(|| {
    #[derive(serde::Deserialize)]
    struct Vectors {
        scheme: String,
        producer: String,
        cases: Vec<TsCase>,
    }
    let vectors: Vectors = serde_json::from_str(include_str!("ts_interop_vectors.json")).unwrap();
    assert_eq!(vectors.scheme, "ML-DSA-65");
    assert_eq!(vectors.producer, "@noble/post-quantum");
    assert_eq!(vectors.cases.len(), 5, "the vector file changed shape");
    vectors.cases
});

fn hex_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = <String as serde::Deserialize>::deserialize(deserializer)?;
    Hex::decode(&s).map_err(serde::de::Error::custom)
}

fn keys() -> Vec<MLDSA65KeyPair> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    (0..4).map(|_| MLDSA65KeyPair::generate(&mut rng)).collect()
}

/// A key pair from a fixed seed
fn keypair_from_seed(byte: u8) -> MLDSA65KeyPair {
    MLDSA65KeyPair::from_bytes(&[byte; SK_LENGTH]).unwrap()
}

fn json(bytes: &[u8]) -> String {
    format!("\"{}\"", Base64::encode(bytes))
}

fn hash(value: &impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Mirrors `fastcrypto::tests::test_helpers::verify_serialization`. The binary formats are the raw
/// bytes and JSON is their base64 form.
fn verify_serialization<T>(obj: &T, expected: &[u8])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    assert_eq!(bincode::serialize(obj).unwrap(), expected);
    assert_eq!(*obj, bincode::deserialize(expected).unwrap());
    assert_eq!(bcs::to_bytes(obj).unwrap(), expected);
    assert_eq!(*obj, bcs::from_bytes(expected).unwrap());
    assert_eq!(serde_json::to_string(obj).unwrap(), json(expected));
    assert_eq!(*obj, serde_json::from_str(&json(expected)).unwrap());
}

/// Every way to decode `T` accepts `bytes` if and only if there are `N` of them, and keeps them.
fn check_decoding<T, const N: usize>(bytes: &[u8])
where
    T: ToFromBytes + Serialize + DeserializeOwned + PartialEq + Debug,
{
    let from_bytes = T::from_bytes(bytes);
    let from_base64 = T::decode_base64(&Base64::encode(bytes));
    let from_bcs = bcs::from_bytes::<T>(bytes);
    let from_json = serde_json::from_str::<T>(&json(bytes));
    if bytes.len() == N {
        let decoded = from_bytes.unwrap();
        assert_eq!(decoded.as_ref(), bytes);
        assert_eq!(decoded, from_base64.unwrap());
        assert_eq!(decoded, from_bcs.unwrap());
        assert_eq!(decoded, from_json.unwrap());
        verify_serialization(&decoded, bytes);
    } else {
        assert_eq!(from_bytes.unwrap_err(), FastCryptoError::InvalidInput);
        assert!(from_base64.is_err());
        assert!(from_bcs.is_err());
        assert!(from_json.is_err());
    }
}

/// [check_decoding] for all types, including the `*AsBytes` ones.
fn check_decoding_all(bytes: &[u8]) {
    check_decoding::<MLDSA65PrivateKey, SK_LENGTH>(bytes);
    check_decoding::<MLDSA65KeyPair, SK_LENGTH>(bytes);
    check_decoding::<MLDSA65PublicKey, PK_LENGTH>(bytes);
    check_decoding::<MLDSA65Signature, SIG_LENGTH>(bytes);

    let pk = bcs::from_bytes::<MLDSA65PublicKeyAsBytes>(bytes);
    let pk_json = serde_json::from_str::<MLDSA65PublicKeyAsBytes>(&json(bytes));
    assert_eq!(pk.is_ok(), bytes.len() == PK_LENGTH);
    assert_eq!(pk.clone().ok(), pk_json.ok());
    if let Ok(pk) = pk {
        verify_serialization(&pk, bytes);
        let decoded = MLDSA65PublicKey::try_from(&pk).unwrap();
        assert_eq!(decoded.as_ref(), bytes);
        assert_eq!(MLDSA65PublicKeyAsBytes::from(&decoded), pk);
    }

    let sig = bcs::from_bytes::<MLDSA65SignatureAsBytes>(bytes);
    let sig_json = serde_json::from_str::<MLDSA65SignatureAsBytes>(&json(bytes));
    assert_eq!(sig.is_ok(), bytes.len() == SIG_LENGTH);
    assert_eq!(sig.clone().ok(), sig_json.ok());
    if let Ok(sig) = sig {
        verify_serialization(&sig, bytes);
        let decoded = MLDSA65Signature::try_from(&sig).unwrap();
        assert_eq!(decoded.as_ref(), bytes);
        assert_eq!(MLDSA65SignatureAsBytes::from(&decoded), sig);
    }
}

/// The result of verifying raw bytes.
fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), FastCryptoError> {
    MLDSA65PublicKey::from_bytes(pk)?.verify(msg, &MLDSA65Signature::from_bytes(sig)?)
}

//
// Serialization tests
//

#[test]
fn lengths_match_the_scheme() {
    assert_eq!(MLDSA65_PRIVATE_KEY_LENGTH, 32);
    assert_eq!(MLDSA65_KEYPAIR_LENGTH, 32);
    assert_eq!(MLDSA65_PUBLIC_KEY_LENGTH, 1952);
    assert_eq!(MLDSA65_SIGNATURE_LENGTH, 3309);
}

#[test]
fn decoding_accepts_exactly_one_length() {
    for len in [SK_LENGTH, PK_LENGTH, SIG_LENGTH] {
        for len in [0, len - 1, len, len + 1, 2 * len] {
            // All values of the right length are accepted, also when they aren't valid encodings of
            // a signature: those are only rejected by verify.
            check_decoding_all(&vec![0; len]);
            check_decoding_all(&vec![0xff; len]);
        }
    }

    // The encodings of a public key and a signature don't decode as one, in either order.
    let keypair = keypair_from_seed(1);
    let sig = keypair.sign(MSG);
    check_decoding_all(&[keypair.public().as_ref(), sig.as_ref()].concat());
    check_decoding_all(&[sig.as_ref(), keypair.public().as_ref()].concat());
}

#[test]
fn base64_is_strict() {
    // The last two bytes are encoded as "+/s=", where the lowest two bits of "s" are unused.
    let encoded = Base64::encode([0xfb; PK_LENGTH]);
    let public = MLDSA65PublicKey::decode_base64(&encoded).unwrap();
    assert_eq!(public.as_ref(), [0xfb; PK_LENGTH]);
    assert_eq!(public.encode_base64(), encoded);

    let without_end = encoded.strip_suffix("s=").unwrap();
    for invalid in [
        "not base64!".to_string(),
        format!("{without_end}s"),
        format!("{without_end}t="),
        format!("{encoded}="),
        format!("{encoded}\n"),
        format!(" {encoded}"),
        encoded.replace('+', "-"),
        encoded.replace('/', "_"),
    ] {
        assert!(MLDSA65PublicKey::decode_base64(&invalid).is_err());
        assert!(serde_json::from_value::<MLDSA65PublicKey>(invalid.into()).is_err());
    }
}

#[test]
fn public_key_ordering_and_hashing_follow_the_bytes() {
    let mut keypairs = keys();
    keypairs.sort_by(|a, b| a.public().as_ref().cmp(b.public().as_ref()));
    let sorted: BTreeSet<_> = keypairs.iter().map(|kp| kp.public().clone()).collect();
    assert!(sorted.iter().eq(keypairs.iter().map(|kp| kp.public())));

    // Keys that differ only in the last byte
    let pk = MLDSA65PublicKey::from_bytes(&[0; PK_LENGTH]).unwrap();
    let mut bytes = [0; PK_LENGTH];
    bytes[PK_LENGTH - 1] = 1;
    let next = MLDSA65PublicKey::from_bytes(&bytes).unwrap();
    assert!(pk < next);
    assert_ne!(pk, next);
    assert_ne!(hash(&pk), hash(&next));
    assert_eq!(
        hash(&pk),
        hash(&MLDSA65PublicKey::from_bytes(pk.as_ref()).unwrap())
    );
}

#[test]
fn debug_output_is_redacted_for_secrets() {
    let keypair = keys().pop().unwrap();
    let signature = keypair.sign(MSG);
    let secret = Base64::encode(keypair.as_ref());

    // Public types print their base64 form, which assertion failures rely on.
    let public = Base64::encode(keypair.public().as_ref());
    assert_eq!(format!("{:?}", keypair.public()), public);
    assert_eq!(format!("{}", keypair.public()), public);
    assert_eq!(format!("{signature:?}"), Base64::encode(signature.as_ref()));
    assert_eq!(format!("{signature}"), Base64::encode(signature.as_ref()));

    // Secret material must never appear in formatted output.
    assert!(!format!("{keypair:?}").contains(&secret));
    let private = keypair.private();
    assert!(!format!("{private:?}").contains(&secret));
    assert!(!format!("{private}").contains(&secret));
}

//
// Key tests
//

#[test]
fn generate_is_random() {
    let generated: BTreeSet<_> = keys().iter().map(|kp| kp.public().clone()).collect();
    assert_eq!(generated.len(), keys().len());
}

/// The private key is the 32-byte FIPS 204 seed and the public key is always derived from it: the
/// same recovery phrase must yield the same account everywhere.
#[test]
fn key_pairs_are_determined_by_the_seed() {
    let seed = [7u8; SK_LENGTH];
    let keypair = MLDSA65KeyPair::from_bytes(&seed).unwrap();
    let private = MLDSA65PrivateKey::from_bytes(&seed).unwrap();
    assert_eq!(private.as_ref(), &seed);
    assert_eq!(&MLDSA65PublicKey::from(&private), keypair.public());

    for other in [
        keypair.copy(),
        MLDSA65KeyPair::from(private),
        MLDSA65KeyPair::from_str(&keypair.encode_base64()).unwrap(),
        bcs::from_bytes(&bcs::to_bytes(&keypair).unwrap()).unwrap(),
        serde_json::from_str(&serde_json::to_string(&keypair).unwrap()).unwrap(),
        // A private key that has already been used to sign
        {
            let used = keypair.copy();
            used.sign(MSG);
            used.private().into()
        },
    ] {
        assert_eq!(other, keypair);
        assert_eq!(other.as_ref(), &seed);
        assert_eq!(keypair.public().verify(MSG, &other.sign(MSG)), Ok(()));
        assert_eq!(
            other.private(),
            MLDSA65PrivateKey::from_bytes(&seed).unwrap()
        );
    }

    assert_ne!(keypair, keypair_from_seed(8));
    assert_ne!(keypair.private(), keypair_from_seed(8).private());
}

/// The ML-DSA-65 vectors from satoshilabs/slips#1968: chain codes pin the
/// HMAC walk, and the public-key digests pin FIPS 204 key expansion.
#[test]
fn slip10_slips1968_vectors() {
    const SEED_1: &str = "000102030405060708090a0b0c0d0e0f";
    const SEED_2: &str = concat!(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2",
        "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    );
    #[rustfmt::skip]
    const VECTORS: &[(&str, &[u32], &str, &str)] = &[
        (SEED_1, &[],
         "7e74b6275f92cc4fb2cbdac0c63cb5e7ac2bce1ded2b7dbc7bf2232f772578d5",
         "f41b8366cd9b720dbab9dfcefde673e4c19798192d7543f30f277e57e77ba457"),
        (SEED_1, &[0],
         "d8b27c87ec212d6501629199262a9d0d66ec26deab313c26a474bc4ddd5dce7c",
         "1d9d7fce0a1560acef9b117f3e3022cb0bdd46f30a3134db33165baf66b53e7e"),
        (SEED_1, &[0, 1],
         "60219beef857bd0bc7870424c4f60464decb097a18ae37b035df22ebaa7515b9",
         "0fdc416cbe544a493b59ae8112a907d5acf09ed4583eb8e12d6c769bcf394943"),
        (SEED_1, &[0, 1, 2],
         "dc7b0e1379b3f1acd02d1e25f13d8bb16830ca68c73b00d900b9030a41d6a658",
         "6db4146987c59099709622700d66bcb07b8d49e1007ea6570e15fc3f6dac1c53"),
        (SEED_1, &[0, 1, 2, 2],
         "565cb34027c3b54773f7f48e329bc86db7ffc6f618b112af6d59a3f82501e17a",
         "d487dcf16e74ddd731fafe780d0e5e8b8d338d4f7a3b7e209f8b4c519419764d"),
        (SEED_1, &[0, 1, 2, 2, 1000000000],
         "dc65d6cf4fa993c2f04fae2b41d70d8c5ba4c9d2042ea5720bf42a2315a6b7db",
         "9591ff122a7eff9cd64100f2123e678db9c257815ec5570b0b6acd8847e62f24"),
        (SEED_2, &[],
         "0e696f43f0e71c1c9febf61f43f10903385b78cee5871915472027b25ba755cc",
         "36233a01384e7081becf4da903d10fe7d357da9061cbed1983819fe0a0ced509"),
        (SEED_2, &[0],
         "d977be3c8525364e155764ef76b985126d8f6be41b55e6e50a9915ae29f27a56",
         "577dc77b0987d6cc587a88605590b183f3a7580577dab08cac1ede0a9636b882"),
        (SEED_2, &[0, 2147483647],
         "45406bac7fc36390d89ac938bff6ca1ebf9fc6da2057d1580b26a8f2e25a0d2f",
         "a0155112060496906db18bd46cdd7e18dd35e6e14621083300a0027fd6a421a2"),
        (SEED_2, &[0, 2147483647, 1],
         "10ffddec3c4acf719afe528b1ced03e0f7d8555999c11b69376bd5ff4e04dbea",
         "41357d47d1269fe94f9fc66396d7dc768e5bcaae700a0b877471a06ef2e12d27"),
        (SEED_2, &[0, 2147483647, 1, 2147483646],
         "3580d842e9d8d6a072b77d95e08b0a87648edfaec9bc25cee6c9127d1aa4a679",
         "e947963f404e03be513bdccf23c5a3cb9bd4455f306276fcd9acd4b0d3e16e75"),
        (SEED_2, &[0, 2147483647, 1, 2147483646, 2],
         "55a202d3f7803dd79e31c454e65eb7da49dee824b467bfed5204df980e71571d",
         "4b6c9f1dd1a811fe704c1355e32c43b63007317868ed6c3fce385f11c1b5da39"),
    ];
    for (seed_hex, indexes, want_cc, want_pk_digest) in VECTORS {
        let seed = Hex::decode(seed_hex).unwrap();
        let node = derive_hardened(Slip10MasterKey::MlDsa65, &seed, indexes).unwrap();
        assert_eq!(
            Hex::encode(node.chain_code),
            *want_cc,
            "chain code, path {indexes:?}"
        );

        let kp = derive_mldsa65_keypair(&seed, indexes).unwrap();
        let digest = Sha256::digest(kp.public().as_ref());
        assert_eq!(
            kp.private().as_ref(),
            node.secret,
            "keypair uses the node secret"
        );
        assert_eq!(
            Hex::encode(digest),
            *want_pk_digest,
            "pk digest, path {indexes:?}"
        );
    }

    // Seeds outside the SLIP-0010 range are rejected.
    for (seed_length, expected) in [
        (0, FastCryptoError::InputTooShort(MIN_SEED_LENGTH)),
        (15, FastCryptoError::InputTooShort(MIN_SEED_LENGTH)),
        (65, FastCryptoError::InputTooLong(MAX_SEED_LENGTH)),
    ] {
        assert_eq!(
            derive_mldsa65_keypair(&vec![1; seed_length], &[0]).unwrap_err(),
            expected
        );
    }
}

//
// Signature verification tests
//

#[test]
fn signing_is_hedged() {
    // Signing draws fresh randomness per call (the FIPS 204 default), so two signatures over
    // the same message differ while both verify.
    let keypair = keys().pop().unwrap();
    let first = keypair.sign(MSG);
    let second = keypair.sign(MSG);
    assert_ne!(first, second);
    assert_eq!(keypair.public().verify(MSG, &first), Ok(()));
    assert_eq!(keypair.public().verify(MSG, &second), Ok(()));
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
fn insecure_default_is_all_zeros() {
    let default = MLDSA65PublicKey::insecure_default();
    assert_eq!(default.as_ref(), &[0u8; PK_LENGTH]);
    assert_eq!(
        default.verify(MSG, &keypair_from_seed(1).sign(MSG)),
        Err(FastCryptoError::InvalidSignature)
    );
}

#[test]
fn matches_typescript_interop_vectors() {
    for case in TS_CASES.iter() {
        // Same seed, same account, on both stacks.
        let private = MLDSA65PrivateKey::from_bytes(&case.seed).unwrap();
        let public = MLDSA65PublicKey::from(&private);
        assert_eq!(public.as_ref(), case.pk, "{}: seed->pk diverged", case.name);
        verify_serialization(&public, &case.pk);

        // Fixed rnd makes signing deterministic: the wrapper must reproduce the
        // ts-produced signature exactly.
        let (wrapper_key, wrapper_public) = mldsa::SigningKeySeed::from_bytes(&case.seed)
            .unwrap()
            .expand();
        let rnd = case.rnd.as_slice().try_into().unwrap();
        let ours = wrapper_key.sign(&case.msg, &case.ctx, rnd).unwrap();
        assert_eq!(
            ours.as_bytes()[..],
            case.sig,
            "{}: signature bytes diverged",
            case.name
        );
        assert_eq!(wrapper_public.verify(&case.msg, &case.ctx, &ours), Ok(()));

        // The trait layer only accepts signatures with the empty context.
        let parsed = MLDSA65Signature::from_bytes(&case.sig).unwrap();
        let expected = if case.ctx.is_empty() {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidSignature)
        };
        assert_eq!(public.verify(&case.msg, &parsed), expected, "{}", case.name);
        verify_serialization(&parsed, &case.sig);
    }
}

/// Wycheproof's ML-DSA-65 verify set through the trait layer, which fixes the context to
/// empty: a case verifies here only if it is valid and carries no context. The wrapper
/// crate runs the same set with explicit contexts; this checks the fastcrypto parsing and
/// error mapping on top of it.
#[test]
fn wycheproof_verify_vectors() {
    use wycheproof::mldsa_verify::{TestName, TestSet};
    use wycheproof::TestResult;

    let set = TestSet::load(TestName::MlDsa65Verify).unwrap();
    assert_eq!(set.number_of_tests, 210, "the vector set changed shape");
    let mut accepted = 0;

    for group in &set.test_groups {
        let Ok(public) = MLDSA65PublicKey::from_bytes(&group.pubkey) else {
            // Only wrong-length keys may fail to parse, and every case under them is invalid.
            assert_ne!(group.pubkey.len(), MLDSA65_PUBLIC_KEY_LENGTH);
            assert!(group.tests.iter().all(|t| t.result == TestResult::Invalid));
            continue;
        };
        for t in &group.tests {
            let label = format!("tc {} ({})", t.tc_id, t.comment);
            let Ok(sig) = MLDSA65Signature::from_bytes(&t.sig) else {
                assert_ne!(t.sig.len(), MLDSA65_SIGNATURE_LENGTH, "{label}: parse");
                assert_eq!(t.result, TestResult::Invalid, "{label}: parse");
                continue;
            };
            let no_ctx = t.ctx.as_ref().is_none_or(|c| c.is_empty());
            let expect_ok = t.result == TestResult::Valid && no_ctx;
            let got = public.verify(&t.msg, &sig);
            assert_eq!(got.is_ok(), expect_ok, "{label}: {:?} -> {got:?}", t.flags);
            if !expect_ok {
                assert_eq!(got, Err(FastCryptoError::InvalidSignature), "{label}");
            }
            accepted += usize::from(expect_ok);
        }
    }
    assert_eq!(
        accepted, 77,
        "valid empty-context cases changed; re-check the set"
    );
}

/// Wycheproof's ML-DSA-65 sign-from-seed set: the seed is the private key here, so every
/// group checks seed -> public key, and every valid empty-context signature verifies.
/// Byte-exact signing is covered in the wrapper crate, which takes the vector's rnd.
#[test]
fn wycheproof_sign_seed_vectors() {
    use wycheproof::mldsa_sign::{TestName, TestSet};
    use wycheproof::TestResult;

    let set = TestSet::load(TestName::MlDsa65SignSeed).unwrap();
    assert_eq!(set.number_of_tests, 105, "the vector set changed shape");
    let (mut keys, mut verified) = (0, 0);

    for group in &set.test_groups {
        let seed = group.privseed.as_ref().expect("seed set");
        let Ok(private) = MLDSA65PrivateKey::from_bytes(seed) else {
            assert_ne!(seed.len(), MLDSA65_PRIVATE_KEY_LENGTH);
            assert!(group.tests.iter().all(|t| t.result == TestResult::Invalid));
            continue;
        };
        let public = MLDSA65PublicKey::from(&private);
        assert_eq!(
            public.as_ref(),
            &group.pubkey.as_ref().expect("seed set")[..]
        );
        keys += 1;

        for t in &group.tests {
            // Skip mu-only (`Internal`) cases and anything signed under a context.
            let (Some(msg), true) = (&t.msg, t.ctx.as_ref().is_none_or(|c| c.is_empty())) else {
                continue;
            };
            if t.result != TestResult::Valid {
                continue;
            }
            let sig = MLDSA65Signature::from_bytes(&t.sig).unwrap();
            assert!(
                public.verify(msg, &sig).is_ok(),
                "tc {} ({}): vector signature rejected",
                t.tc_id,
                t.comment
            );
            verified += 1;
        }
    }
    assert_eq!((keys, verified), (39, 81), "the vector set changed shape");
}

//
// Proptests
//

/// A valid public key, message and signature with the empty context: the message has 32 bytes, like
/// the digests that Sui signs.
static VALID: Lazy<&TsCase> = Lazy::new(|| {
    let case = TS_CASES.iter().find(|c| c.name == "digest-msg").unwrap();
    assert!(case.ctx.is_empty());
    case
});

/// The start of the hints in a signature.
const HINTS: usize = 3248;

/// The start of each part of a public key, a 32-byte message and a signature, concatenated. The parts
/// of a signature are the commitment hash, z, the hint positions and the hint counts.
const PARTS: [usize; 7] = [
    0,
    MSG_OFFSET,
    SIG_OFFSET,
    SIG_OFFSET + 48,
    SIG_OFFSET + HINTS,
    SIG_OFFSET + 3303,
    SIG_OFFSET + SIG_LENGTH,
];
const MSG_OFFSET: usize = PK_LENGTH;
const SIG_OFFSET: usize = MSG_OFFSET + 32;

/// Arbitrary bytes, most of the time with a length that one of the types accepts or that is off by
/// one.
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    let near = (
        prop::sample::select(vec![SK_LENGTH, PK_LENGTH, SIG_LENGTH]),
        0..4usize,
    )
        .prop_map(|(len, i)| [len, len, len - 1, len + 1][i]);
    let len = prop_oneof![4 => near, 1 => 0..2 * SIG_LENGTH];
    (len, any::<u64>()).prop_map(|(len, seed)| {
        let mut bytes = vec![0; len];
        StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
        bytes
    })
}

/// A change to a byte string.
#[derive(Clone, Debug)]
enum Edit {
    FlipBit(usize, u8),
    SetByte(usize, u8),
    Swap(usize, usize),
    Fill(usize, usize, u8),
}

impl Edit {
    fn apply(&self, bytes: &mut [u8]) {
        match *self {
            Edit::FlipBit(i, bit) => bytes[i] ^= 1 << bit,
            Edit::SetByte(i, value) => bytes[i] = value,
            Edit::Swap(i, j) => bytes.swap(i, j),
            Edit::Fill(i, j, value) => bytes[i.min(j)..=i.max(j)].fill(value),
        }
    }
}

/// Byte values, with a higher chance for the extreme ones and for small ones.
fn arb_byte() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0), Just(0xff), 0..64u8, any::<u8>()]
}

/// An edit of the bytes in `start..end`.
fn arb_edit(start: usize, end: usize) -> impl Strategy<Value = Edit> {
    prop_oneof![
        (start..end, 0..8u8).prop_map(|(i, bit)| Edit::FlipBit(i, bit)),
        (start..end, arb_byte()).prop_map(|(i, value)| Edit::SetByte(i, value)),
        (start..end, start..end).prop_map(|(i, j)| Edit::Swap(i, j)),
        (start..end, start..end, arb_byte()).prop_map(|(i, j, value)| Edit::Fill(i, j, value)),
    ]
}

/// An edit of one of the [PARTS].
fn arb_part_edit() -> impl Strategy<Value = Edit> {
    prop::sample::select(PARTS.windows(2).collect::<Vec<_>>())
        .prop_flat_map(|part| arb_edit(part[0], part[1]))
}

proptest! {
    #[test]
    fn decoding_agrees_on_arbitrary_bytes(bytes in arb_bytes()) {
        check_decoding_all(&bytes);
    }

    /// Nobody can turn a signature into another one, or into one for another message or public key.
    #[test]
    fn verify_accepts_only_the_original(edits in prop::collection::vec(arb_part_edit(), 1..4)) {
        let valid = [VALID.pk.as_slice(), &VALID.msg, &VALID.sig].concat();
        let mut edited = valid.clone();
        edits.iter().for_each(|edit| edit.apply(&mut edited));

        let expected = if edited == valid {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidSignature)
        };
        let (pk, rest) = edited.split_at(MSG_OFFSET);
        let (msg, sig) = rest.split_at(SIG_OFFSET - MSG_OFFSET);
        prop_assert_eq!(verify(pk, msg, sig), expected);
    }

    /// Verification never panics, for any public key, message and signature. Without valid hints, a
    /// signature is rejected before it is hashed.
    #[test]
    fn verify_rejects_arbitrary_bytes(
        seed in any::<u64>(),
        msg in prop::collection::vec(any::<u8>(), 0..100),
        valid_hints in any::<bool>(),
        edits in prop::collection::vec(arb_edit(0, SIG_LENGTH), 0..4),
    ) {
        let (mut pk, mut sig) = (vec![0; PK_LENGTH], vec![0; SIG_LENGTH]);
        let mut rng = StdRng::seed_from_u64(seed);
        rng.fill_bytes(&mut pk);
        rng.fill_bytes(&mut sig);
        if valid_hints {
            sig[HINTS..].copy_from_slice(&VALID.sig[HINTS..]);
        }
        edits.iter().for_each(|edit| edit.apply(&mut sig));
        prop_assert_eq!(verify(&pk, &msg, &sig), Err(FastCryptoError::InvalidSignature));
    }

    #[test]
    fn any_seed_is_a_private_key(
        seed in any::<[u8; SK_LENGTH]>(),
        msg in prop::collection::vec(any::<u8>(), 0..100),
        other_msg in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        let keypair = MLDSA65KeyPair::from_bytes(&seed).unwrap();
        let private = MLDSA65PrivateKey::from_bytes(&seed).unwrap();
        prop_assert_eq!(&MLDSA65PublicKey::from(&private), keypair.public());

        let signature = keypair.sign(&msg);
        prop_assert_eq!(keypair.public().verify(&msg, &signature), Ok(()));
        if msg != other_msg {
            prop_assert_eq!(
                keypair.public().verify(&other_msg, &signature),
                Err(FastCryptoError::InvalidSignature)
            );
        }
    }
}
