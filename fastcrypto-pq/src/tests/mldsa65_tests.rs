// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests for the fastcrypto trait layer over ML-DSA-65.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use rand::rngs::StdRng;
use rand::SeedableRng as _;

use fastcrypto::encoding::{Base64, Encoding, Hex};
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

/// A key pair from a fixed seed
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
    // the same message differ while both verify. Deterministic signing does not guarantee signature uniqueness.
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
    // seed to key expansion. The core idea is: wallets store the seed, and
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
    // Deserializing a keypair always re-derives the public key rather than trusting bytes
    // on the wire
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

    // The secret side serializes as the 32-byte seed
    let private = keypair.copy().private();
    verify_serialization(&private, Some(private.as_ref()));
    let kp_bytes = bincode::serialize(&keypair).unwrap();
    assert_eq!(kp_bytes, keypair.as_ref());
    let restored: MLDSA65KeyPair = bincode::deserialize(&kp_bytes).unwrap();
    assert_eq!(restored.public(), keypair.public());
    assert_eq!(restored.as_ref(), keypair.as_ref());
}

/// Mirrors `fastcrypto::tests::test_helpers::verify_serialization`
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

/// Cross-stack interop vectors, produced by the ts wallet stack (`@noble/post-quantum` 0.6.1)
#[test]
fn matches_typescript_interop_vectors() {
    use mysten_mldsa_native_rs as mldsa;

    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        seed: String,
        msg: String,
        ctx: String,
        rnd: String,
        pk: String,
        sig: String,
    }
    #[derive(serde::Deserialize)]
    struct Vectors {
        scheme: String,
        producer: String,
        cases: Vec<Case>,
    }

    let vectors: Vectors = serde_json::from_str(include_str!("ts_interop_vectors.json")).unwrap();
    assert_eq!(vectors.scheme, "ML-DSA-65");
    assert_eq!(vectors.producer, "@noble/post-quantum");
    assert_eq!(vectors.cases.len(), 5, "the vector file changed shape");

    for case in &vectors.cases {
        let seed = Hex::decode(&case.seed).unwrap();
        let msg = Hex::decode(&case.msg).unwrap();
        let ctx = Hex::decode(&case.ctx).unwrap();
        let rnd: [u8; 32] = Hex::decode(&case.rnd).unwrap().try_into().unwrap();
        let pk = Hex::decode(&case.pk).unwrap();
        let sig = Hex::decode(&case.sig).unwrap();

        // Same seed, same account, on both stacks.
        let private = MLDSA65PrivateKey::from_bytes(&seed).unwrap();
        let public = MLDSA65PublicKey::from(&private);
        assert_eq!(public.as_ref(), &pk[..], "{}: seed->pk diverged", case.name);

        // Fixed rnd makes signing deterministic: the wrapper must reproduce the
        // ts-produced signature exactly.
        let (wrapper_key, wrapper_public) =
            mldsa::SigningKeySeed::from_bytes(&seed).unwrap().expand();
        let ours = wrapper_key.sign(&msg, &ctx, &rnd).unwrap();
        assert_eq!(
            ours.as_bytes()[..],
            sig[..],
            "{}: signature bytes diverged",
            case.name
        );

        if ctx.is_empty() {
            let parsed = MLDSA65Signature::from_bytes(&sig).unwrap();
            assert!(
                public.verify(&msg, &parsed).is_ok(),
                "{}: TS signature rejected",
                case.name
            );
            // The wire format is the raw bytes: no serialization envelope may sneak in.
            verify_serialization(&public, Some(public.as_ref()));
            verify_serialization(&parsed, Some(parsed.as_ref()));
        } else {
            let parsed = mldsa::Signature::from_bytes(&sig).unwrap();
            assert!(wrapper_public.verify(&msg, &ctx, &parsed).is_ok());
        }
    }
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

/// The ML-DSA-65 vectors from satoshilabs/slips#1968: chain codes pin the
/// HMAC walk, and the public-key digests pin FIPS 204 key expansion.
#[test]
fn slip10_slips1968_vectors() {
    use crate::slip10::MLDSA65_MASTER_KEY;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::hash::{HashFunction, Sha256};
    use fastcrypto::slip10::derive_hardened;

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
        let node = derive_hardened(MLDSA65_MASTER_KEY, &seed, indexes);
        assert_eq!(
            Hex::encode(node.chain_code),
            *want_cc,
            "chain code, path {indexes:?}"
        );

        let kp = MLDSA65KeyPair::derive_slip10(&seed, indexes).unwrap();
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
}
