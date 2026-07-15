// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use proptest::prelude::*;
use rand::{rngs::StdRng, SeedableRng as _};

use crate::falcon512::{
    verify::{verify, verify_strict},
    Falcon512KeyPair, Falcon512PrivateKey, Falcon512PublicKey, Falcon512Signature,
    FALCON512_PRIVATE_KEY_LENGTH, FALCON512_PUBLIC_KEY_LENGTH, FALCON512_SIGNATURE_LENGTH,
};
use crate::falcon512_verify_tests::{parse_kat_vectors, sample, to_canonical_padded};
use crate::test_helpers::verify_serialization;
use crate::traits::{EncodeDecodeBase64, KeyPair, Signer, ToFromBytes, VerifyingKey};

const MSG: &[u8] = b"Hello, world!";

pub fn keys() -> Vec<Falcon512KeyPair> {
    // Seeded rng, so — like the other schemes — the same four key pairs on
    // every run.
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4)
        .map(|_| Falcon512KeyPair::generate(&mut rng))
        .collect()
}

#[test]
fn sign_and_verify() {
    let kp = keys().pop().unwrap();
    let signature = kp.sign(MSG);
    assert!(kp.public().verify(MSG, &signature).is_ok());

    // Wrong message.
    assert!(kp.public().verify(b"Bad message", &signature).is_err());

    // Wrong key.
    let other_kp = keys().swap_remove(0);
    assert_ne!(other_kp.public(), kp.public());
    assert!(other_kp.public().verify(MSG, &signature).is_err());

    // A corrupted signature does not verify (flip a nonce byte; flipping the
    // header or the zero tail is covered by the strict-encoding tests).
    let mut corrupted = signature.as_ref().to_vec();
    corrupted[1] ^= 0x01;
    let corrupted = <Falcon512Signature as ToFromBytes>::from_bytes(&corrupted).unwrap();
    assert!(kp.public().verify(MSG, &corrupted).is_err());
}

#[test]
fn sign_and_verify_large_message() {
    // A Sui transaction can reach 128 KiB; the signer and verifier must
    // agree on messages of that size (neither bounds the message length).
    let kp = keys().pop().unwrap();
    let msg = vec![0x5au8; 128 * 1024];
    let signature = kp.sign(&msg);
    assert!(kp.public().verify(&msg, &signature).is_ok());
}

#[test]
fn signatures_are_canonical_padded_form() {
    // PQClean falcon-padded-512 must emit exactly the canonical form this
    // module's strict verify accepts: 666 bytes, header 0x39.
    let kp = keys().pop().unwrap();
    for msg in [&b"x"[..], MSG, &[0u8; 1000]] {
        let signature = kp.sign(msg);
        assert_eq!(signature.as_ref().len(), FALCON512_SIGNATURE_LENGTH);
        assert_eq!(signature.as_ref()[0], 0x39);
        // The canonical form also passes the permissive verifier.
        assert!(verify_strict(kp.public().as_ref(), msg, signature.as_ref()));
        assert!(verify(kp.public().as_ref(), msg, signature.as_ref()));
    }
}

#[test]
fn serialize_deserialize() {
    let kp = keys().pop().unwrap();
    let pk = kp.public().clone();
    let sig = kp.sign(MSG);
    let sk = kp.private();

    verify_serialization(&pk, Some(pk.as_bytes()));
    verify_serialization(&sk, Some(sk.as_bytes()));
    verify_serialization(&sig, Some(sig.as_bytes()));

    let kp = keys().pop().unwrap();
    verify_serialization(&kp, Some(kp.as_bytes()));
}

#[test]
fn import_export_public_key() {
    let kpref = keys().pop().unwrap();
    let public_key = kpref.public();
    let export = public_key.encode_base64();
    println!("{:#?}", export);
    let import = Falcon512PublicKey::decode_base64(&export);
    println!("{:#?}", import);
    assert!(import.is_ok());
    assert_eq!(import.unwrap().as_ref(), public_key.as_ref());
}

#[test]
fn keypair_from_bytes_roundtrip() {
    // The keypair serializes to the bare 1281-byte secret key; the public
    // key is re-derived (h = g/f) on deserialization.
    let kp = keys().pop().unwrap();
    let bytes = kp.as_ref().to_vec();
    assert_eq!(bytes.len(), FALCON512_PRIVATE_KEY_LENGTH);

    let restored = Falcon512KeyPair::from_bytes(&bytes).unwrap();
    assert_eq!(restored.public(), kp.public());
    assert_eq!(restored.as_ref(), bytes.as_slice());

    // The restored keypair produces signatures the original key verifies.
    let signature = restored.sign(MSG);
    assert!(kp.public().verify(MSG, &signature).is_ok());
}

#[test]
fn from_bytes_rejects_malformed_secret_key() {
    let kp = keys().pop().unwrap();

    // Wrong header byte.
    let mut bad = kp.as_ref().to_vec();
    bad[0] ^= 0x01;
    assert!(Falcon512KeyPair::from_bytes(&bad).is_err());

    // First f coefficient forced to the forbidden -2^(bits-1) pattern.
    let mut bad = kp.as_ref().to_vec();
    bad[1] = 0x80;
    assert!(Falcon512KeyPair::from_bytes(&bad).is_err());

    // A bit flip inside f is not an error, it is a different key: the
    // derived public key must change.
    let mut flipped = kp.as_ref().to_vec();
    flipped[100] ^= 0x01;
    if let Ok(other) = Falcon512KeyPair::from_bytes(&flipped) {
        assert_ne!(other.public(), kp.public());
    }
}

#[test]
fn exact_length_rejection() {
    for len in [
        FALCON512_PUBLIC_KEY_LENGTH - 1,
        FALCON512_PUBLIC_KEY_LENGTH + 1,
        0,
    ] {
        assert!(Falcon512PublicKey::from_bytes(&vec![0u8; len]).is_err());
    }
    for len in [
        FALCON512_SIGNATURE_LENGTH - 1,
        FALCON512_SIGNATURE_LENGTH + 1,
        0,
    ] {
        assert!(<Falcon512Signature as ToFromBytes>::from_bytes(&vec![0u8; len]).is_err());
    }
    for len in [
        FALCON512_PRIVATE_KEY_LENGTH - 1,
        FALCON512_PRIVATE_KEY_LENGTH + 1,
        0,
    ] {
        assert!(Falcon512PrivateKey::from_bytes(&vec![0u8; len]).is_err());
    }
}

#[test]
fn malformed_public_key_rejected_at_parse_time() {
    // Correct length but an invalid header byte must fail from_bytes.
    let mut bytes = keys().pop().unwrap().public().as_ref().to_vec();
    bytes[0] = 0x0A;
    assert!(Falcon512PublicKey::from_bytes(&bytes).is_err());
    // All-0xFF body has coefficients ≥ q, which is a non-canonical key.
    let mut bytes = vec![0xFFu8; FALCON512_PUBLIC_KEY_LENGTH];
    bytes[0] = 0x09;
    assert!(Falcon512PublicKey::from_bytes(&bytes).is_err());
}

#[test]
fn wellformed_garbage_fails_closed() {
    // A structurally valid (all-zero-coefficient) public key with a garbage
    // signature: must be an error, never a panic and never Ok.
    let mut pk_bytes = vec![0u8; FALCON512_PUBLIC_KEY_LENGTH];
    pk_bytes[0] = 0x09;
    let pk = Falcon512PublicKey::from_bytes(&pk_bytes).unwrap();
    let mut sig_bytes = vec![0u8; FALCON512_SIGNATURE_LENGTH];
    sig_bytes[0] = 0x39;
    let sig = <Falcon512Signature as ToFromBytes>::from_bytes(&sig_bytes).unwrap();
    assert!(pk.verify(MSG, &sig).is_err());
}

#[test]
fn dont_display_secrets() {
    let keypairs = keys();
    keypairs.into_iter().for_each(|keypair| {
        let sk = keypair.private();
        assert_eq!(format!("{}", sk), "<elided secret for Falcon512PrivateKey>");
        assert_eq!(
            format!("{:?}", sk),
            "<elided secret for Falcon512PrivateKey>"
        );
    });
}

/// Canonicalized KAT vectors (see `falcon512_verify_tests`) must pass the
/// public scheme API: official signatures, strict encoding, full parse path.
#[test]
fn canonicalized_kat_vectors_pass_public_api() {
    let vectors = parse_kat_vectors();
    let mut converted = 0usize;

    for v in sample(&vectors) {
        let padded = to_canonical_padded(&v.sig);

        let pk = Falcon512PublicKey::from_bytes(&v.pk).unwrap();
        let sig = <Falcon512Signature as ToFromBytes>::from_bytes(&padded).unwrap();
        assert!(
            pk.verify(&v.msg, &sig).is_ok(),
            "vector {}: canonical padded form must pass the public API",
            v.count
        );
        converted += 1;
    }
    assert!(converted >= 10, "need at least 10 converted vectors");
}

/// Wire-format gates through the public API, driven off a known-good
/// canonical signature: every deviation from the single accepted encoding
/// must fail (whether at signature parse time or at verification). The same
/// variants are cross-checked against the permissive verifier in
/// `falcon512_verify_tests`.
#[test]
fn public_api_rejects_every_non_canonical_encoding() {
    let vectors = parse_kat_vectors();
    let v = &vectors[0];
    let padded = to_canonical_padded(&v.sig);
    let pk = Falcon512PublicKey::from_bytes(&v.pk).unwrap();

    let verify_public = |bytes: &[u8]| -> bool {
        match <Falcon512Signature as ToFromBytes>::from_bytes(bytes) {
            Ok(sig) => pk.verify(&v.msg, &sig).is_ok(),
            Err(_) => false,
        }
    };

    assert!(verify_public(&padded), "baseline must pass");

    // Non-zero padding tail: forgery surface in the padded body.
    let mut tampered = padded.clone();
    *tampered.last_mut().unwrap() = 0x01;
    assert!(!verify_public(&tampered), "non-zero tail");

    // 665 bytes: dropping a tail zero byte breaks the fixed length (rejected
    // at signature parse time).
    assert!(
        !verify_public(&padded[..FALCON512_SIGNATURE_LENGTH - 1]),
        "665 bytes"
    );

    // 667 bytes: one zero byte too many.
    let mut long = padded.clone();
    long.push(0);
    assert!(!verify_public(&long), "667 bytes");

    // Header 0x29 at the padded length: the compressed family is valid
    // permissively but is exactly the second encoding strict mode removes.
    let mut compressed_header = padded.clone();
    compressed_header[0] = 0x29;
    assert!(!verify_public(&compressed_header), "header 0x29");
}

// Arbitrary implementations for the proptests
fn arb_keypair() -> impl Strategy<Value = Falcon512KeyPair> {
    // Key generation is deterministic in the rng, so proptest's seed fully
    // determines the key pair (and failures replay).
    any::<[u8; 32]>()
        .prop_map(|seed| {
            let mut rng = StdRng::from_seed(seed);
            Falcon512KeyPair::generate(&mut rng)
        })
        .no_shrink()
}

proptest! {
    // Key generation is comparatively heavy for the PQ schemes, so fewer
    // cases than the default 256.
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    fn test_keypair_roundtrip(
        kp in arb_keypair(),
    ){
        let serialized = bincode::serialize(&kp).unwrap();
        let deserialized: Falcon512KeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(kp.public(), deserialized.public());
    }
}
