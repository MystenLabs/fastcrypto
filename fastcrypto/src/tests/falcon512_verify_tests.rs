// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Full NIST Round-3 KAT parity for the Falcon-512 verification core.
//!
//! Parses the official 100-vector response file (`falcon512-KAT.rsp`, copied
//! verbatim from the Falcon submission).

use crate::falcon512::verify::{
    derive_public_key, validate_secret_key, verify, verify_strict, SIG_PADDED_LEN,
};

pub struct KatVector {
    pub count: u32,
    /// 48-byte entropy the KAT harness fed its AES-256-CTR DRBG for this
    /// vector; replaying the DRBG recovers the exact `randombytes` stream
    /// keygen consumed (see `keygen_seed_reproduces_reference_kats`).
    pub seed: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub msg: Vec<u8>,
    /// Detached signature `header(1) || nonce(40) || body'
    pub sig: Vec<u8>,
}

/// Parse the `.rsp` into vectors
pub fn parse_kat_vectors() -> Vec<KatVector> {
    let content = include_str!("vectors/falcon512-KAT.rsp");

    let mut vectors = Vec::new();
    let (mut count, mut seed, mut mlen, mut msg, mut pk, mut sk) =
        (None, None, None, None, None, None);

    for line in content.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(" = ") else {
            continue; // blank lines and the "# Falcon-512" banner
        };
        match key {
            "count" => count = Some(value.parse::<u32>().expect("count is decimal")),
            "seed" => seed = Some(hex::decode(value).expect("seed is hex")),
            "mlen" => mlen = Some(value.parse::<usize>().expect("mlen is decimal")),
            "msg" => msg = Some(hex::decode(value).expect("msg is hex")),
            "pk" => pk = Some(hex::decode(value).expect("pk is hex")),
            "sk" => sk = Some(hex::decode(value).expect("sk is hex")),
            "sm" => {
                let sm = hex::decode(value).expect("sm is hex");
                let mlen = mlen.take().expect("mlen precedes sm");
                let msg = msg.take().expect("msg precedes sm");
                assert_eq!(msg.len(), mlen, "mlen disagrees with msg");

                // Reassemble header || nonce || body from the sm layout above.
                let sig_len = ((sm[0] as usize) << 8) | sm[1] as usize;
                let nonce = &sm[2..42];
                let sig_data = &sm[42 + mlen..];
                assert_eq!(
                    sig_data.len(),
                    sig_len,
                    "declared sig_len disagrees with sm"
                );
                let mut sig = Vec::with_capacity(40 + sig_data.len());
                sig.push(sig_data[0]);
                sig.extend_from_slice(nonce);
                sig.extend_from_slice(&sig_data[1..]);

                vectors.push(KatVector {
                    count: count.take().expect("count precedes sm"),
                    seed: seed.take().expect("seed precedes sm"),
                    pk: pk.take().expect("pk precedes sm"),
                    sk: sk.take().expect("sk precedes sm"),
                    msg,
                    sig,
                });
            }
            _ => {} // smlen: unused
        }
    }
    vectors
}

/// Rewrite a natural-length KAT signature into the canonical padded form that
/// strict verification accepts. To do so, flip the header family nibble
/// `0x29 -> 0x39` and zero-pad to 666 bytes. It works because the header byte
/// is not hashed (hash-to-point absorbs only `nonce || message`) and the
/// padded body encoding is the same compressed bitstream with a zero tail.
/// This works well for us, as we need to have our own headers, possibly 0x08
pub fn to_canonical_padded(sig: &[u8]) -> Vec<u8> {
    assert_eq!(sig[0], 0x29, "KAT signatures use the compressed header");
    assert!(sig.len() <= SIG_PADDED_LEN, "vector too long to pad");
    let mut padded = sig.to_vec();
    padded[0] = 0x39;
    padded.resize(SIG_PADDED_LEN, 0);
    padded
}

/// Every 10th vector: a spread across the file without re-verifying all 100
/// in the more expensive multi-variant tests.
pub fn sample(vectors: &[KatVector]) -> impl Iterator<Item = &KatVector> {
    vectors.iter().step_by(10)
}

#[test]
fn all_100_kat_vectors_verify_permissive() {
    let vectors = parse_kat_vectors();
    assert_eq!(vectors.len(), 100, "expected the full NIST KAT suite");

    for v in &vectors {
        // Sanity on what the suite exercises: the Round-3 KATs are uniformly
        // header 0x29 at natural (sub-666) length.
        assert_eq!(v.sig[0], 0x29, "vector {}: unexpected header", v.count);
        assert!(
            v.sig.len() < SIG_PADDED_LEN,
            "vector {}: unexpected length",
            v.count
        );

        assert!(
            verify(&v.pk, &v.msg, &v.sig),
            "KAT vector {} must verify",
            v.count
        );

        // The raw KAT form (header 0x29, natural length) is exactly what
        // strict mode exists to exclude
        assert!(
            !verify_strict(&v.pk, &v.msg, &v.sig),
            "vector {}: raw 0x29 form must fail strict",
            v.count
        );
    }
}

/// Negative variants: any single flipped bit, in the signature nonce, the
/// signature body, the message, or the public key, must fail verification.
#[test]
fn kat_bit_flips_are_rejected() {
    let vectors = parse_kat_vectors();

    for v in sample(&vectors) {
        // Nonce flip: changes the hash-to-point challenge.
        let mut sig = v.sig.clone();
        sig[1] ^= 0x01;
        assert!(
            !verify(&v.pk, &v.msg, &sig),
            "vector {}: nonce flip",
            v.count
        );

        // Body flip, mid-stream
        let mut sig = v.sig.clone();
        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;
        assert!(
            !verify(&v.pk, &v.msg, &sig),
            "vector {}: body flip",
            v.count
        );

        // Message flip
        let mut msg = v.msg.clone();
        msg[0] ^= 0x80;
        assert!(
            !verify(&v.pk, &msg, &v.sig),
            "vector {}: message flip",
            v.count
        );

        // Public-key flip (not the header byte): different h, so the
        // recomputed s1 = c − s2 . h lands outside the norm bound.
        let mut pk = v.pk.clone();
        let mid = pk.len() / 2;
        pk[mid] ^= 0x01;
        assert!(!verify(&pk, &v.msg, &v.sig), "vector {}: pk flip", v.count);
    }
}

/// The canonicalized form (0x29 -> 0x39, zero-pad to 666) of a KAT signature
/// must pass strict verification.
#[test]
fn canonicalized_kat_vectors_pass_strict() {
    let vectors = parse_kat_vectors();
    let mut converted = 0usize;

    for v in sample(&vectors) {
        let padded = to_canonical_padded(&v.sig);
        assert!(
            verify_strict(&v.pk, &v.msg, &padded),
            "vector {}: canonical padded form must pass strict",
            v.count
        );
        assert!(
            verify(&v.pk, &v.msg, &padded),
            "vector {}: canonical padded form must stay valid permissively",
            v.count
        );
        converted += 1;
    }
    assert!(converted >= 10, "need at least 10 converted vectors");
}

/// Wire-format gates, driven off a known-good canonical signature
#[test]
fn strict_rejects_every_non_canonical_encoding() {
    let vectors = parse_kat_vectors();
    let v = &vectors[0];
    let padded = to_canonical_padded(&v.sig);

    assert!(verify_strict(&v.pk, &v.msg, &padded), "baseline must pass");

    // Non-zero padding tail
    let mut tampered = padded.clone();
    *tampered.last_mut().unwrap() = 0x01;
    assert!(!verify_strict(&v.pk, &v.msg, &tampered), "non-zero tail");
    assert!(
        !verify(&v.pk, &v.msg, &tampered),
        "non-zero tail (permissive)"
    );

    // 665 bytes: dropping a tail zero byte breaks the fixed strict length
    assert!(
        !verify_strict(&v.pk, &v.msg, &padded[..SIG_PADDED_LEN - 1]),
        "665 bytes"
    );
    assert!(
        !verify(&v.pk, &v.msg, &padded[..SIG_PADDED_LEN - 1]),
        "665 bytes (permissive)"
    );

    // 667 bytes: one zero byte too many.
    let mut long = padded.clone();
    long.push(0);
    assert!(!verify_strict(&v.pk, &v.msg, &long), "667 bytes");
    assert!(!verify(&v.pk, &v.msg, &long), "667 bytes (permissive)");

    // Header 0x29 at the padded length
    let mut compressed_header = padded.clone();
    compressed_header[0] = 0x29;
    assert!(
        !verify_strict(&v.pk, &v.msg, &compressed_header),
        "header 0x29"
    );
    assert!(
        verify(&v.pk, &v.msg, &compressed_header),
        "0x29 stays valid permissively"
    );
}

/// The derived public key must match the KAT public key byte for byte, for
/// all 100 vectors. The whole sk -> pk path consists of: trimmed decode, NTT,
/// pointwise inversion, inverse NTT, 14-bit encode.
#[test]
fn kat_secret_keys_derive_their_public_keys() {
    let vectors = parse_kat_vectors();
    assert_eq!(vectors.len(), 100);
    for v in &vectors {
        let derived = derive_public_key(&v.sk).expect("KAT sk derives");
        assert_eq!(&derived[..], v.pk.as_slice(), "vector {}", v.count);
    }
}

/// The KAT secret keys must pass the consistency check against their own
/// public keys, and fail it against anyone else's.
#[test]
fn kat_secret_keys_validate_against_their_public_keys() {
    let vectors = parse_kat_vectors();

    for v in sample(&vectors) {
        assert!(
            validate_secret_key(&v.sk, &v.pk),
            "vector {}: own key pair must validate",
            v.count
        );
    }

    // A secret key spliced onto a different vector's public key fails the
    // h·f = g check.
    assert!(!validate_secret_key(&vectors[0].sk, &vectors[1].pk));

    // A bit flip inside f is caught by the structural decode or by the consistency check
    let mut sk = vectors[0].sk.clone();
    sk[100] ^= 0x01;
    assert!(!validate_secret_key(&sk, &vectors[0].pk));

    // Wrong header byte.
    let mut sk = vectors[0].sk.clone();
    sk[0] ^= 0x01;
    assert!(!validate_secret_key(&sk, &vectors[0].pk));
}
