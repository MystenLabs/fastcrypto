// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! NIST ACVP-Server KATs for SLH-DSA-SHA2-128s.
//!
//! Fixtures under `kats/fixtures/` are extracted by `fixtures/extract.sh`.
//! Each test is `#[ignore]`d by default (full keygen+sign runs for several
//! minutes in debug mode). Run explicitly with:
//!
//!     cargo test -p fastcrypto --features experimental --release \
//!         sphincs::kats -- --ignored --nocapture

use crate::sphincs::{
    slh_keygen, slh_sign, slh_verify, SlhDsaParams, SlhDsaPublicKey, SlhDsaSecretKey,
    SlhDsaSignature,
};
use serde::Deserialize;
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "src",
        "sphincs",
        "kats",
        "fixtures",
        name,
    ]
    .iter()
    .collect();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {}", path.display(), e))
}

fn hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

// ---------------- keyGen ----------------

#[derive(Deserialize)]
struct KeygenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "skSeed")]
    sk_seed: String,
    #[serde(rename = "skPrf")]
    sk_prf: String,
    #[serde(rename = "pkSeed")]
    pk_seed: String,
    sk: String,
    pk: String,
}

#[test]
#[ignore]
fn kat_slh_dsa_sha2_128s_keygen() {
    let params = SlhDsaParams::sha2_128s();
    let cases: Vec<KeygenCase> =
        serde_json::from_str(&fixture("slh_dsa_sha2_128s_keygen.json")).unwrap();
    assert!(!cases.is_empty());

    for c in &cases {
        let (pk, sk) = slh_keygen(&params, &hex(&c.sk_seed), &hex(&c.sk_prf), &hex(&c.pk_seed));
        assert_eq!(
            pk.to_bytes(),
            hex(&c.pk),
            "keygen pk mismatch, tcId={}",
            c.tc_id
        );
        assert_eq!(
            sk.to_bytes(),
            hex(&c.sk),
            "keygen sk mismatch, tcId={}",
            c.tc_id
        );
    }
    println!("keygen: {} cases passed", cases.len());
}

// ---------------- sigGen (preHash=none, deterministic=true) ----------------

#[derive(Deserialize)]
struct SiggenCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    sk: String,
    pk: String,
    message: String,
    signature: String,
}

#[test]
#[ignore]
fn kat_slh_dsa_sha2_128s_siggen() {
    let params = SlhDsaParams::sha2_128s();
    let cases: Vec<SiggenCase> =
        serde_json::from_str(&fixture("slh_dsa_sha2_128s_siggen.json")).unwrap();
    assert!(!cases.is_empty());

    for c in &cases {
        let sk = SlhDsaSecretKey::from_bytes(&params, &hex(&c.sk)).unwrap();
        let pk = SlhDsaPublicKey::from_bytes(&params, &hex(&c.pk)).unwrap();
        let msg = hex(&c.message);

        let sig = slh_sign(&params, &sk, &msg, None);
        assert_eq!(
            sig.to_bytes(),
            hex(&c.signature),
            "sig bytes mismatch, tcId={}",
            c.tc_id
        );
        // Sanity: our own verify accepts the sig we produced.
        assert!(
            slh_verify(&params, &pk, &msg, &sig),
            "self-verify failed, tcId={}",
            c.tc_id
        );
    }
    println!("siggen: {} cases passed", cases.len());
}

// ---------------- sigVer (preHash=none) ----------------

#[derive(Deserialize)]
struct SigverCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    reason: String,
    pk: String,
    message: String,
    signature: String,
}

#[test]
#[ignore]
fn kat_slh_dsa_sha2_128s_sigver() {
    let params = SlhDsaParams::sha2_128s();
    let cases: Vec<SigverCase> =
        serde_json::from_str(&fixture("slh_dsa_sha2_128s_sigver.json")).unwrap();
    assert!(!cases.is_empty());

    for c in &cases {
        let pk = SlhDsaPublicKey::from_bytes(&params, &hex(&c.pk)).unwrap();
        let msg = hex(&c.message);
        let sig_bytes = hex(&c.signature);

        // Malformed-length sigs (too large / too small per ACVP reason) must be rejected
        // at parse time; that maps to testPassed = false.
        let got = match SlhDsaSignature::from_bytes(&params, &sig_bytes) {
            Ok(sig) => slh_verify(&params, &pk, &msg, &sig),
            Err(_) => false,
        };
        assert_eq!(
            got, c.test_passed,
            "sigver mismatch, tcId={} reason=\"{}\"",
            c.tc_id, c.reason
        );
    }
    println!("sigver: {} cases passed", cases.len());
}
