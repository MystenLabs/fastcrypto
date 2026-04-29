// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! NIST ACVP-Server KATs for SLH-DSA-SHA2-128s.
//!
//! Fixtures under `kats/fixtures/` are extracted by `fixtures/extract.sh` and
//! split by ACVP `preHash` mode:
//!
//!   * `*_none.json` exercises [`slh_sign_internal`] / [`slh_verify_internal`]
//!     (FIPS 205 Alg. 19/20).
//!   * `*_pure.json` exercises [`slh_sign`] / [`slh_verify`] (FIPS 205 Alg.
//!     22/24), with the per-test `context` string.
//!
//! Each test is `#[ignore]`d by default (full keygen+sign runs for several
//! minutes in debug mode). Run explicitly with:
//!
//!     cargo test -p fastcrypto --features experimental --release \
//!         sphincs::kats -- --ignored --nocapture

use crate::sphincs::{
    slh_keygen, slh_sign, slh_sign_internal, slh_verify, slh_verify_internal, SlhDsaParams,
    SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature,
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

fn opt_hex(s: &Option<String>) -> Option<Vec<u8>> {
    s.as_ref().map(|h| hex(h))
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

// ---------------- sigGen (preHash=none, internal) ----------------

#[derive(Deserialize)]
struct SiggenInternalCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    deterministic: bool,
    #[serde(rename = "additionalRandomness")]
    additional_randomness: Option<String>,
    sk: String,
    pk: String,
    message: String,
    signature: String,
}

#[test]
#[ignore]
fn kat_slh_dsa_sha2_128s_siggen_internal() {
    let params = SlhDsaParams::sha2_128s();
    let cases: Vec<SiggenInternalCase> =
        serde_json::from_str(&fixture("slh_dsa_sha2_128s_siggen_none.json")).unwrap();
    assert!(!cases.is_empty());

    for c in &cases {
        // ACVP invariant: deterministic groups omit `additionalRandomness`,
        // randomized groups always supply it.
        assert_eq!(
            c.deterministic,
            c.additional_randomness.is_none(),
            "tcId={}: deterministic flag inconsistent with additionalRandomness presence",
            c.tc_id
        );
        let sk = SlhDsaSecretKey::from_bytes(&params, &hex(&c.sk)).unwrap();
        let pk = SlhDsaPublicKey::from_bytes(&params, &hex(&c.pk)).unwrap();
        let msg = hex(&c.message);
        let addrnd = opt_hex(&c.additional_randomness);

        let sig = slh_sign_internal(&params, &sk, &msg, addrnd.as_deref());
        assert_eq!(
            sig.to_bytes(),
            hex(&c.signature),
            "sig bytes mismatch, tcId={}",
            c.tc_id
        );
        assert!(
            slh_verify_internal(&params, &pk, &msg, &sig),
            "self-verify failed, tcId={}",
            c.tc_id
        );
    }
    println!("siggen (internal): {} cases passed", cases.len());
}

// ---------------- sigGen (preHash=pure, external) ----------------

#[derive(Deserialize)]
struct SiggenPureCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    deterministic: bool,
    context: String,
    #[serde(rename = "additionalRandomness")]
    additional_randomness: Option<String>,
    sk: String,
    pk: String,
    message: String,
    signature: String,
}

#[test]
#[ignore]
fn kat_slh_dsa_sha2_128s_siggen_pure() {
    let params = SlhDsaParams::sha2_128s();
    let cases: Vec<SiggenPureCase> =
        serde_json::from_str(&fixture("slh_dsa_sha2_128s_siggen_pure.json")).unwrap();
    assert!(!cases.is_empty());

    for c in &cases {
        assert_eq!(
            c.deterministic,
            c.additional_randomness.is_none(),
            "tcId={}: deterministic flag inconsistent with additionalRandomness presence",
            c.tc_id
        );
        let sk = SlhDsaSecretKey::from_bytes(&params, &hex(&c.sk)).unwrap();
        let pk = SlhDsaPublicKey::from_bytes(&params, &hex(&c.pk)).unwrap();
        let msg = hex(&c.message);
        let ctx = hex(&c.context);
        let addrnd = opt_hex(&c.additional_randomness);

        let sig = slh_sign(&params, &sk, &msg, &ctx, addrnd.as_deref()).unwrap();
        assert_eq!(
            sig.to_bytes(),
            hex(&c.signature),
            "sig bytes mismatch, tcId={}",
            c.tc_id
        );
        assert!(
            slh_verify(&params, &pk, &msg, &sig, &ctx),
            "self-verify failed, tcId={}",
            c.tc_id
        );
    }
    println!("siggen (pure): {} cases passed", cases.len());
}

// ---------------- sigVer (preHash=none, internal) ----------------

#[derive(Deserialize)]
struct SigverInternalCase {
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
fn kat_slh_dsa_sha2_128s_sigver_internal() {
    let params = SlhDsaParams::sha2_128s();
    let cases: Vec<SigverInternalCase> =
        serde_json::from_str(&fixture("slh_dsa_sha2_128s_sigver_none.json")).unwrap();
    assert!(!cases.is_empty());

    for c in &cases {
        let pk = SlhDsaPublicKey::from_bytes(&params, &hex(&c.pk)).unwrap();
        let msg = hex(&c.message);
        let sig_bytes = hex(&c.signature);

        // Malformed-length sigs (per ACVP "reason") must be rejected at parse time.
        let got = match SlhDsaSignature::from_bytes(&params, &sig_bytes) {
            Ok(sig) => slh_verify_internal(&params, &pk, &msg, &sig),
            Err(_) => false,
        };
        assert_eq!(
            got, c.test_passed,
            "sigver mismatch, tcId={} reason=\"{}\"",
            c.tc_id, c.reason
        );
    }
    println!("sigver (internal): {} cases passed", cases.len());
}

// ---------------- sigVer (preHash=pure, external) ----------------

#[derive(Deserialize)]
struct SigverPureCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(rename = "testPassed")]
    test_passed: bool,
    reason: String,
    context: String,
    pk: String,
    message: String,
    signature: String,
}

#[test]
#[ignore]
fn kat_slh_dsa_sha2_128s_sigver_pure() {
    let params = SlhDsaParams::sha2_128s();
    let cases: Vec<SigverPureCase> =
        serde_json::from_str(&fixture("slh_dsa_sha2_128s_sigver_pure.json")).unwrap();
    assert!(!cases.is_empty());

    for c in &cases {
        let pk = SlhDsaPublicKey::from_bytes(&params, &hex(&c.pk)).unwrap();
        let msg = hex(&c.message);
        let ctx = hex(&c.context);
        let sig_bytes = hex(&c.signature);

        let got = match SlhDsaSignature::from_bytes(&params, &sig_bytes) {
            Ok(sig) => slh_verify(&params, &pk, &msg, &sig, &ctx),
            Err(_) => false,
        };
        assert_eq!(
            got, c.test_passed,
            "sigver mismatch, tcId={} reason=\"{}\"",
            c.tc_id, c.reason
        );
    }
    println!("sigver (pure): {} cases passed", cases.len());
}
