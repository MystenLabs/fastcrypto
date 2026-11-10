// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checks that the Lean translation the Aeneas proofs are about was generated from the current
//! production code. Compiled as part of the fastcrypto-threshold tests (see
//! `fastcrypto-threshold/src/lib.rs`), so it runs in normal CI without Charon, Aeneas or Lean.

use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::hash::{HashFunction, Sha256};

const PRODUCTION: &str =
    include_str!("../../../fastcrypto-threshold/src/knapsack_weight_reduction.rs");
const RECORDED_HASH: &str = include_str!("translated_code.sha256");

/// The proofs in this directory are about `KnapsackWeightReduction/Funs.lean`, which `extract.sh`
/// generates from the production code. This test fails when the code it was generated from has
/// changed since: the region between the AENEAS-VERIFIED markers, and the two definitions it uses
/// from elsewhere in the file. Comments and whitespace are ignored.
///
/// After such a change, run `extract.sh`, which regenerates the translation and then reruns this
/// test with `BLESS_AENEAS_TRANSLATION=1` to record the new hash, and check that the proofs still
/// go through with `lake build`.
#[test]
fn aeneas_translation_is_fresh() {
    let hash = Hex::encode(Sha256::digest(translated_code(PRODUCTION).as_bytes()).digest);
    if std::env::var_os("BLESS_AENEAS_TRANSLATION").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../verification/fastcrypto-threshold/knapsack_weight_reduction_aeneas/translated_code.sha256"
        );
        std::fs::write(path, format!("{hash}\n")).expect("write the hash");
        return;
    }
    assert_eq!(
        hash,
        RECORDED_HASH.trim(),
        "the code the Aeneas proofs are about has changed since its Lean translation was \
         generated; run verification/fastcrypto-threshold/knapsack_weight_reduction_aeneas/extract.sh \
         and check that the proofs still go through (see the README there)"
    );
}

/// The parts of the production file that the translation is generated from, without comments
/// and with whitespace collapsed.
fn translated_code(source: &str) -> String {
    let region = between(source, "// BEGIN AENEAS-VERIFIED", "// END AENEAS-VERIFIED");
    let max_parties = between(source, "const MAX_PARTIES", ";");
    let reduced_weights = between(source, "pub struct ReducedWeights", "\n}");
    [max_parties, reduced_weights, region]
        .map(normalize)
        .join("\n")
}

/// The text from the first occurrence of `begin` up to the next occurrence of `end`.
fn between<'a>(source: &'a str, begin: &str, end: &str) -> &'a str {
    let start = source
        .find(begin)
        .unwrap_or_else(|| panic!("`{begin}` not found"));
    let len = source[start..]
        .find(end)
        .unwrap_or_else(|| panic!("`{end}` not found after `{begin}`"));
    &source[start..start + len]
}

/// Removes `//` comments and collapses whitespace, so that only code changes change the hash.
fn normalize(source: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < source.len() {
        let rest = &source[i..];
        if rest.starts_with("//") {
            i += rest.find('\n').unwrap_or(rest.len());
        } else if let Some(literal) = rest.strip_prefix('"') {
            // Copy string literals verbatim so their content is never treated as code.
            let len = 1 + literal.find('"').expect("closing quote") + 1;
            out.push_str(&rest[..len]);
            i += len;
        } else {
            let c = rest.chars().next().unwrap();
            if c.is_whitespace() {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            } else {
                out.push(c);
            }
            i += c.len_utf8();
        }
    }
    out.trim().to_string()
}
