// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checks that the Lean translation the Aeneas proofs are about was generated from the current
//! production code. Compiled as part of the fastcrypto-threshold tests (see
//! `fastcrypto-threshold/src/lib.rs`), so it runs in normal CI without Charon, Aeneas or Lean.

use fastcrypto::encoding::{Encoding, Hex};
use fastcrypto::hash::{HashFunction, Sha256};

const DKG: &str = include_str!("../../../fastcrypto-threshold/src/dkg_v1.rs");
const NODES: &str = include_str!("../../../fastcrypto-threshold/src/nodes.rs");
const STANDINS: &str = include_str!("standins/src/lib.rs");
const STANDINS_BUILD: &str = include_str!("standins/build.rs");
const RECORDED_HASH: &str = include_str!("translated_code.sha256");

/// The proofs in this directory are about `DkgMerge/Funs.lean`, which `extract.sh` generates from
/// the production code of the verified functions, compiled against the stand-in types. This test
/// fails when that code has changed since: the regions between the `AENEAS-VERIFIED` markers in
/// `dkg_v1.rs` and `nodes.rs`, or the stand-in crate. Comments and whitespace are ignored.
///
/// After such a change, run `extract.sh`, which regenerates the translation and then reruns this
/// test with `BLESS_AENEAS_TRANSLATION=1` to record the new hash, and check that the proofs still
/// go through with `lake build`.
#[test]
fn dkg_merge_lean_translation_is_fresh() {
    let code = [
        region(DKG, "used_processed_messages_from"),
        region(DKG, "merge"),
        region(NODES, "node_id_to_node"),
        STANDINS,
        STANDINS_BUILD,
    ]
    .map(normalize)
    .join("\n");
    let hash = Hex::encode(Sha256::digest(code.as_bytes()).digest);
    if std::env::var_os("BLESS_AENEAS_TRANSLATION").is_some() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../verification/fastcrypto-threshold/dkg_merge_aeneas/translated_code.sha256"
        );
        std::fs::write(path, format!("{hash}\n")).expect("write the hash");
        return;
    }
    assert_eq!(
        hash,
        RECORDED_HASH.trim(),
        "the code the Aeneas proofs about `Party::merge` are about has changed since its Lean \
         translation was generated; run verification/fastcrypto-threshold/dkg_merge_aeneas/extract.sh \
         and check that the proofs still go through (see the README there)"
    );
}

/// The text between the `BEGIN AENEAS-VERIFIED: name` and `END AENEAS-VERIFIED: name` markers.
fn region<'a>(source: &'a str, name: &str) -> &'a str {
    let begin = format!("// BEGIN AENEAS-VERIFIED: {name}\n");
    let end = format!("// END AENEAS-VERIFIED: {name}\n");
    let start = source
        .find(&begin)
        .unwrap_or_else(|| panic!("begin marker of `{name}`"))
        + begin.len();
    let stop = source
        .find(&end)
        .unwrap_or_else(|| panic!("end marker of `{name}`"));
    &source[start..stop]
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
