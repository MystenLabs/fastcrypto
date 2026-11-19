// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checks that the annotated copy Creusot verifies is the production code. Compiled as part of
//! the fastcrypto-threshold tests (see `fastcrypto-threshold/src/lib.rs`), so it runs in normal CI without
//! Creusot.

/// The annotated copy of the verified functions that Creusot proves
/// (verified_knapsack_weight_reduction.rs, next to this file) must match the production code: once its
/// annotations and comments are removed, the region between the CREUSOT-VERIFIED markers must be
/// the same code in both files. Otherwise the proof would be about different code.
#[test]
fn creusot_copy_matches_production() {
    let production = verified_region(include_str!(
        "../../../fastcrypto-threshold/src/knapsack_weight_reduction.rs"
    ));
    let copy = verified_region(include_str!("verified_knapsack_weight_reduction.rs"));
    assert!(
        !copy.contains("#[trusted]"),
        "trusted functions are not verified"
    );
    let production = normalize(production, false);
    let copy = normalize(copy, true);
    if production != copy {
        let at = production
            .chars()
            .zip(copy.chars())
            .take_while(|(a, b)| a == b)
            .count();
        let context = |s: &str| {
            s.chars()
                .skip(at.saturating_sub(60))
                .take(120)
                .collect::<String>()
        };
        panic!(
            "the Creusot copy differs from the production code; update \
             verified_knapsack_weight_reduction.rs.\nproduction: ...{}...\ncopy:       ...{}...",
            context(&production),
            context(&copy)
        );
    }
}

/// The text between the `BEGIN CREUSOT-VERIFIED` and `END CREUSOT-VERIFIED` markers.
fn verified_region(source: &str) -> &str {
    let begin = source
        .find("// BEGIN CREUSOT-VERIFIED")
        .expect("begin marker");
    let end = source.find("// END CREUSOT-VERIFIED").expect("end marker");
    assert!(begin < end);
    &source[begin..end]
}

/// Removes comments, and Creusot annotations if `strip_annotations`, and collapses whitespace.
fn normalize(source: &str, strip_annotations: bool) -> String {
    const ATTRIBUTES: [&str; 4] = ["#[requires", "#[ensures", "#[invariant", "#[variant"];
    let s = source.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < s.len() {
        let rest = &source[i..];
        if rest.starts_with("//") {
            i += rest.find('\n').unwrap_or(rest.len());
        } else if let Some(literal) = rest.strip_prefix('"') {
            // Copy string literals verbatim so their content is never treated as code.
            let len = 1 + literal.find('"').expect("closing quote") + 1;
            out.push_str(&rest[..len]);
            i += len;
        } else if strip_annotations && ATTRIBUTES.iter().any(|a| rest.starts_with(a)) {
            i += balanced_len(rest, '[');
        } else if strip_annotations && rest.starts_with("proof_assert!") {
            i += "proof_assert!".len();
            i += balanced_len(&source[i..], '{');
            i += source[i..].starts_with(';') as usize;
        } else if strip_annotations && is_snapshot_let(rest) {
            let start = rest.find("snapshot!").unwrap() + "snapshot!".len();
            i += start + balanced_len(&rest[start..], '{');
            i += source[i..].starts_with(';') as usize;
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

/// Whether `s` starts with `let <ident> = snapshot!`.
fn is_snapshot_let(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("let ") else {
        return false;
    };
    let ident_len = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(0);
    ident_len > 0 && rest[ident_len..].trim_start().starts_with("= snapshot!")
}

/// The length of the prefix of `s` up to and including the bracket that closes the first `open`.
fn balanced_len(s: &str, open: char) -> usize {
    let start = s.find(open).expect("opening bracket");
    let mut depth = 0;
    for (i, c) in s.char_indices().skip(start) {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced annotation");
}
