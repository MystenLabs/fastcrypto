// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checks that the annotated copy Verus verifies is the production code. Compiled as part of
//! the fastcrypto-threshold tests (see `fastcrypto-threshold/src/lib.rs`), so it runs in normal CI
//! without Verus.

/// The annotated copy of the verified functions that Verus proves
/// (verified_knapsack_weight_reduction.rs, next to this file) must match the production code: once
/// its annotations and comments are removed, the region between the VERUS-VERIFIED markers must
/// be the same code in both files. Otherwise the proof would be about different code.
#[test]
fn verus_copy_matches_production() {
    let production_file =
        include_str!("../../../fastcrypto-threshold/src/knapsack_weight_reduction.rs");
    let copy_file = include_str!("verified_knapsack_weight_reduction.rs");

    // These would let the proof assume what it should prove, or skip verifying code.
    for escape_hatch in [
        "assume(",
        "admit(",
        "assume_specification",
        "external_body",
        "verifier::external]",
        "verus_verify(external",
        "verifier::truncate",
    ] {
        assert!(
            !copy_file.contains(escape_hatch),
            "`{escape_hatch}` is not allowed in the verified copy"
        );
    }

    let production = verified_region(production_file);
    let copy = verified_region(copy_file);
    check_every_function_is_verified(copy);

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
            "the Verus copy differs from the production code; update \
             verified_knapsack_weight_reduction.rs.\nproduction: ...{}...\ncopy:       ...{}...",
            context(&production),
            context(&copy)
        );
    }
}

/// The text between the `BEGIN VERUS-VERIFIED` and `END VERUS-VERIFIED` markers.
fn verified_region(source: &str) -> &str {
    let begin = source
        .find("// BEGIN VERUS-VERIFIED")
        .expect("begin marker");
    let end = source.find("// END VERUS-VERIFIED").expect("end marker");
    assert!(begin < end);
    &source[begin..end]
}

/// Verus only verifies a function outside `verus!` if it has a `#[verus_spec]` attribute, and
/// silently treats it as unverified otherwise. So every function in the region must have one, and
/// the main theorem must not have a precondition that could make it vacuous.
fn check_every_function_is_verified(region: &str) {
    let mut functions = 0;
    for (newline, _) in region.match_indices('\n') {
        let fn_start = newline + 1;
        let line = &region[fn_start..];
        let Some(signature) = line
            .strip_prefix("pub(crate) fn ")
            .or_else(|| line.strip_prefix("fn "))
        else {
            continue;
        };
        let name = &signature[..signature.find('(').expect("function signature")];
        let missing = || panic!("`{name}` has no #[verus_spec], so Verus would skip it");
        // The function's attribute is the last `#[verus_spec` before it, and only whitespace
        // may separate the two.
        let spec_start = region[..fn_start]
            .rfind("#[verus_spec")
            .unwrap_or_else(missing);
        let spec_end = spec_start + balanced_len(&region[spec_start..], '[');
        if !region[spec_end..fn_start].trim().is_empty() {
            missing();
        }
        let spec = &region[spec_start..spec_end];
        if name == "verify_reduction" {
            assert!(
                !spec.contains("requires"),
                "the main theorem must hold for all inputs"
            );
            assert!(
                spec.contains("ensures"),
                "the main theorem must have a postcondition"
            );
        }
        functions += 1;
    }
    assert_eq!(functions, 4, "expected the four verified functions");
}

/// Removes comments, and Verus annotations if `strip_annotations`, and collapses whitespace.
fn normalize(source: &str, strip_annotations: bool) -> String {
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
        } else if strip_annotations && rest.starts_with("#[verus_spec") {
            i += balanced_len(rest, '[');
        } else if strip_annotations
            && (rest.starts_with("proof!") || rest.starts_with("proof_decl!"))
        {
            i += balanced_len(rest, '{');
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
