// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checks that the annotated copy Verus verifies is the production code. Compiled as part of
//! the fastcrypto-threshold tests (see `fastcrypto-threshold/src/lib.rs`), so it runs in normal CI
//! without Verus.

const COPY: &str = include_str!("verified_dkg_merge.rs");

/// The verified regions: their names and the production files they're in.
const REGIONS: [(&str, &str); 3] = [
    (
        "used_processed_messages_from",
        include_str!("../../../fastcrypto-threshold/src/dkg_v1.rs"),
    ),
    (
        "merge",
        include_str!("../../../fastcrypto-threshold/src/dkg_v1.rs"),
    ),
    (
        "node_id_to_node",
        include_str!("../../../fastcrypto-threshold/src/nodes.rs"),
    ),
];

/// The only precondition of `merge`: the assumption in its doc comment, that every message comes
/// from `process_message` and so has a valid sender. Changing it changes what is proved.
const MERGE_REQUIRES: &str = "forall|i: int| 0 <= i < processed_messages@.len() ==> \
     (#[trigger] processed_messages@[i]).message.sender < self.nodes.nodes@.len(),";

/// The items in the copy that may be `external_body`, i.e. trusted: the opaque stand-ins and the
/// derived `Clone`s.
const ALLOWED_EXTERNAL_BODY: [&str; 4] = [
    "pub struct Opaque<",
    "pub struct Complaint<",
    "fn clone(&self) -> (r: Self)",
    "fn clone(&self) -> (r: Self)",
];

/// The annotated copy of the verified functions (verified_dkg_merge.rs, next to this file) must
/// match the production code: once its annotations and comments are removed, each region must be
/// the same code in both files. Otherwise the proof would be about different code.
#[test]
fn verus_copy_matches_production() {
    // These would let the proof assume what it should prove, or skip verifying code.
    for escape_hatch in [
        "assume(",
        "admit(",
        "assume_specification",
        "verifier::external]",
        "verus_verify(external",
        "verifier::truncate",
    ] {
        assert!(
            !COPY.contains(escape_hatch),
            "`{escape_hatch}` is not allowed in the verified copy"
        );
    }
    check_external_body();

    for (name, production_file) in REGIONS {
        let production = verified_region(production_file, name);
        let copy = verified_region(COPY, name);
        check_every_function_is_verified(name, copy);
        if name == "merge" {
            check_merge_requires(copy);
        }
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
                "region `{name}` of the Verus copy differs from the production code; update \
                 verified_dkg_merge.rs.\nproduction: ...{}...\ncopy:       ...{}...",
                context(&production),
                context(&copy)
            );
        }
    }
}

/// The text between the `BEGIN VERUS-VERIFIED: name` and `END VERUS-VERIFIED: name` markers.
fn verified_region<'a>(source: &'a str, name: &str) -> &'a str {
    let begin_marker = format!("// BEGIN VERUS-VERIFIED: {name}\n");
    let end_marker = format!("// END VERUS-VERIFIED: {name}\n");
    let begin = source
        .find(&begin_marker)
        .unwrap_or_else(|| panic!("begin marker of `{name}`"));
    let end = source
        .find(&end_marker)
        .unwrap_or_else(|| panic!("end marker of `{name}`"));
    assert!(begin < end);
    &source[begin + begin_marker.len()..end]
}

/// `external_body` makes Verus trust an item instead of verifying it, so it may only be used on
/// the stand-ins listed in `ALLOWED_EXTERNAL_BODY`.
fn check_external_body() {
    let mut found = Vec::new();
    for (at, _) in COPY.match_indices("#[verifier::external_body]") {
        // The item is the next line that isn't another attribute.
        let item = COPY[at..]
            .lines()
            .skip(1)
            .map(str::trim)
            .find(|line| !line.starts_with("#["))
            .expect("an item after the attribute");
        let allowed = ALLOWED_EXTERNAL_BODY
            .iter()
            .find(|allowed| item.starts_with(**allowed))
            .unwrap_or_else(|| panic!("`external_body` is not allowed on `{item}`"));
        found.push(*allowed);
    }
    assert_eq!(
        found, ALLOWED_EXTERNAL_BODY,
        "unexpected `external_body` items"
    );
}

/// Verus only verifies a function outside `verus!` if it has a `#[verus_spec]` attribute, and
/// silently treats it as unverified otherwise. So every function in a region must have one.
fn check_every_function_is_verified(name: &str, region: &str) {
    let mut functions = 0;
    for (newline, _) in region.match_indices('\n') {
        let fn_start = newline + 1;
        let line = region[fn_start..].trim_start();
        let Some(signature) = line
            .strip_prefix("pub fn ")
            .or_else(|| line.strip_prefix("fn "))
        else {
            continue;
        };
        let function = &signature[..signature.find('(').expect("function signature")];
        let missing =
            || panic!("`{function}` in `{name}` has no #[verus_spec], so Verus would skip it");
        // The function's attribute is the last `#[verus_spec` before it, and only whitespace
        // and doc comments may separate the two.
        let spec_start = region[..fn_start]
            .rfind("#[verus_spec")
            .unwrap_or_else(missing);
        let spec_end = spec_start + balanced_len(&region[spec_start..], '[');
        if !normalize(&region[spec_end..fn_start], false).is_empty() {
            missing();
        }
        functions += 1;
    }
    assert_eq!(functions, 1, "expected one function in `{name}`");
}

/// `merge` may only assume `MERGE_REQUIRES`.
fn check_merge_requires(region: &str) {
    let spec_start = region.find("#[verus_spec").expect("spec of merge");
    let spec = &region[spec_start..spec_start + balanced_len(&region[spec_start..], '[')];
    let requires = spec.find("requires").expect("requires of merge") + "requires".len();
    let ensures = spec.find("ensures").expect("ensures of merge");
    assert_eq!(
        normalize(&spec[requires..ensures], false),
        normalize(MERGE_REQUIRES, false),
        "the precondition of `merge` changed"
    );
}

/// Removes comments, and Verus annotations if `strip_annotations`, and puts the code in a form that
/// doesn't depend on formatting: whitespace is kept only where it separates two words, and trailing
/// commas before a closing bracket are dropped (rustfmt adds them when it splits an argument list,
/// e.g. around an annotated closure).
fn normalize(source: &str, strip_annotations: bool) -> String {
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut space = false;
    let mut i = 0;
    while i < source.len() {
        let rest = &source[i..];
        if rest.starts_with("//") {
            i += rest.find('\n').unwrap_or(rest.len());
        } else if strip_annotations && rest.starts_with("#[verus_spec") {
            i += balanced_len(rest, '[');
        } else if strip_annotations && rest.starts_with("proof!") {
            i += balanced_len(rest, '{');
            i += source[i..].starts_with(';') as usize;
        } else {
            let c = rest.chars().next().unwrap();
            let len = if c == '"' {
                // Copy string literals verbatim so their content is never treated as code.
                1 + rest[1..].find('"').expect("closing quote") + 1
            } else {
                c.len_utf8()
            };
            if c.is_whitespace() {
                space = true;
            } else if c == ',' && next_is_closing_bracket(&rest[1..]) {
                // A trailing comma.
            } else {
                if space && out.ends_with(is_word) && is_word(c) {
                    out.push(' ');
                }
                space = false;
                out.push_str(&rest[..len]);
            }
            i += len;
        }
    }
    out
}

/// Whether the next character that isn't whitespace or part of a comment closes a bracket.
fn next_is_closing_bracket(s: &str) -> bool {
    let mut rest = s.trim_start();
    while rest.starts_with("//") {
        rest = rest[rest.find('\n').unwrap_or(rest.len())..].trim_start();
    }
    rest.starts_with([')', ']', '}'])
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
