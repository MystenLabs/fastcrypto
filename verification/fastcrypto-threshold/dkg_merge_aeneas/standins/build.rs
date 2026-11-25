// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Copies the verified regions of the production code into `$OUT_DIR/verified_regions.rs`, inside
//! impl blocks for the stand-in types, so the code that Charon translates is the production code.

use std::path::Path;
use std::{env, fs};

/// The verified regions: the production file each one is in, its name, and the impl block that
/// encloses it in production.
const REGIONS: [(&str, &str, &str); 3] = [
    (
        "dkg_v1.rs",
        "used_processed_messages_from",
        "impl<G: Clone, EG: Clone> From<&[ProcessedMessage<G, EG>]> for UsedProcessedMessages<G, EG>",
    ),
    ("dkg_v1.rs", "merge", "impl<G: Clone, EG: Clone> Party<G, EG>"),
    ("nodes.rs", "node_id_to_node", "impl<G> Nodes<G>"),
];

fn main() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../fastcrypto-threshold/src");
    let mut out = String::new();
    for (file, name, impl_header) in REGIONS {
        let path = src.join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        let source = fs::read_to_string(&path).expect("production file");
        let begin = format!("// BEGIN AENEAS-VERIFIED: {name}\n");
        let end = format!("// END AENEAS-VERIFIED: {name}\n");
        let start = source.find(&begin).expect("begin marker") + begin.len();
        let stop = source.find(&end).expect("end marker");
        out.push_str(&format!("{impl_header} {{\n{}}}\n\n", &source[start..stop]));
    }
    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("verified_regions.rs");
    fs::write(dest, out).expect("write verified_regions.rs");
}
