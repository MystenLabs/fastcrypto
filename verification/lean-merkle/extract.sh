#!/usr/bin/env bash
# THIS FILE IS AI-ONLY
# Regenerate `Merkle/` from fastcrypto's `merkle` module with Charon and Aeneas.
#
# Uses the `charon` and `aeneas` binaries of the Aeneas nightly release `nightly-2026.11.18-1dc8ad3`
# (https://github.com/AeneasVerif/aeneas/releases), which matches the Aeneas commit in
# `lakefile.lean`. Set CHARON and AENEAS to their paths, or put them on PATH.
#
# The `hash` module is opaque except for `Digest`: Lean sees the `HashFunction` trait as a
# structure of functions that the generated code takes as a parameter.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
charon=${CHARON:-charon}
aeneas=${AENEAS:-aeneas}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

M=crate::merkle
cd "$root/fastcrypto"
CARGO_TARGET_DIR="$root/target/charon" "$charon" cargo --preset aeneas \
  --start-from "$M::MerkleTree::build_from_leaf_hashes" \
  --start-from "$M::MerkleTree::get_proof" \
  --start-from "$M::MerkleTree::root" \
  --start-from "$M::MerkleProof::verify_proof" \
  --start-from "$M::MerkleProof::is_right_most" \
  --opaque crate::hash --include crate::hash::Digest \
  --opaque serde_core --opaque serde \
  --dest-file "$out/merkle.llbc"

"$aeneas" -backend lean -split-files -dest "$out/lean" "$out/merkle.llbc"

rm -rf "$here/Merkle" && mkdir "$here/Merkle"
cp "$out/lean/Types.lean" "$out/lean/Funs.lean" "$here/Merkle/"
cp "$out/lean/FunsExternal_Template.lean" "$here/Merkle/FunsExternal.lean"
sed -i.bak 's/import lean\./import Merkle./g' "$here"/Merkle/*.lean && rm "$here"/Merkle/*.bak
python3 -I "$here/fix_aeneas_output.py" "$here/Merkle"
for f in "$here"/Merkle/*.lean; do
  { echo "-- THIS FILE IS AI-ONLY"; cat "$f"; } > "$f.tmp" && mv "$f.tmp" "$f"
done
