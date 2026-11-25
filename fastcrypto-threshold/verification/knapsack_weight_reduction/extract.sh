#!/usr/bin/env bash
# THIS FILE IS AI-ONLY
# Regenerate `Generated/` from fastcrypto-threshold's `knapsack_weight_reduction` module with
# Charon and Aeneas.
#
# Uses the `charon` and `aeneas` binaries of the Aeneas nightly release `nightly-2026.11.21-2e3d448`
# (https://github.com/AeneasVerif/aeneas/releases), which matches the Aeneas commit in
# `lakefile.lean`. Set CHARON and AENEAS to their paths, or put them on PATH.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
charon=${CHARON:-charon}
aeneas=${AENEAS:-aeneas}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

cd "$root/fastcrypto-threshold"
CARGO_TARGET_DIR="$root/target/charon" "$charon" cargo --preset aeneas \
  --start-from "crate::knapsack_weight_reduction::verify_reduction" \
  --start-from "crate::knapsack_weight_reduction::reduce_weights" \
  --dest-file "$out/kwr.llbc"

"$aeneas" -backend lean -split-files -dest "$out/lean" "$out/kwr.llbc"

gen="$here/Generated"
rm -rf "$gen" && mkdir "$gen"
cp "$out/lean/Types.lean" "$out/lean/Funs.lean" "$gen/"
cp "$out/lean/FunsExternal_Template.lean" "$gen/FunsExternal.lean"
sed -i.bak 's/import Kwr\./import knapsack_weight_reduction.Generated./g' "$gen"/*.lean && rm "$gen"/*.bak
for f in "$gen"/*.lean; do
  { echo "-- THIS FILE IS AI-ONLY"; cat "$f"; } > "$f.tmp" && mv "$f.tmp" "$f"
done
