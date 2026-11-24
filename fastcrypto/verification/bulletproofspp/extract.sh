#!/usr/bin/env bash
# THIS FILE IS AI-ONLY
# Regenerate `Generated/` from fastcrypto's `bulletproofspp` module with Charon and Aeneas.
#
# Uses the `charon` and `aeneas` binaries of the Aeneas nightly release `nightly-2026.11.21-2e3d448`
# (https://github.com/AeneasVerif/aeneas/releases), which matches the Aeneas commit in
# `lakefile.lean`. Set CHARON and AENEAS to their paths, or put them on PATH.
#
# `groups`, `pedersen` (except `Range`), `serde_helpers`, `merlin` and `transcript` (except `Label`)
# are opaque, as are `crs::compatible_with_pedersen_commitments` and `crs::cached_generators`
# (hash-to-curve and the CRS cache):
# Lean sees their types and functions as axioms, about which the proofs assume only what
# `ScalarModel`, `PointModel` and `TranscriptModel` state.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
charon=${CHARON:-charon}
aeneas=${AENEAS:-aeneas}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

U=crate::bulletproofspp::util
cd "$root/fastcrypto"
CARGO_TARGET_DIR="$root/target/charon" "$charon" cargo --preset aeneas \
  --start-from "$U::inner_product" \
  --start-from "$U::weighted_inner_product" \
  --start-from "$U::weighted_norm" \
  --start-from "$U::to_scalars" \
  --start-from "$U::power_vector" \
  --start-from "$U::vec_add" \
  --start-from "$U::vec_scalar_mul" \
  --start-from "$U::hadamard" \
  --start-from "$U::pad_to" \
  --start-from "$U::batch_invert" \
  --start-from "$U::to_digits" \
  --start-from "$U::multiplicities" \
  --start-from "crate::bulletproofspp::laurent" \
  --start-from "crate::bulletproofspp::constraints::Constraints::new" \
  --start-from "crate::bulletproofspp::constraints::Constraints::p_n" \
  --start-from "crate::bulletproofspp::norm_linear::prove" \
  --start-from "crate::bulletproofspp::norm_linear::verify" \
  --start-from "crate::bulletproofspp::crs::Generators::commit" \
  --start-from "crate::bulletproofspp::circuit::CircuitParams::new" \
  --start-from "crate::bulletproofspp::circuit::prove" \
  --start-from "crate::bulletproofspp::circuit::verify" \
  --start-from "crate::bulletproofspp::range_proof::RangeProof::prove_batch" \
  --start-from "crate::bulletproofspp::range_proof::RangeProof::verify_batch" \
  --start-from "crate::bulletproofspp::range_proof::RangeProof::prove" \
  --start-from "crate::bulletproofspp::range_proof::RangeProof::verify" \
  --opaque crate::bulletproofspp::crs::cached_generators \
  --opaque crate::groups --opaque crate::pedersen --opaque crate::serde_helpers --opaque merlin \
  --opaque crate::bulletproofspp::crs::compatible_with_pedersen_commitments \
  --include crate::pedersen::PedersenCommitment --include crate::pedersen::Blinding \
  --include crate::pedersen::Range \
  --opaque crate::bulletproofspp::transcript --include crate::bulletproofspp::transcript::Label \
  --dest-file "$out/bppp.llbc" -- --features experimental

"$aeneas" -backend lean -split-files -dest "$out/lean" "$out/bppp.llbc"

gen="$here/Generated"
rm -rf "$gen" && mkdir "$gen"
cp "$out/lean/Types.lean" "$out/lean/Funs.lean" "$gen/"
cp "$out/lean/TypesExternal_Template.lean" "$gen/TypesExternal.lean"
cp "$out/lean/FunsExternal_Template.lean" "$gen/FunsExternal.lean"
sed -i.bak 's/import Bppp\./import bulletproofspp.Generated./g' "$gen"/*.lean && rm "$gen"/*.bak
python3 -I "$here/fix_aeneas_output.py" "$gen"
for f in "$gen"/*.lean; do
  { echo "-- THIS FILE IS AI-ONLY"; cat "$f"; } > "$f.tmp" && mv "$f.tmp" "$f"
done
