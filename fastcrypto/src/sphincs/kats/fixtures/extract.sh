#!/usr/bin/env bash
# Extract SLH-DSA KAT fixtures from usnistgov/ACVP-Server.
#
# Usage: ./extract.sh [PARAMETER_SET]
#   PARAMETER_SET defaults to SLH-DSA-SHA2-128s — the only variant our code
#   implements today. We pull two ACVP categories:
#     * preHash = "none"  → exercises slh_{sign,verify}_internal directly
#                           (FIPS 205 Alg. 19/20).
#     * preHash = "pure"  → exercises slh_{sign,verify} (FIPS 205 Alg. 22/24).
#   For sigGen we keep both deterministic and non-deterministic groups.
#   The preHash = "preHash" category needs HashSLH-DSA (FIPS 205 §10.4-§10.5),
#   which we don't implement yet.
#
# Requires: curl, jq.

set -euo pipefail

PARAM_SET="${1:-SLH-DSA-SHA2-128s}"
BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Normalize the param-set name for filenames: "SLH-DSA-SHA2-128s" → "slh_dsa_sha2_128s".
SLUG="$(echo "$PARAM_SET" | tr '[:upper:]-' '[:lower:]_')"

fetch() {
  local subdir="$1" dest="$2"
  curl -fsSL "$BASE/$subdir/internalProjection.json" -o "$dest"
}

echo "Fetching ACVP internalProjection.json files..."
fetch SLH-DSA-keyGen-FIPS205 "$TMP/keygen.json"
fetch SLH-DSA-sigGen-FIPS205 "$TMP/siggen.json"
fetch SLH-DSA-sigVer-FIPS205 "$TMP/sigver.json"

echo "Filtering for $PARAM_SET..."

# keyGen: all tests for the parameter set.
jq --arg p "$PARAM_SET" \
   '[.testGroups[] | select(.parameterSet == $p) | .tests[]]' \
   "$TMP/keygen.json" > "$OUT_DIR/${SLUG}_keygen.json"

# sigGen: emit one file per preHash mode we support. Each test inherits the
# group's `deterministic` flag (so the consumer knows whether to pass
# `additionalRandomness`) and, for "pure", the `context` field.
for mode in none pure; do
  jq --arg p "$PARAM_SET" --arg m "$mode" \
     '[.testGroups[]
       | select(.parameterSet == $p and .preHash == $m)
       | . as $g
       | .tests[]
       | {tcId, deterministic: $g.deterministic, context, additionalRandomness,
          sk, pk, message, signature}]' \
     "$TMP/siggen.json" > "$OUT_DIR/${SLUG}_siggen_${mode}.json"
done

# sigVer: same split. Includes valid + modified-sig / malformed negative cases.
for mode in none pure; do
  jq --arg p "$PARAM_SET" --arg m "$mode" \
     '[.testGroups[]
       | select(.parameterSet == $p and .preHash == $m)
       | .tests[]
       | {tcId, testPassed, reason, context, pk, message, signature}]' \
     "$TMP/sigver.json" > "$OUT_DIR/${SLUG}_sigver_${mode}.json"
done

echo "Wrote:"
wc -c "$OUT_DIR/${SLUG}_keygen.json" \
       "$OUT_DIR/${SLUG}_siggen_none.json" "$OUT_DIR/${SLUG}_siggen_pure.json" \
       "$OUT_DIR/${SLUG}_sigver_none.json" "$OUT_DIR/${SLUG}_sigver_pure.json"
