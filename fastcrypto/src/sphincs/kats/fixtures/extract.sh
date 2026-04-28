#!/usr/bin/env bash
# Extract SLH-DSA KAT fixtures from usnistgov/ACVP-Server.
#
# Usage: ./extract.sh [PARAMETER_SET]
#   PARAMETER_SET defaults to SLH-DSA-SHA2-128s — the only variant our code
#   implements today. For sigGen/sigVer we pull only the "internal" group
#   (preHash = "none", deterministic = true for sigGen), which is what
#   slh_sign / slh_verify compute. pure + preHash variants would need the
#   wrapper algorithms from FIPS 205 §10.
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

# sigGen: preHash=="none" and deterministic==true (matches slh_sign(sk, msg, None)).
jq --arg p "$PARAM_SET" \
   '[.testGroups[]
     | select(.parameterSet == $p and .preHash == "none" and .deterministic == true)
     | .tests[]
     | {tcId, sk, pk, message, signature}]' \
   "$TMP/siggen.json" > "$OUT_DIR/${SLUG}_siggen.json"

# sigVer: preHash=="none" (covers valid + all modified-sig / malformed negative cases).
jq --arg p "$PARAM_SET" \
   '[.testGroups[]
     | select(.parameterSet == $p and .preHash == "none")
     | .tests[]
     | {tcId, testPassed, reason, pk, message, signature}]' \
   "$TMP/sigver.json" > "$OUT_DIR/${SLUG}_sigver.json"

echo "Wrote:"
wc -c "$OUT_DIR/${SLUG}_keygen.json" "$OUT_DIR/${SLUG}_siggen.json" "$OUT_DIR/${SLUG}_sigver.json"
