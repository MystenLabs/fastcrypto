#!/usr/bin/env bash
# Copyright (c) 2022, Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the Lean translation of the verified functions in
# fastcrypto-threshold/src/knapsack_weight_reduction.rs, and records the hash of the code it was
# generated from in translated_code.sha256. See README.md.
#
# Needs `charon` and `aeneas` from the commits named in README.md, on PATH or in $CHARON and
# $AENEAS.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CHARON="${CHARON:-charon}"
AENEAS="${AENEAS:-aeneas}"
LLBC="$HERE/fastcrypto_threshold.llbc"

# Translate `verify_reduction` and everything it calls (Charon follows the calls).
(
    cd "$REPO/fastcrypto-threshold"
    "$CHARON" cargo --preset=aeneas \
        --start-from 'fastcrypto_threshold::knapsack_weight_reduction::verify_reduction' \
        --dest-file "$LLBC" \
        -- --lib
)

# Generate KnapsackWeightReduction/{Types,Funs}.lean (and a template for any external functions).
"$AENEAS" -backend lean -split-files -namespace KnapsackWeightReduction \
    -dest "$HERE" -subdir KnapsackWeightReduction "$LLBC"

# Record which code the translation was generated from.
(cd "$REPO" && BLESS_AENEAS_TRANSLATION=1 cargo test -q -p fastcrypto-threshold --lib \
    aeneas_translation_is_fresh)

echo "Done. Now check the proofs with: (cd $HERE && lake build)"
