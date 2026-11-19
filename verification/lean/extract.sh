#!/usr/bin/env bash
# Regenerate `Avss/` from fastcrypto-threshold's `threshold_schnorr::avss` with Charon and Aeneas.
#
# Uses the `charon` and `aeneas` binaries of the Aeneas nightly release `nightly-2026.11.18-1dc8ad3`
# (https://github.com/AeneasVerif/aeneas/releases), which matches the Aeneas commit in
# `lakefile.lean`. Set CHARON and AENEAS to their paths, or put them on PATH.
#
# Code outside `avss.rs` is kept opaque: Lean only sees the signatures of the functions it calls
# from other modules and crates.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
charon=${CHARON:-charon}
aeneas=${AENEAS:-aeneas}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

A=crate::threshold_schnorr::avss
cd "$root/fastcrypto-threshold"
RUSTFLAGS="--cfg aeneas" CARGO_TARGET_DIR="$root/target/charon" "$charon" cargo --preset aeneas \
  --start-from "$A::Receiver::process_message" \
  --start-from "$A::Receiver::handle_complaint" \
  --start-from "$A::Receiver::verify_complaint_response" \
  --start-from "$A::Receiver::recover" \
  --opaque fastcrypto --include fastcrypto::error \
  --opaque serde_core --opaque serde \
  --opaque "{impl serde_core::ser::Serialize for _}" --opaque "{impl serde_core::de::Deserialize<_> for _}" \
  --opaque crate::polynomial --opaque crate::nodes --opaque crate::ecies_v1 \
  --opaque crate::threshold_schnorr::recovery_proof --opaque crate::random_oracle \
  --opaque crate::threshold_schnorr::bcs \
  --opaque crate::types --include crate::types::IndexedValue \
  --dest-file "$out/avss.llbc"

# Aeneas exits with an error when it cannot translate a body. Such bodies are `sorry`, which
# `fix_aeneas_output.py` turns into axioms: `check_recovery_proof` (its closure) and serde's derives.
"$aeneas" -backend lean -split-files -dest "$out/lean" "$out/avss.llbc" || true

rm -rf "$here/Avss" && mkdir "$here/Avss"
cp "$out/lean/Types.lean" "$out/lean/Funs.lean" "$here/Avss/"
cp "$out/lean/TypesExternal_Template.lean" "$here/Avss/TypesExternal.lean"
cp "$out/lean/FunsExternal_Template.lean" "$here/Avss/FunsExternal.lean"
sed -i.bak 's/import lean\./import Avss./g' "$here"/Avss/*.lean && rm "$here"/Avss/*.bak
python3 -I "$here/fix_aeneas_output.py" "$here/Avss"
