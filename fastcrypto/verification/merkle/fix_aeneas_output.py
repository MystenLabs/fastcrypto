#!/usr/bin/env python3
# THIS FILE IS AI-ONLY
"""Patch the Aeneas output in a generated Lean directory:
* Replace the axioms Aeneas emits for two `AsRef` impls of the standard library, which its Lean
  library does not model, by their definitions:
  * `impl AsRef<[T]> for [T]` returns its argument.
  * `impl AsRef<U> for &T` calls `T`'s `as_ref` (Lean does not distinguish `&T` from `T`).
* serde's traits are mutually recursive, which Lean rejects. Each `serde_core` structure becomes an
  empty structure with the same name and parameters. The generated code only passes `Serialize`
  impls on to `bcs::to_bytes`, which is opaque."""
import re, sys, pathlib
d = pathlib.Path(sys.argv[1])
MODELS = {
    "Slice.Insts.CoreConvertAsRefSlice.as_ref": (
        "def Slice.Insts.CoreConvertAsRefSlice.as_ref\n"
        "  {T : Type _} (s : Slice T) : Result (Slice T) :=\n"
        "  ok s"),
    "Shared0T.Insts.CoreConvertAsRef.as_ref": (
        "def Shared0T.Insts.CoreConvertAsRef.as_ref\n"
        "  {T : Type _} {U : Type _} (AsRefInst : core.convert.AsRef T U) (x : T) : Result U :=\n"
        "  AsRefInst.as_ref x"),
}
t = (d / "Types.lean").read_text()
chunks = t.split("\n\n")
n_serde = 0
for k, c in enumerate(chunks):
    m = re.search(r"^structure (serde_core\.[\w.]+)(.*?)\bwhere\b", c, re.S | re.M)
    if m:
        chunks[k] = c[: m.end()]
        n_serde += 1
assert n_serde > 0
(d / "Types.lean").write_text("\n\n".join(chunks))
f = d / "FunsExternal.lean"
s = f.read_text()
for name, model in MODELS.items():
    s, n = re.subn(r"axiom " + re.escape(name) + r"\n(?:[^\n]+\n)*", model + "\n", s)
    assert n == 1, name
f.write_text(s)
print("fixed", d)
