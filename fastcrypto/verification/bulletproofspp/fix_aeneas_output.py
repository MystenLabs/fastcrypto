#!/usr/bin/env python3
# THIS FILE IS AI-ONLY
"""Patch the Aeneas output in a generated Lean directory: replace the axiom Aeneas emits for
`u64::ilog2`, which its Lean library does not model, by its definition. It panics on zero and
otherwise returns the floor of the base-2 logarithm."""
import re, sys, pathlib
d = pathlib.Path(sys.argv[1])
MODELS = {
    "core.num.U64.ilog2": (
        "def core.num.U64.ilog2 (x : Std.U64) : Result Std.U32 :=\n"
        "  if x.val = 0 then fail .panic else ok ⟨BitVec.ofNat _ x.val.log2⟩"),
}
f = d / "FunsExternal.lean"
s = f.read_text()
for name, model in MODELS.items():
    s, n = re.subn(r"axiom " + re.escape(name) + r"[^\n]*\n(?:[^\n]+\n)*", model + "\n", s)
    assert n == 1, name
f.write_text(s)
print("fixed", d)
