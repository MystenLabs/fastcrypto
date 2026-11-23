#!/usr/bin/env python3
# THIS FILE IS AI-ONLY
"""Replace the axioms Aeneas emits for two `AsRef` impls of the standard library, which its Lean
library does not model, by their definitions:
* `impl AsRef<[T]> for [T]` returns its argument.
* `impl AsRef<U> for &T` calls `T`'s `as_ref` (Lean does not distinguish `&T` from `T`)."""
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
f = d / "FunsExternal.lean"
s = f.read_text()
for name, model in MODELS.items():
    s, n = re.subn(r"axiom " + re.escape(name) + r"\n(?:[^\n]+\n)*", model + "\n", s)
    assert n == 1, name
f.write_text(s)
print("fixed", d)
