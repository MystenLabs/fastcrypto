#!/usr/bin/env python3
# THIS FILE IS AI-ONLY
"""Patch the Aeneas output in a generated Lean directory: replace the axioms Aeneas emits for some
functions of the standard library, which its Lean library does not model, and for the methods
of `pedersen::Range`, which Charon leaves opaque with the rest of `pedersen`, by their
definitions:
* `u64::ilog2` panics on zero and otherwise returns the floor of the base-2 logarithm.
* `i32::unsigned_abs` returns the absolute value as a `u32`.
* `core::slice::from_ref` returns the slice of one element.
* `usize::next_power_of_two` returns the least power of two at least its argument, and panics
  on overflow, as with debug assertions.
* `Range::bits` is the number of bits of the range, and `Range::is_in_range` compares with
  `u64::MAX >> (64 - bits)`, that is `2^bits - 1`."""
import re, sys, pathlib
d = pathlib.Path(sys.argv[1])
MODELS = {
    "core.num.U64.ilog2": (
        "def core.num.U64.ilog2 (x : Std.U64) : Result Std.U32 :=\n"
        "  if x.val = 0 then fail .panic else ok ⟨BitVec.ofNat _ x.val.log2⟩"),
    "core.num.I32.unsigned_abs": (
        "def core.num.I32.unsigned_abs (x : Std.I32) : Result Std.U32 :=\n"
        "  ok ⟨BitVec.ofNat _ x.val.natAbs⟩"),
    "core.slice.raw.from_ref": (
        "def core.slice.raw.from_ref {T : Type _} (x : T) : Result (Slice T) :=\n"
        "  ok (Slice.from [x] (by scalar_tac))"),
    "core.num.Usize.next_power_of_two": (
        "def core.num.Usize.next_power_of_two (x : Std.Usize) : Result Std.Usize :=\n"
        "  if x.val.nextPowerOfTwo ≤ Std.Usize.max then ok ⟨BitVec.ofNat _ x.val.nextPowerOfTwo⟩\n"
        "  else fail .panic"),
    "pedersen.Range.bits": (
        "def pedersen.Range.bits (r : pedersen.Range) : Result Std.Usize :=\n"
        "  match r with\n"
        "  | .Bits8 => ok 8#usize\n"
        "  | .Bits16 => ok 16#usize\n"
        "  | .Bits32 => ok 32#usize\n"
        "  | .Bits64 => ok 64#usize"),
    "pedersen.Range.is_in_range": (
        "def pedersen.Range.is_in_range (r : pedersen.Range) (value : Std.U64) : Result Bool := do\n"
        "  let b ← pedersen.Range.bits r\n"
        "  ok (decide (value.val ≤ 2 ^ b.val - 1))"),
}
f = d / "FunsExternal.lean"
s = f.read_text()
for name, model in MODELS.items():
    s, n = re.subn(r"axiom " + re.escape(name) + r"[^\n]*\n(?:[^\n]+\n)*", model + "\n", s)
    assert n == 1, name
f.write_text(s)
print("fixed", d)
