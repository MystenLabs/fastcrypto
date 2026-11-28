import knapsack_weight_reduction.Generated.Funs

/-!
The assumptions that the theorems in `Theorems.lean` take. They are about functions of the Rust
standard library that the Aeneas library does not model, so the translation leaves them
undefined. A reviewer reads this file and `Theorems.lean` in full; the files in `Proofs/` are
lemmas, which Lean checks.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

namespace WeightReductionProofs

/-- For every `s` of type `&str`, `s.to_string()` returns a `String`. Nothing is assumed about
that `String`. -/
def ToStringReturns : Prop :=
  ∀ s : Str, alloc.string.ToString.Blanket.to_string Str.Insts.CoreFmtDisplay s ⦃ _ => True ⦄

/-- `cmp` is a total order on `xs`: on every pair of elements of `xs`, it returns without changing
its state, `cmp(b, a)` is the reverse of `cmp(a, b)`, and `cmp(a, b) != Greater` and
`cmp(b, c) != Greater` imply `cmp(a, c) != Greater`. -/
def TotalOrderOn {T F : Type} (inst : core.ops.function.FnMut F (T × T) Ordering) (cmp : F)
    (xs : List T) : Prop :=
  ∃ ord : T → T → Ordering,
    (∀ a ∈ xs, ∀ b ∈ xs, inst.call_mut cmp (a, b) = ok (ord a b, cmp)) ∧
    (∀ a ∈ xs, ∀ b ∈ xs, ord b a = (ord a b).swap) ∧
    (∀ a ∈ xs, ∀ b ∈ xs, ∀ c ∈ xs, ord a b ≠ .gt → ord b c ≠ .gt → ord a c ≠ .gt)

/-- For every mutable slice `s` and every `compare` that returns on all pairs of elements of `s` and
is a total order on them (`TotalOrderOn`), `s.sort_by(compare)` returns, leaving a permutation of
`s`. This is what the Rust documentation of `sort_by` states
(https://doc.rust-lang.org/std/primitive.slice.html#method.sort_by). -/
def SortByPermutes : Prop :=
  ∀ {T F : Type} (inst : core.ops.function.FnMut F (T × T) Ordering) (s : Slice T) (cmp : F),
    TotalOrderOn inst cmp s.val →
    ∃ s', alloc.slice.Slice.sort_by inst s cmp = ok s' ∧ s'.val.Perm s.val

end WeightReductionProofs
