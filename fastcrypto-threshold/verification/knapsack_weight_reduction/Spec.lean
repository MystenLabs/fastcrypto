-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Generated.Funs
import Mathlib.Algebra.BigOperators.Group.Finset.Basic

/-!
The statements of the theorems about `fastcrypto_threshold::knapsack_weight_reduction`, and their
assumptions. `Theorems.lean` proves the statements. This file is the claim of the proofs, so a
reviewer reads it in full. The rest is checked by Lean.

The statements are about the Lean translation of the Rust code in `Generated/`. There, a `U16` is
a Rust `u16`, which Lean converts to its value as a natural number where needed, so sums do not
overflow.

The assumptions are about functions of the Rust standard library that the Aeneas library does not
model, so the translation leaves them undefined:
* `ToStringReturns`: for every `s` of type `&str`, `s.to_string()` returns a `String`.
* `SortByPermutes`: for every mutable slice `s` and every `compare` that returns on all pairs of
  elements of `s` and is a total order on them, `s.sort_by(compare)` returns, leaving a
  permutation of `s`. Here, `compare` is a total order if `compare(b, a)` is the reverse of
  `compare(a, b)`, and `compare(a, b) != Greater` and `compare(b, c) != Greater` imply
  `compare(a, c) != Greater`. This is what the Rust documentation of `sort_by` states
  (https://doc.rust-lang.org/std/primitive.slice.html#method.sort_by).
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

namespace WeightReductionProofs

/-! ## Assumptions -/

/-- `to_string` returns on every `&str`. It is only called to build the message of a
`GeneralError`, and nothing is assumed about the string it returns. -/
def ToStringReturns : Prop :=
  ∀ s : Str, ∃ r, alloc.string.ToString.Blanket.to_string Str.Insts.CoreFmtDisplay s = ok r

/-- `cmp` returns on every pair of elements of `xs`, without changing its state, and is a total
order on them, which is what Rust requires of the comparator of `sort_by`: comparing `b` with `a`
gives the reverse of comparing `a` with `b`, and "not greater" is transitive. -/
def TotalOrderOn {T F : Type} (inst : core.ops.function.FnMut F (T × T) Ordering) (cmp : F)
    (xs : List T) : Prop :=
  ∃ ord : T → T → Ordering,
    (∀ a ∈ xs, ∀ b ∈ xs, inst.call_mut cmp (a, b) = ok (ord a b, cmp)) ∧
    (∀ a ∈ xs, ∀ b ∈ xs, ord b a = (ord a b).swap) ∧
    (∀ a ∈ xs, ∀ b ∈ xs, ∀ c ∈ xs, ord a b ≠ .gt → ord b c ≠ .gt → ord a c ≠ .gt)

/-- `sort_by`, as Rust documents it: if the comparator returns on the elements of the slice and is
a total order on them, `sort_by` returns a permutation of the slice. -/
def SortByPermutes : Prop :=
  ∀ {T F : Type} (inst : core.ops.function.FnMut F (T × T) Ordering) (s : Slice T) (cmp : F),
    TotalOrderOn inst cmp s.val →
    ∃ s', alloc.slice.Slice.sort_by inst s cmp = ok s' ∧ s'.val.Perm s.val

/-! ## Statements -/

/-- `verify_reduction` does not panic, and is sound. `verify_reduction(weights, t, f, delta,
reduction)` with `reduction = (weights', t', f')` returns on every input: the `panic!` in
`max_reduced_weight` is unreachable. And if it returns `Ok(())`, then for every set `S` of
parties, writing `w(S)` and `w'(S)` for the sums of the original and reduced weights of the
parties in `S`:
* (P) `w(S) < t` implies `w'(S) < t'`,
* (L1) `w(S) ≥ t + f + delta` implies `w'(S) ≥ t' + f'`,
* (L2) `w(S) ≤ f` implies `w'(S) ≤ f'`,
* (L3) `w(S) ≥ t + delta` implies `w'(S) ≥ t'`. -/
def VerifyReductionSound : Prop :=
  ToStringReturns →
  ∀ (weights : Slice U16) (t f delta : U16) (weights' : alloc.vec.Vec U16) (t' f' : U16),
    verify_reduction weights t f delta ⟨weights', t', f'⟩ ⦃ res =>
      res = .Ok () → ∀ S : Finset ℕ,
        let n := weights.length
        let w : ℕ := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights.val[i]!
        let w' : ℕ := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights'.val[i]!
        (w < t → w' < t') ∧
        (w ≥ t + f + delta → w' ≥ t' + f') ∧
        (w ≤ f → w' ≤ f') ∧
        (w ≥ t + delta → w' ≥ t') ⦄

/-- `reduce_weights` does not panic, and computes reductions that `verify_reduction` accepts:
`reduce_weights(weights, t, f, delta, total_weight_lower_bound)` returns on every input, and when
it returns `Ok(reduction)`, `verify_reduction(weights, t, f, delta, reduction)` returns
`Ok(())`. -/
def ReduceWeightsPassesVerify : Prop :=
  ToStringReturns → SortByPermutes →
  ∀ (weights : Slice U16) (t f delta total_weight_lower_bound : U16),
    reduce_weights weights t f delta total_weight_lower_bound ⦃ res =>
      ∀ reduction, res = .Ok reduction →
        verify_reduction weights t f delta reduction = ok (.Ok ()) ⦄

end WeightReductionProofs
