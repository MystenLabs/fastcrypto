import knapsack_weight_reduction.Assumptions
import knapsack_weight_reduction.Proofs.Reduce

/-!
The theorems about `fastcrypto_threshold::knapsack_weight_reduction`. This file and
`Assumptions.lean`, which states the assumptions they take, are the claim of the proofs, so a
reviewer reads both in full. The files in `Proofs/` are lemmas, which Lean checks.

The theorems are about the Lean translation of the Rust code in `Generated/`. There, a `U16` is a
Rust `u16`, which Lean converts to its value as a natural number where needed, so sums do not
overflow.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

namespace WeightReductionProofs

/-- `verify_reduction` does not panic, and is sound. `verify_reduction(weights, t, f, delta,
reduction)` with `reduction = (weights', t', f')` returns on every input: the `panic!` in
`max_reduced_weight` is unreachable. And if it returns `Ok(())`, then for every set `S` of
parties, writing `w(S)` and `w'(S)` for the sums of the original and reduced weights of the
parties in `S`:
* (P) `w(S) < t` implies `w'(S) < t'`,
* (L1) `w(S) ≥ t + f + delta` implies `w'(S) ≥ t' + f'`,
* (L2) `w(S) ≤ f` implies `w'(S) ≤ f'`,
* (L3) `w(S) ≥ t + delta` implies `w'(S) ≥ t'`. -/
theorem verify_reduction_sound (hts : ToStringReturns)
    (weights : Slice U16) (t f delta : U16) (weights' : alloc.vec.Vec U16) (t' f' : U16) :
    verify_reduction weights t f delta ⟨weights', t', f'⟩ ⦃ res =>
      res = .Ok () → ∀ S : Finset ℕ,
        let n := weights.length
        let w : ℕ := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights.val[i]!
        let w' : ℕ := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights'.val[i]!
        (w < t → w' < t') ∧
        (w ≥ t + f + delta → w' ≥ t' + f') ∧
        (w ≤ f → w' ≤ f') ∧
        (w ≥ t + delta → w' ≥ t') ⦄ := by
  apply WP.spec_mono (verify_reduction_spec hts weights t f delta
    ⟨weights', t', f'⟩)
  intro res h hok S
  have := h hok (fun i => decide (i ∈ S))
  simp only [ReductionPropertiesHold, wsum_eq_sum] at this
  exact this

/-- `reduce_weights` does not panic, and computes reductions that `verify_reduction` accepts:
`reduce_weights(weights, t, f, delta, total_weight_lower_bound)` returns on every input, and when
it returns `Ok(reduction)`, `verify_reduction(weights, t, f, delta, reduction)` returns
`Ok(())`. -/
theorem reduce_weights_passes_verify (hts : ToStringReturns) (hsort : SortByPermutes)
    (weights : Slice U16) (t f delta total_weight_lower_bound : U16) :
    reduce_weights weights t f delta total_weight_lower_bound ⦃ res =>
      ∀ reduction, res = .Ok reduction →
        verify_reduction weights t f delta reduction = ok (.Ok ()) ⦄ := by
  refine reduce_weights_spec hts (fun reduced weights s h => ?_) _ _ _ _ _
  obtain ⟨s', h1, h2⟩ := hsort
    greedy_reject.closure.Insts.CoreOpsFunctionFnMutPairShared2UsizeShared3UsizeOrdering s
    ((reduced, weights) : greedy_reject.closure)
    ⟨densityCmp reduced weights, greedy_comparator_total reduced weights s.val h⟩
  rw [h1]; simpa using h2

end WeightReductionProofs

#print axioms WeightReductionProofs.verify_reduction_sound
#print axioms WeightReductionProofs.reduce_weights_passes_verify
