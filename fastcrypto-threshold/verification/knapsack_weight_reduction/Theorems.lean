-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Reduce

/-!
The theorems about `verify_reduction(weights, t, f, delta, reduction)` in
`fastcrypto_threshold::knapsack_weight_reduction`, which checks a reduction of the weights
`weights` and thresholds `(t, f)` to `reduction = (weights', t', f')`:
* `verify_reduction_sound`: if it returns `Ok(())`, then (P), (L1), (L2) and (L3) hold for every
  set of parties.
* `verify_reduction_no_panic`: it returns, without panicking, on every input.

And about `reduce_weights(weights, t, f, delta, total_weight_lower_bound)`, which computes such a
reduction:
* `reduce_weights_passes_verify`: every reduction it returns passes `verify_reduction`.
* `reduce_weights_no_panic`: it returns, without panicking, on every input.

All four assume `ToStringReturns`: `to_string` returns on every `&str`. The last two also assume
`SortByPermutes`: if the comparator of `sort_by` returns and is a total order on the slice, then
`sort_by` returns a permutation of it.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

namespace WeightReductionProofs

/-- Soundness of `verify_reduction`. If `verify_reduction(weights, t, f, delta, reduction)`
returns `Ok(())`, then for every set `S` of parties, writing `w(S)` and `w'(S)` for the sums of
the original and reduced weights of the parties in `S`:
* (P) `w(S) < t` implies `w'(S) < t'`,
* (L1) `w(S) ≥ t + f + delta` implies `w'(S) ≥ t' + f'`,
* (L2) `w(S) ≤ f` implies `w'(S) ≤ f'`,
* (L3) `w(S) ≥ t + delta` implies `w'(S) ≥ t'`. -/
theorem verify_reduction_sound (hts : ToStringReturns) (weights : Slice U16) (t f delta : U16)
    (reduction : ReducedWeights)
    (h : verify_reduction weights t f delta reduction = ok (.Ok ())) (S : Finset ℕ) :
    let n := weights.length
    let w := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights.val[i]!.val
    let w' := ∑ i ∈ (Finset.range n).filter (· ∈ S), reduction.weights.val[i]!.val
    (w < t.val → w' < reduction.t.val) ∧
    (w ≥ t.val + f.val + delta.val → w' ≥ reduction.t.val + reduction.f.val) ∧
    (w ≤ f.val → w' ≤ reduction.f.val) ∧
    (w ≥ t.val + delta.val → w' ≥ reduction.t.val) := by
  have := spec_of_eq_ok (verify_reduction_spec hts weights t f delta reduction) h rfl
    (fun i => decide (i ∈ S))
  simp only [ReductionPropertiesHold, wsum_eq_sum] at this
  exact this

/-- `verify_reduction` does not panic: on every input, it returns `Ok(())` or an error. In
particular, the `panic!` in `max_reduced_weight` is unreachable. -/
theorem verify_reduction_no_panic (hts : ToStringReturns) (weights : Slice U16)
    (t f delta : U16) (reduction : ReducedWeights) :
    ∃ r, verify_reduction weights t f delta reduction = ok r :=
  (spec_eq_ok (verify_reduction_spec hts weights t f delta reduction)).imp fun _ h => h.1

/-- `reduce_weights` computes reductions that `verify_reduction` accepts. If
`reduce_weights(weights, t, f, delta, total_weight_lower_bound)` returns `Ok(reduction)`, then
`verify_reduction(weights, t, f, delta, reduction)` returns `Ok(())`. -/
theorem reduce_weights_passes_verify (hts : ToStringReturns) (hsort : SortByPermutes)
    (weights : Slice U16) (t f delta total_weight_lower_bound : U16) (reduction : ReducedWeights)
    (h : reduce_weights weights t f delta total_weight_lower_bound = ok (.Ok reduction)) :
    verify_reduction weights t f delta reduction = ok (.Ok ()) :=
  spec_of_eq_ok (reduce_weights_spec hts hsort weights t f delta total_weight_lower_bound) h
    reduction rfl

/-- `reduce_weights` does not panic: on every input, it returns a reduction or an error. -/
theorem reduce_weights_no_panic (hts : ToStringReturns) (hsort : SortByPermutes)
    (weights : Slice U16) (t f delta total_weight_lower_bound : U16) :
    ∃ r, reduce_weights weights t f delta total_weight_lower_bound = ok r :=
  (spec_eq_ok (reduce_weights_spec hts hsort weights t f delta total_weight_lower_bound)).imp
    fun _ h => h.1

end WeightReductionProofs
