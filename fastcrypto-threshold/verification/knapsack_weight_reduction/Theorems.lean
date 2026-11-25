-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Reduce

/-!
The main theorems about `fastcrypto_threshold::knapsack_weight_reduction`.

The theorems take two assumptions about functions of the Rust standard library that the Aeneas
library does not model, so the translation leaves them undefined:
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

/-- `verify_reduction` does not panic, and is sound. `verify_reduction(weights, t, f, delta,
reduction)` with `reduction = (weights', t', f')` returns on every input: the `panic!` in
`max_reduced_weight` is unreachable. And if it returns `Ok(())`, then for every set `S` of
parties, writing `w(S)` and `w'(S)` for the sums of the original and reduced weights of the
parties in `S`:
* (P) `w(S) < t` implies `w'(S) < t'`,
* (L1) `w(S) ≥ t + f + delta` implies `w'(S) ≥ t' + f'`,
* (L2) `w(S) ≤ f` implies `w'(S) ≤ f'`,
* (L3) `w(S) ≥ t + delta` implies `w'(S) ≥ t'`. -/
theorem verify_reduction_sound (hts : ToStringReturns) (weights : Slice U16) (t f delta : U16)
    (weights' : alloc.vec.Vec U16) (t' f' : U16) :
    verify_reduction weights t f delta ⟨weights', t', f'⟩ ⦃ res =>
      res = .Ok () → ∀ S : Finset ℕ,
        let n := weights.length
        let w : ℕ := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights.val[i]!
        let w' : ℕ := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights'.val[i]!
        (w < t → w' < t') ∧
        (w ≥ t + f + delta → w' ≥ t' + f') ∧
        (w ≤ f → w' ≤ f') ∧
        (w ≥ t + delta → w' ≥ t') ⦄ := by
  apply WP.spec_mono (verify_reduction_spec hts weights t f delta ⟨weights', t', f'⟩)
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
        verify_reduction weights t f delta reduction = ok (.Ok ()) ⦄ :=
  reduce_weights_spec hts hsort weights t f delta total_weight_lower_bound

end WeightReductionProofs
