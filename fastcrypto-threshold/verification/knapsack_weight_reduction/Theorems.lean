-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Reduce

/-!
The proofs of the statements in `Spec.lean`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

namespace WeightReductionProofs

theorem verify_reduction_sound : VerifyReductionSound := by
  intro hts weights t f delta weights' t' f'
  apply WP.spec_mono (verify_reduction_spec hts weights t f delta ⟨weights', t', f'⟩)
  intro res h hok S
  have := h hok (fun i => decide (i ∈ S))
  simp only [ReductionPropertiesHold, wsum_eq_sum] at this
  exact this

theorem reduce_weights_passes_verify : ReduceWeightsPassesVerify :=
  fun hts hsort weights t f delta total_weight_lower_bound =>
    reduce_weights_spec hts hsort weights t f delta total_weight_lower_bound

end WeightReductionProofs

#print axioms WeightReductionProofs.verify_reduction_sound
#print axioms WeightReductionProofs.reduce_weights_passes_verify
