-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.RangeProof
import bulletproofspp.Proofs.Model.Circuit

/-!
# Completeness of `range_proof.rs`

`RangeProof::verify_batch` accepts the proof `RangeProof::prove_batch` outputs for the Pedersen
commitments to the values.
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

lemma le_next_power_of_two (n : ℕ) : n ≤ next_power_of_two n :=
  Nat.le_pow_clog (by norm_num) n

namespace RangeProof

/-- `CircuitParams::new` for a nonempty batch. -/
lemma params_new (range : Range) (m : ℕ) (hm : m ≠ 0) :
    ∃ params, CircuitParams.new range m = .ok params ∧ params.Valid ∧ params.range = range ∧
      params.m = m ∧ 16 ^ params.d = 2 ^ range.bits := by
  refine ⟨_, by simp [CircuitParams.new, hm]; rfl, ⟨rfl, ?_, ?_⟩, rfl, rfl, ?_⟩
  · exact (le_max_left _ _).trans (le_next_power_of_two _)
  · exact (le_max_right _ BASE).trans (le_next_power_of_two _)
  · cases range <;> rfl

/-- The Pedersen commitments to `values` under `blindings`. -/
def commitments (G H : E) (values : List ℕ) (blindings : List F) : List (PedersenCommitment E) :=
  (List.zip (to_scalars values : List F) blindings).map fun (v, s) => PedersenCommitment.new G H v s

end RangeProof

end Bppp
