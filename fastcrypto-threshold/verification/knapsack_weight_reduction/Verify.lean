-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Knapsack

/-!
What `verify_reduction` returns (`verify_reduction_spec`), under the assumption
`ToStringReturns`, and the lemmas to read a Hoare triple as an equation.
-/

open Aeneas Aeneas.Std Result ControlFlow

namespace WeightReductionProofs
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

set_option maxHeartbeats 2000000

-- As in `Knapsack.lean`, which also makes `UScalar.cast_inBounds_spec` a `step` lemma.
attribute [-step] UScalar.cast.step_spec

lemma spec_eq_ok {α : Type _} {m : Result α} {p : α → Prop} (h : m ⦃ x => p x ⦄) :
    ∃ x, m = ok x ∧ p x := by
  cases m with
  | ret a => exact ⟨a, rfl, (WP.spec_ok a).mp h⟩
  | vis e k => exact absurd h (by simp)
  | div => exact absurd h (by simp)

lemma spec_of_eq_ok {α : Type _} {m : Result α} {p : α → Prop} {x : α}
    (h : m ⦃ x => p x ⦄) (hm : m = ok x) : p x := by
  rw [hm] at h; exact (WP.spec_ok x).mp h


/-- Discharges the preconditions in `verify_reduction`: bounds, and facts about the table seen
through `Vec.deref`. -/
macro "vr_tac" : tactic => `(tactic| first
  | scalar_tac
  | (simp only [deref_val, deref_length] at *; scalar_tac)
  | (simp only [deref_val, deref_length] at *; agrind)
  | (simp [U16.rMax, U32.rMax] at *; scalar_tac)
  | (simp only [deref_val, deref_length] at *; simp_all))

/-- `to_string` returns on every `&str`. It is only called to build the message of a
`GeneralError`, and nothing is assumed about the string it returns. -/
def ToStringReturns : Prop :=
  ∀ s : Str, ∃ r, alloc.string.ToString.Blanket.to_string Str.Insts.CoreFmtDisplay s = ok r

lemma to_string_spec (hts : ToStringReturns) (s : Str) :
    alloc.string.ToString.Blanket.to_string Str.Insts.CoreFmtDisplay s ⦃ _ => True ⦄ := by
  obtain ⟨r, h⟩ := hts s; rw [h]; simp

@[simp, scalar_tac_simps]
lemma MAX_PARTIES_val : MAX_PARTIES.val = 1000 := by
  simp [MAX_PARTIES]

@[simp]
lemma deref_val {α : Type _} (v : alloc.vec.Vec α) : (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref]

@[simp, scalar_tac_simps]
lemma deref_length {α : Type _} (v : alloc.vec.Vec α) :
    (alloc.vec.Vec.deref v).length = v.length := by
  simp [alloc.vec.Vec.deref]

/-- For every input, `verify_reduction` returns without panicking, overflowing or indexing out of
bounds, and if it returns `Ok(())`, then (P), (L1), (L2) and (L3) hold for every subset of the
parties. -/
lemma verify_reduction_spec (hts : ToStringReturns) (weights : Slice U16) (t f delta : U16)
    (reduction : ReducedWeights) :
    verify_reduction weights t f delta reduction ⦃ r =>
      r = .Ok () → ∀ s, ReductionPropertiesHold weights.val t.val f.val delta.val
        reduction.weights.val reduction.t.val reduction.f.val s ⦄ := by
  unfold verify_reduction
  have := to_string_spec hts
  -- `step*` goes through every branch. The early returns are discharged automatically, and
  -- `vr_tac` discharges the preconditions of the calls (bounds, and facts about the table).
  step*
  all_goals try vr_tac
  -- What is left is the success case: every check passed. Collect the facts and apply
  -- `properties_of_checks`.
  intro _ s
  simp only [deref_val, deref_length] at *
  have hlen : reduction.weights.length = weights.length := by
    have h := ‹¬(weights.len != reduction.weights.len) = true›
    simp [bne_iff_ne] at h; scalar_tac
  have hRT : reduced_total.val = total reduction.weights.val weights.length := by
    rw [reduced_total_post, hlen]
  have htbl_len :
      min_original_weight_map.length = total reduction.weights.val weights.length + 1 := by
    rw [min_original_weight_map_post, hRT]
  refine properties_of_checks weights.val reduction.weights.val t.val f.val delta.val
    reduction.t.val reduction.f.val (by scalar_tac) (by scalar_tac)
    (fun u => min_original_weight_map.val[u]!.val)
    (fun s b => by simpa using min_original_weight_map_post2 s b)
    i17.val i21.val i26.val i34.val ?_ ?_ ?_ ?_
    (by scalar_tac) (by scalar_tac) (by scalar_tac) (by scalar_tac) s
  -- Each `max_reduced_weight` result bounds the entries at most its argument.
  · intro u hu hu'; exact i17_post1 u (by scalar_tac) (by scalar_tac)
  · intro u hu hu'; exact i21_post1 u (by scalar_tac) (by scalar_tac)
  · intro u hu hu'; exact i26_post1 u (by scalar_tac) (by scalar_tac)
  · intro u hu hu'; exact i34_post1 u (by scalar_tac) (by scalar_tac)

end WeightReductionProofs
