-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Knapsack
import knapsack_weight_reduction.Spec

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
  · intro u hu hu'; exact i17_post2 u (by scalar_tac) (by scalar_tac)
  · intro u hu hu'; exact i21_post2 u (by scalar_tac) (by scalar_tac)
  · intro u hu hu'; exact i26_post2 u (by scalar_tac) (by scalar_tac)
  · intro u hu hu'; exact i34_post2 u (by scalar_tac) (by scalar_tac)

end WeightReductionProofs

/-! ## When `verify_reduction` accepts -/

namespace WeightReductionProofs
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

/-- `max { u ≤ len - 1 : tbl[u] ≤ b }`: what `max_reduced_weight` returns. -/
def gmax (tbl : List U32) (b : ℕ) : ℕ :=
  Nat.findGreatest (fun u => tbl[u]!.val ≤ b) (tbl.length - 1)

lemma eq_gmax (tbl : Slice U32) (b : ℕ) (r : ℕ) (hr : r < tbl.length)
    (hle : tbl.val[r]!.val ≤ b) (hmax : ∀ u, u < tbl.length → tbl.val[u]!.val ≤ b → u ≤ r) :
    r = gmax tbl.val b := by
  unfold gmax
  symm
  rw [Nat.findGreatest_eq_iff]
  refine ⟨by simp only [Slice.length] at hr; omega, fun _ => hle, fun k hk hk' hP => ?_⟩
  have := hmax k (by simp only [Slice.length] at hr ⊢; omega) hP
  omega

lemma gmax_mono (tbl : List U32) {a b : ℕ} (h : a ≤ b) : gmax tbl a ≤ gmax tbl b :=
  Nat.findGreatest_mono (fun _ hu => le_trans hu h) le_rfl

lemma gmax_le (tbl : List U32) (b : ℕ) : gmax tbl b ≤ tbl.length - 1 :=
  Nat.findGreatest_le _

/-- `max_reduced_weight` returns `gmax`. -/
lemma max_reduced_weight_gmax (tbl : Slice U32) (weight : U32)
    (hlen : 1 ≤ tbl.length) (hlen' : tbl.length ≤ 65536) (h0 : tbl.val[0]!.val = 0) :
    max_reduced_weight tbl weight ⦃ r => r.val = gmax tbl.val weight.val ∧ r.val < tbl.length ⦄ :=
  WP.spec_mono (max_reduced_weight_spec tbl weight hlen hlen' h0)
    fun r ⟨hr, hle, hmax⟩ => ⟨eq_gmax tbl weight.val r.val hr hle hmax, hr⟩

-- In the next lemma, `step*` uses the table given as a hypothesis.
attribute [-step] knapsack_min_original_spec max_reduced_weight_spec

set_option maxHeartbeats 4000000 in
/-- `verify_reduction` accepts `reduction` if the checks on the inputs pass, and the four values
of `max_reduced_weight` on its table `tbl` pass the checks (P), (L2), (L3) and (L1). -/
lemma verify_reduction_accepts (hts : ToStringReturns) (weights : Slice U16) (t f delta : U16)
    (reduction : ReducedWeights) (tbl : alloc.vec.Vec U32) (RT : U32)
    (hlen : reduction.weights.length = weights.length) (hn : weights.length ≤ 1000)
    (hW : total weights.val weights.length ≤ 65535)
    (hRT : RT.val = total reduction.weights.val weights.length) (hRT' : RT.val ≤ 65535)
    (htbl : knapsack_min_original weights (alloc.vec.Vec.deref reduction.weights) RT = ok tbl)
    (hlenT : tbl.length = RT.val + 1) (h0 : tbl.val[0]!.val = 0)
    (ht : 1 ≤ t.val) (hf : 1 ≤ f.val) (hft : f.val < t.val)
    (htf : t.val + 2 * f.val ≤ total weights.val weights.length)
    (htfd : t.val + f.val + delta.val ≤ total weights.val weights.length)
    (ht' : 1 ≤ reduction.t.val) (hf' : 1 ≤ reduction.f.val)
    (hft' : reduction.f.val < reduction.t.val)
    (hP : gmax tbl.val (t.val - 1) ≤ reduction.t.val - 1)
    (hL2 : gmax tbl.val f.val ≤ reduction.f.val)
    (hL3 : reduction.t.val ≤
      RT.val - gmax tbl.val (total weights.val weights.length - (t.val + delta.val)))
    (hL1 : reduction.t.val + reduction.f.val ≤
      RT.val - gmax tbl.val (total weights.val weights.length - (t.val + f.val + delta.val))) :
    verify_reduction weights t f delta reduction = ok (.Ok ()) := by
  have hk : ∀ rt : U32, rt.val = RT.val →
      knapsack_min_original weights (alloc.vec.Vec.deref reduction.weights) rt ⦃ y => y = tbl ⦄ := by
    intro rt h
    have : rt = RT := UScalar.eq_of_val_eq h
    rw [this, htbl]; simp
  have hm : ∀ b : U32, max_reduced_weight (alloc.vec.Vec.deref tbl) b ⦃ r =>
      r.val = gmax tbl.val b.val ⦄ := fun b => by
    simpa using WP.spec_mono (max_reduced_weight_gmax (alloc.vec.Vec.deref tbl) b
      (by simp [hlenT]) (by simp [hlenT]; omega) (by simpa using h0)) fun _ h => h.1
  have := to_string_spec hts
  suffices hs : verify_reduction weights t f delta reduction ⦃ r => r = .Ok () ⦄ by
    obtain ⟨r, h, rfl⟩ := spec_eq_ok hs; exact h
  unfold verify_reduction
  step*
  all_goals try vr_tac
  subst min_original_weight_map_post
  step*
  all_goals vr_tac

end WeightReductionProofs
