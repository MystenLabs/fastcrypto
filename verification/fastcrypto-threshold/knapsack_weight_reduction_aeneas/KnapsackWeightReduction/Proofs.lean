/-
Copyright (c) 2022, Mysten Labs, Inc.
SPDX-License-Identifier: Apache-2.0
-/
import KnapsackWeightReduction.Funs
import KnapsackWeightReduction.Spec

open Aeneas Aeneas.Std Result ControlFlow

namespace KnapsackWeightReduction
open knapsack_weight_reduction

set_option maxHeartbeats 2000000

-- Reason about casts as exact, with a proof obligation that the value fits, instead of modulo.
attribute [-step] UScalar.cast.step_spec
attribute [local step] UScalar.cast_inBounds_spec

/-- `l[i]!` is `l[i]` within bounds. -/
theorem getElem!_of_lt {α : Type _} [Inhabited α] (l : List α) (i : ℕ) (h : i < l.length) :
    l[i]! = l[i] := getElem!_pos l i h

/-! ## `sum_u16` -/

@[step]
theorem sum_u16_loop_spec (values : Slice U16) (sum : U32) (i : Usize)
    (hlen : values.length ≤ 65537) (hi : i.val ≤ values.length)
    (hsum : sum.val = total values.val i.val) :
    sum_u16_loop values sum i ⦃ r => r.val = total values.val values.length ⦄ := by
  unfold sum_u16_loop
  apply loop.spec_decr_nat
    (measure := fun (x : U32 × Usize) => values.length - x.2.val)
    (inv := fun (x : U32 × Usize) => x.2.val ≤ values.length ∧ x.1.val = total values.val x.2.val)
  · rintro ⟨sum, i⟩ ⟨hi, hsum⟩
    unfold sum_u16_loop.body
    simp only at hi hsum ⊢
    split
    · have hle := total_le values.val i.val
      step*
      refine ⟨by scalar_tac, ?_, by scalar_tac⟩
      have hi' : i.val < values.val.length := by scalar_tac
      rw [i4_post, total_succ, getElem!_of_lt _ _ hi', sum1_post, i3_post, i2_post, hsum]
    · simp only [WP.spec_ok]
      have : i.val = values.length := by scalar_tac
      rw [hsum, this]
  · exact ⟨hi, hsum⟩

@[step]
theorem sum_u16_spec (values : Slice U16) (hlen : values.length ≤ 65537) :
    sum_u16 values ⦃ r => r.val = total values.val values.length ⦄ := by
  unfold sum_u16
  step*
  simp

/-! ## `max_reduced_weight`

The loop's `massert (v > 0)` is the translation of the `panic!` after the loop, so proving that
the loop never fails proves that the panic is unreachable. -/

@[step]
theorem max_reduced_weight_loop_spec (tbl : Slice U32) (weight : U32) (v : Usize)
    (hlen : 1 ≤ tbl.length) (hlen' : tbl.length ≤ 65536) (h0 : tbl.val[0]!.val = 0)
    (hv : v.val ≤ tbl.length)
    (habove : ∀ u, v.val ≤ u → u < tbl.length → weight.val < tbl.val[u]!.val) :
    max_reduced_weight_loop tbl weight v ⦃ r =>
      r.val < tbl.length ∧ ∀ u, u < tbl.length → tbl.val[u]!.val ≤ weight.val → u ≤ r.val ⦄ := by
  unfold max_reduced_weight_loop
  apply loop.spec_decr_nat
    (measure := fun (v : Usize) => v.val)
    (inv := fun (v : Usize) => v.val ≤ tbl.length ∧
      ∀ u, v.val ≤ u → u < tbl.length → weight.val < tbl.val[u]!.val)
  · rintro v ⟨hv, habove⟩
    unfold max_reduced_weight_loop.body
    have hpos : 0 < v.val := by
      by_contra h
      have := habove 0 (by omega) (by omega)
      omega
    step*
    -- The early return is discharged automatically; this is the case that keeps going.
    refine ⟨by scalar_tac, ?_, by scalar_tac⟩
    intro u hu hu'
    by_cases h : u = v1.val
    · subst h
      rw [getElem!_of_lt _ _ (by scalar_tac), ← i_post]
      scalar_tac
    · exact habove u (by omega) hu'
  · exact ⟨hv, habove⟩

@[step]
theorem max_reduced_weight_spec (tbl : Slice U32) (weight : U32)
    (hlen : 1 ≤ tbl.length) (hlen' : tbl.length ≤ 65536) (h0 : tbl.val[0]!.val = 0) :
    max_reduced_weight tbl weight ⦃ r =>
      r.val < tbl.length ∧ ∀ u, u < tbl.length → tbl.val[u]!.val ≤ weight.val → u ≤ r.val ⦄ := by
  unfold max_reduced_weight
  step*

/-! ## `knapsack_min_original` -/

/-- The inner loop, which relaxes the table with one party, iterating `v` downward. Entries below
`v` still hold their old value, and entries from `v` on hold the relaxed one. -/
theorem knapsack_min_original_loop0_loop0_spec
    (old : List U32) (tbl : alloc.vec.Vec U32) (w : U32) (q v : Usize)
    (hlen : tbl.length = old.length) (hq : q.val ≤ v.val) (hv : v.val ≤ old.length)
    (hfits : ∀ u < old.length, old[u]!.val ≠ U32.max → old[u]!.val + w.val ≤ U32.max)
    (hbelow : ∀ u < v.val, tbl.val[u]! = old[u]!)
    (habove : ∀ u, v.val ≤ u → u < old.length → tbl.val[u]!.val = relax old q.val w.val u) :
    knapsack_min_original_loop0_loop0 tbl w q v ⦃ tbl' =>
      tbl'.length = old.length ∧
      ∀ u < old.length, tbl'.val[u]!.val = relax old q.val w.val u ⦄ := by
  unfold knapsack_min_original_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : alloc.vec.Vec U32 × Usize) => x.2.val)
    (inv := fun (x : alloc.vec.Vec U32 × Usize) =>
      x.1.length = old.length ∧ q.val ≤ x.2.val ∧ x.2.val ≤ old.length ∧
      (∀ u < x.2.val, x.1.val[u]! = old[u]!) ∧
      (∀ u, x.2.val ≤ u → u < old.length → x.1.val[u]!.val = relax old q.val w.val u))
  · rintro ⟨tbl, v⟩ ⟨hlen, hq, hv, hbelow, habove⟩
    unfold knapsack_min_original_loop0_loop0.body
    simp only at hlen hq hv hbelow habove ⊢
    simp only [step_simps]
    spec_split
    · let* ⟨ v1, v1_post, v1_post1 ⟩ ← Usize.sub_spec
      let* ⟨ i, i_post, i_post1 ⟩ ← Usize.sub_spec
      let* ⟨ i1, i1_post ⟩ ← alloc.vec.Vec.index_usize_spec
      -- Entry `i = v1 - q` is below `v`, so it still holds its old value, and so does `v1`.
      have hi1 : i1 = old[i.val]! := by
        rw [i1_post, ← getElem!_of_lt _ _ (by scalar_tac)]; exact hbelow _ (by scalar_tac)
      have htv1 : tbl.val[v1.val]! = old[v1.val]! := hbelow _ (by scalar_tac)
      -- Entries other than `v1` are unchanged by this iteration.
      have hrest : ∀ u, v1.val ≤ u → u < old.length → u ≠ v1.val →
          tbl.val[u]!.val = relax old q.val w.val u :=
        fun u hu hu' hne => habove u (by scalar_tac) hu'
      -- The relaxed value of entry `v1`.
      have hrelax : relax old q.val w.val v1.val =
          if i1.val ≠ U32.max ∧ i1.val + w.val < old[v1.val]!.val then i1.val + w.val
          else old[v1.val]!.val := by
        unfold relax
        have : v1.val - q.val = i.val := by scalar_tac
        simp only [this, hi1, show q.val ≤ v1.val by scalar_tac, true_and]
      spec_split
      · rename_i hne
        have hne : i1.val ≠ U32.max := by simp [bne_iff_ne, U32.rMax] at hne; scalar_tac
        let* ⟨ i2, i2_post ⟩ ← alloc.vec.Vec.index_usize_spec
        have hi2 : i2 = i1 := by rw [i2_post, i1_post]
        -- No overflow: `hfits` bounds `i2 + w` (discharged automatically).
        let* ⟨ candidate, candidate_post ⟩ ← U32.add_spec
        let* ⟨ i3, i3_post ⟩ ← alloc.vec.Vec.index_usize_spec
        have hi3 : i3 = old[v1.val]! := by
          rw [i3_post, ← getElem!_of_lt _ _ (by scalar_tac)]; exact htv1
        spec_split
        · -- The candidate is smaller: entry `v1` is updated.
          rename_i hlt
          let* ⟨ _, index_mut_back, __post, index_mut_back_post ⟩ ←
            alloc.vec.Vec.index_mut_usize_spec
          rw [index_mut_back_post]
          refine ⟨by simp [hlen], by scalar_tac, by scalar_tac, ?_, ?_, by scalar_tac⟩
          · intro u hu
            rw [alloc.vec.Vec.set_val_eq]
            have := hbelow u (by scalar_tac)
            simp_lists [this]
          · intro u hu hu'
            by_cases h : u = v1.val
            · subst h
              rw [alloc.vec.Vec.set_val_eq]
              simp_lists
              rw [hrelax, ite_eq_left ⟨hne, by rw [← hi3]; scalar_tac⟩, candidate_post, hi2]
            · rw [alloc.vec.Vec.set_val_eq]
              have := hrest u hu hu' h
              simp_lists
              rw [← getElem!_of_lt _ _ (by scalar_tac)]; exact this
        · -- The candidate is not smaller: nothing changes.
          rename_i hnot_lt
          simp only [WP.spec_ok]
          refine ⟨hlen, by scalar_tac, by scalar_tac, fun u hu => hbelow u (by scalar_tac), ?_,
            by scalar_tac⟩
          intro u hu hu'
          by_cases h : u = v1.val
          · subst h
            rw [hrelax, ite_eq_right (by rw [← hi3]; scalar_tac), htv1]
          · exact hrest u hu hu' h
      · -- The shifted entry is `u32::MAX`: nothing changes.
        rename_i heq
        have heq : i1.val = U32.max := by simp [bne_iff_ne, U32.rMax] at heq; scalar_tac
        simp only [WP.spec_ok]
        refine ⟨hlen, by scalar_tac, by scalar_tac, fun u hu => hbelow u (by scalar_tac), ?_,
          by scalar_tac⟩
        intro u hu hu'
        by_cases h : u = v1.val
        · subst h
          rw [hrelax, ite_eq_right (by simp [heq]), htv1]
        · exact hrest u hu hu' h
    · -- The loop exits with `v = q`: entries below `q` are not relaxed at all.
      rename_i hle
      simp only [WP.spec_ok]
      refine ⟨hlen, fun u hu => ?_⟩
      by_cases h : u < v.val
      · rw [hbelow u h]; unfold relax; rw [ite_eq_right (by scalar_tac)]
      · exact habove u (by scalar_tac) hu
  · exact ⟨hlen, hq, hv, hbelow, habove⟩

/-- The inner loop as `knapsack_min_original` calls it: from the end of the table. -/
@[step]
theorem knapsack_min_original_loop0_loop0_full_spec
    (tbl : alloc.vec.Vec U32) (w : U32) (q v : Usize)
    (hv : v.val = tbl.length) (hq : q.val ≤ v.val)
    (hfits : ∀ u < tbl.length, tbl.val[u]!.val ≠ U32.max → tbl.val[u]!.val + w.val ≤ U32.max) :
    knapsack_min_original_loop0_loop0 tbl w q v ⦃ tbl' =>
      tbl'.length = tbl.length ∧
      ∀ u < tbl.length, tbl'.val[u]!.val = relax tbl.val q.val w.val u ⦄ :=
  knapsack_min_original_loop0_loop0_spec tbl.val tbl w q v rfl hq (by scalar_tac)
    (by simpa using hfits) (fun _ _ => rfl) (fun u hu hu' => by scalar_tac)

/-- The outer loop: after processing the first `i` parties, the entry at the reduced weight of
any subset of them is at most its original weight. -/
@[step]
theorem knapsack_min_original_loop0_spec
    (weights reduced : Slice U16) (tbl : alloc.vec.Vec U32) (n i : Usize) (RT : ℕ)
    (hn : n.val = weights.length) (hlenr : reduced.length = weights.length)
    (hRT : RT = total reduced.val weights.length) (hW : total weights.val weights.length ≤ 65535)
    (hlen : tbl.length = RT + 1) (hi : i.val ≤ n.val) (h0 : tbl.val[0]!.val = 0)
    (hbound : ∀ u < tbl.length,
      tbl.val[u]!.val = U32.max ∨ tbl.val[u]!.val ≤ total weights.val i.val)
    (hsub : ∀ s b, tbl.val[wsum reduced.val s b i.val]!.val ≤ wsum weights.val s b i.val) :
    knapsack_min_original_loop0 weights reduced tbl n i ⦃ tbl' =>
      tbl'.length = RT + 1 ∧ tbl'.val[0]!.val = 0 ∧
      ∀ s b, tbl'.val[wsum reduced.val s b weights.length]!.val ≤
        wsum weights.val s b weights.length ⦄ := by
  unfold knapsack_min_original_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : alloc.vec.Vec U32 × Usize) => n.val - x.2.val)
    (inv := fun (x : alloc.vec.Vec U32 × Usize) =>
      x.1.length = RT + 1 ∧ x.2.val ≤ n.val ∧ x.1.val[0]!.val = 0 ∧
      (∀ u < x.1.length,
        x.1.val[u]!.val = U32.max ∨ x.1.val[u]!.val ≤ total weights.val x.2.val) ∧
      (∀ s b, x.1.val[wsum reduced.val s b x.2.val]!.val ≤ wsum weights.val s b x.2.val))
  · rintro ⟨tbl, i⟩ ⟨hlen, hi, h0, hbound, hsub⟩
    unfold knapsack_min_original_loop0.body
    simp only at hlen hi h0 hbound hsub ⊢
    split
    · have hi' : i.val < weights.length := by scalar_tac
      have hir : i.val < reduced.length := by scalar_tac
      -- The totals of the first `i + 1` parties are at most the totals of all of them.
      have hWi := total_mono weights.val (show i.val + 1 ≤ weights.length by omega)
      have hRi := total_mono reduced.val (show i.val + 1 ≤ weights.length by omega)
      rw [total_succ] at hWi hRi
      rw [getElem!_of_lt _ _ (by scalar_tac)] at hWi
      rw [getElem!_of_lt _ _ (by scalar_tac)] at hRi
      step*
      have hw : w.val = weights.val[i.val]!.val := by
        rw [getElem!_of_lt _ _ hi', w_post, i1_post]
      have hq : q.val = reduced.val[i.val]!.val := by
        rw [getElem!_of_lt _ _ hir, q_post, i2_post]
      rw [← getElem!_of_lt _ _ hi', ← hw] at hWi
      rw [← getElem!_of_lt _ _ hir, ← hq] at hRi
      refine ⟨by scalar_tac, by scalar_tac, ?_, ?_, ?_, by scalar_tac⟩
      · -- Entry 0 stays 0.
        have := min_original_weight1_post1 0 (by scalar_tac)
        have := relax_le_old tbl.val q.val w.val 0
        omega
      · -- Every entry is still `u32::MAX` or at most the total original weight.
        intro u hu
        rw [min_original_weight1_post1 u (by scalar_tac), i3_post, total_succ, ← hw]
        rcases relax_cases tbl.val q.val w.val u with h | ⟨hqu, hne, h⟩
        · rw [h]
          rcases hbound u (by scalar_tac) with h' | h'
          · exact Or.inl h'
          · exact Or.inr (by omega)
        · rw [h]
          rcases hbound (u - q.val) (by scalar_tac) with h' | h'
          · exact absurd h' hne
          · exact Or.inr (by omega)
      · -- The table bounds every subset of the first `i + 1` parties.
        intro s b
        rw [i3_post, wsum_succ, wsum_succ, ← hw, ← hq]
        have ha := wsum_le_total reduced.val s b i.val
        have hc := wsum_le_total weights.val s b i.val
        have hold := hsub s b
        by_cases hsb : s i.val = b
        · -- Party `i` is in the subset: its entry moves up by `q`.
          simp only [hsb, ite_true]
          rw [min_original_weight1_post1 _ (by scalar_tac)]
          have hne : tbl.val[wsum reduced.val s b i.val + q.val - q.val]!.val ≠ U32.max := by
            rw [Nat.add_sub_cancel]; scalar_tac
          have := relax_le_shifted tbl.val q.val w.val _ (by omega) hne
          rw [Nat.add_sub_cancel] at this
          omega
        · -- Party `i` is not in the subset: its entry can only decrease.
          simp only [hsb, ite_false, Nat.add_zero]
          rw [min_original_weight1_post1 _ (by scalar_tac)]
          have := relax_le_old tbl.val q.val w.val (wsum reduced.val s b i.val)
          omega
    · simp only [WP.spec_ok]
      have : i.val = weights.length := by scalar_tac
      rw [← this]
      exact ⟨hlen, h0, hsub⟩
  · exact ⟨hlen, hi, h0, hbound, hsub⟩

@[step]
theorem knapsack_min_original_spec (weights reduced : Slice U16) (reduced_total : U32)
    (hlenr : reduced.length = weights.length)
    (hRT : reduced_total.val = total reduced.val weights.length) (hRT' : reduced_total.val ≤ 65535)
    (hW : total weights.val weights.length ≤ 65535) :
    knapsack_min_original weights reduced reduced_total ⦃ tbl =>
      tbl.length = reduced_total.val + 1 ∧ tbl.val[0]!.val = 0 ∧
      ∀ s b, tbl.val[wsum reduced.val s b weights.length]!.val ≤
        wsum weights.val s b weights.length ⦄ := by
  unfold knapsack_min_original
  simp only [step_simps]
  let* ⟨ i, i_post ⟩ ← UScalar.cast_inBounds_spec
  let* ⟨ i1, i1_post ⟩ ← Usize.add_spec
  let* ⟨ tbl0, tbl0_post, tbl0_post1 ⟩ ← alloc.vec.from_elem_spec
  let* ⟨ _, index_mut_back, _, hback ⟩ ← alloc.vec.Vec.index_mut_usize_spec
  let* ⟨ n, n_post ⟩ ← core.cmp.impls.OrdUsize.min.step_spec
  -- The initial table is `0` at entry `0` and `u32::MAX` elsewhere.
  have hinit0 : (index_mut_back 0#u32).val[0]!.val = 0 := by
    rw [hback, alloc.vec.Vec.set_val_eq]; simp_lists; simp
  have hinit : ∀ u, u ≠ 0 → u < i1.val → (index_mut_back 0#u32).val[u]!.val = U32.max := by
    intro u hu hu'
    rw [hback, alloc.vec.Vec.set_val_eq]
    simp_lists [tbl0_post]
    simp [U32.rMax, U32.max_eq]
  let* ⟨ tbl, tbl_post, tbl_post1, tbl_post2 ⟩ ← knapsack_min_original_loop0_spec
  case hlen => rw [hback]; simp; scalar_tac
  case hbound =>
    intro u hu
    by_cases h : u = 0
    · subst h; right; rw [hinit0]; simp
    · left; exact hinit u h (by rw [hback] at hu; simp at hu; scalar_tac)
  case hsub =>
    intro s b
    have : (0#usize : Usize).val = 0 := rfl
    rw [this, wsum_zero, wsum_zero]; exact hinit0.le
  agrind

/-! ## `verify_reduction` -/

/-- Discharges the preconditions in `verify_reduction`: bounds, and facts about the table seen
through `Vec.deref`. -/
macro "vr_tac" : tactic => `(tactic| first
  | scalar_tac
  | (simp only [deref_val, deref_length] at *; scalar_tac)
  | (simp only [deref_val, deref_length] at *; agrind)
  | (simp [U16.rMax, U32.rMax] at *; scalar_tac)
  | (simp only [deref_val, deref_length] at *; simp_all))

@[step]
theorem to_string_spec {T : Type _} (inst : core.fmt.Display T) (x : T) :
    alloc.string.ToString.Blanket.to_string inst x ⦃ _ => True ⦄ := by
  simp [alloc.string.ToString.Blanket.to_string]

@[simp, scalar_tac_simps]
theorem MAX_PARTIES_val : MAX_PARTIES.val = 1000 := by
  simp [MAX_PARTIES]

@[simp]
theorem deref_val {α : Type _} (v : alloc.vec.Vec α) : (alloc.vec.Vec.deref v).val = v.val := by
  simp [alloc.vec.Vec.deref]

@[simp, scalar_tac_simps]
theorem deref_length {α : Type _} (v : alloc.vec.Vec α) :
    (alloc.vec.Vec.deref v).length = v.length := by
  simp [alloc.vec.Vec.deref]

/-- **Main theorem.** For every input, `verify_reduction` returns without panicking, overflowing
or indexing out of bounds, and if it returns `Ok(())`, then (P), (L1), (L2) and (L3) hold for
every subset of the parties. -/
theorem verify_reduction_spec (weights : Slice U16) (t f delta : U16)
    (reduction : ReducedWeights) :
    verify_reduction weights t f delta reduction ⦃ r =>
      r = .Ok () → ∀ s, ReductionPropertiesHold weights.val t.val f.val delta.val
        reduction.weights.val reduction.t.val reduction.f.val s ⦄ := by
  unfold verify_reduction
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

/-- The main theorem with subsets as `Finset`s: if `verify_reduction` returns `Ok(())`, then for
every set `S` of parties, writing `w(S)` and `w'(S)` for the sums of the original and reduced
weights of the parties in `S`, (P), (L1), (L2) and (L3) hold. -/
theorem verify_reduction_sound_finset (weights : Slice U16) (t f delta : U16)
    (reduction : ReducedWeights) :
    verify_reduction weights t f delta reduction ⦃ r =>
      r = .Ok () → ∀ S : Finset ℕ,
        let n := weights.length
        let w := ∑ i ∈ (Finset.range n).filter (· ∈ S), weights.val[i]!.val
        let w' := ∑ i ∈ (Finset.range n).filter (· ∈ S), reduction.weights.val[i]!.val
        (w < t.val → w' < reduction.t.val) ∧
        (t.val + f.val + delta.val ≤ w → reduction.t.val + reduction.f.val ≤ w') ∧
        (w ≤ f.val → w' ≤ reduction.f.val) ∧
        (t.val + delta.val ≤ w → reduction.t.val ≤ w') ⦄ := by
  apply WP.spec_mono (verify_reduction_spec weights t f delta reduction)
  intro r h hok S
  have := h hok (fun i => decide (i ∈ S))
  simp only [ReductionPropertiesHold, wsum_eq_sum] at this
  exact this

end KnapsackWeightReduction
