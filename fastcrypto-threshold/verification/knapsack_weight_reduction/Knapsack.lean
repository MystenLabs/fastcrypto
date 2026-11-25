-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Generated.Funs
import knapsack_weight_reduction.Spec

/-!
What `sum_u16`, `max_reduced_weight` and `knapsack_min_original` return (`sum_u16_spec`,
`max_reduced_weight_spec`, `knapsack_min_original_spec`): the sum, the largest index whose table
entry is at most the bound, and a table whose entry at the reduced weight of any subset is at
most its original weight.
-/

open Aeneas Aeneas.Std Result ControlFlow

namespace WeightReductionProofs
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

set_option maxHeartbeats 2000000

-- Reason about casts as exact, with a proof obligation that the value fits, instead of modulo.
attribute [-step] UScalar.cast.step_spec
attribute [step] UScalar.cast_inBounds_spec


/-- `l[i]!` is `l[i]` within bounds. -/
lemma getElem!_of_lt {α : Type _} [Inhabited α] (l : List α) (i : ℕ) (h : i < l.length) :
    l[i]! = l[i] := getElem!_pos l i h

/-! ## Range iterators -/

@[step]
lemma rev_spec (r : core.ops.range.Range Usize) :
    core.iter.traits.iterator.Iterator.rev.trait_default
      (core.iter.traits.iterator.IteratorRange core.iter.range.StepUsize)
      (core.ops.range.Range.Insts.DoubleEndedIterator core.iter.range.StepUsize) r
    ⦃ it => it = ⟨r⟩ ⦄ := by
  simp [core.iter.traits.iterator.Iterator.rev.trait_default,
    core.iter.traits.iterator.Iterator.rev.default]

/-- `next` on `(start..end).rev()` yields `end - 1` and decrements `end`, while `start < end`. -/
@[step]
lemma rev_next_spec (it : core.iter.adapters.rev.Rev (core.ops.range.Range Usize)) :
    core.iter.adapters.rev.Rev.Insts.CoreIterTraitsIteratorIterator.next
      (core.ops.range.Range.Insts.DoubleEndedIterator core.iter.range.StepUsize) it
    ⦃ o it' =>
      (if it.iter.start.val < it.iter.end.val then
        ∃ e : Usize, e.val + 1 = it.iter.end.val ∧ o = some e ∧ it'.iter.end = e
      else o = none ∧ it'.iter.end = it.iter.end) ∧
      it'.iter.start = it.iter.start ⦄ := by
  rcases it with ⟨⟨s, e⟩⟩
  simp only [core.iter.adapters.rev.Rev.Insts.CoreIterTraitsIteratorIterator.next,
    core.ops.range.Range.Insts.CoreIterTraitsDoubleEndedIterator.next_back,
    core.iter.range.StepUsize, core.iter.range.UScalarStep,
    core.iter.range.UScalarStep.backward_checked]
  by_cases h : s.val < e.val
  · have h1 : 1 ≤ e.val := by scalar_tac
    simp [core.cmp.impls.PartialOrdUsize.lt, h, h1, UScalar.ofNatCore_val_eq]
  · simp [core.cmp.impls.PartialOrdUsize.lt, h]

/-! ## `sum_u16` -/

@[step]
lemma sum_u16_loop_spec (values : Slice U16) (iter : core.slice.iter.Iter U16) (sum : U32)
    (hlen : values.length ≤ 65537) (hs : iter.slice = values) (hi : iter.i ≤ values.length)
    (hsum : sum.val = total values.val iter.i) :
    sum_u16_loop iter sum ⦃ r => r.val = total values.val values.length ⦄ := by
  unfold sum_u16_loop
  apply loop.spec_decr_nat
    (measure := fun (x : core.slice.iter.Iter U16 × U32) => values.length - x.1.i)
    (inv := fun (x : core.slice.iter.Iter U16 × U32) => x.1.slice = values ∧
      x.1.i ≤ values.length ∧ x.2.val = total values.val x.1.i)
  · rintro ⟨it, sum⟩ ⟨hs, hi, hsum⟩
    unfold sum_u16_loop.body core.slice.iter.IteratorSliceIter.next
    simp only at hs hi hsum ⊢
    subst hs
    split
    · rename_i hlt
      have hle := total_le it.slice.val it.i
      simp only [bind_ok]
      step*
      refine ⟨by scalar_tac, ?_, by scalar_tac⟩
      rw [total_succ, getElem!_of_lt _ _ (by scalar_tac), sum1_post, i_post, hsum]
      rfl
    · have : it.i = it.slice.length := by scalar_tac
      simp [WP.spec_ok, hsum, this]
  · exact ⟨hs, hi, hsum⟩

@[step]
lemma sum_u16_spec (values : Slice U16) (hlen : values.length ≤ 65537) :
    sum_u16 values ⦃ r => r.val = total values.val values.length ⦄ := by
  unfold sum_u16
  step*
  simp [iter_post]

/-! ## `max_reduced_weight`

The loop's `fail panic` once the iterator is empty is the translation of the `panic!` after the
loop, so proving that the loop never fails proves that the panic is unreachable. -/

@[step]
lemma max_reduced_weight_loop_spec (tbl : Slice U32) (weight : U32)
    (iter : core.iter.adapters.rev.Rev (core.ops.range.Range Usize))
    (hlen : 1 ≤ tbl.length) (hlen' : tbl.length ≤ 65536) (h0 : tbl.val[0]!.val = 0)
    (hs : iter.iter.start.val = 0) (hv : iter.iter.end.val ≤ tbl.length)
    (habove : ∀ u, iter.iter.end.val ≤ u → u < tbl.length → weight.val < tbl.val[u]!.val) :
    max_reduced_weight_loop iter tbl weight ⦃ r =>
      r.val < tbl.length ∧ tbl.val[r.val]!.val ≤ weight.val ∧
      ∀ u, u < tbl.length → tbl.val[u]!.val ≤ weight.val → u ≤ r.val ⦄ := by
  unfold max_reduced_weight_loop
  apply loop.spec_decr_nat
    (measure := fun (it : core.iter.adapters.rev.Rev (core.ops.range.Range Usize)) =>
      it.iter.end.val)
    (inv := fun (it : core.iter.adapters.rev.Rev (core.ops.range.Range Usize)) =>
      it.iter.start.val = 0 ∧ it.iter.end.val ≤ tbl.length ∧
      ∀ u, it.iter.end.val ≤ u → u < tbl.length → weight.val < tbl.val[u]!.val)
  · rintro it ⟨hs, hv, habove⟩
    unfold max_reduced_weight_loop.body
    have hpos : 0 < it.iter.end.val := by
      by_contra h
      have := habove 0 (by omega) (by omega)
      omega
    let* ⟨ o, it1, ho, hs1 ⟩ ← rev_next_spec
    simp only [hs, hpos, ↓reduceIte] at ho
    obtain ⟨v1, hv1, rfl, hend1⟩ := ho
    simp only
    step*
    · -- The early return: entry `v1` is within the bound, and the entries above it are not.
      refine ⟨by scalar_tac, ?_, ?_⟩
      · rw [i1_post, getElem!_of_lt _ _ (by scalar_tac), ← i_post]; scalar_tac
      · intro u hu hu'
        by_contra hlt
        have := habove u (by omega) hu
        omega
    -- The case that keeps going.
    refine ⟨by rw [hs1]; exact hs, by scalar_tac, ?_, by scalar_tac⟩
    intro u hu hu'
    rw [hend1] at hu
    by_cases h : u = v1.val
    · subst h
      rw [getElem!_of_lt _ _ (by scalar_tac), ← i_post]
      scalar_tac
    · exact habove u (by omega) hu'
  · exact ⟨hs, hv, habove⟩

@[step]
lemma max_reduced_weight_spec (tbl : Slice U32) (weight : U32)
    (hlen : 1 ≤ tbl.length) (hlen' : tbl.length ≤ 65536) (h0 : tbl.val[0]!.val = 0) :
    max_reduced_weight tbl weight ⦃ r =>
      r.val < tbl.length ∧ tbl.val[r.val]!.val ≤ weight.val ∧
      ∀ u, u < tbl.length → tbl.val[u]!.val ≤ weight.val → u ≤ r.val ⦄ := by
  unfold max_reduced_weight
  step*

/-! ## `knapsack_min_original` -/

/-- Each reduced weight is at most the original one. -/
def Dominated (weights reduced : Slice U16) : Prop :=
  ∀ j < weights.length, reduced.val[j]!.val ≤ weights.val[j]!.val

/-- The inner loop, which relaxes the table with one party, iterating `v` downward over
`(q..end).rev()`. Entries below `end` still hold their old value, and entries from `end` on hold
the relaxed one. -/
lemma knapsack_min_original_loop0_loop0_spec
    (old : List U32) (tbl : alloc.vec.Vec U32) (w : U32) (q : Usize)
    (iter : core.iter.adapters.rev.Rev (core.ops.range.Range Usize))
    (hlen : tbl.length = old.length) (hs : iter.iter.start = q)
    (hq : q.val ≤ iter.iter.end.val) (hv : iter.iter.end.val ≤ old.length)
    (hfits : ∀ u < old.length, old[u]!.val ≠ U32.max → old[u]!.val + w.val ≤ U32.max)
    (hbelow : ∀ u < iter.iter.end.val, tbl.val[u]! = old[u]!)
    (habove : ∀ u, iter.iter.end.val ≤ u → u < old.length →
      tbl.val[u]!.val = relax old q.val w.val u) :
    knapsack_min_original_loop0_loop0 iter tbl w q ⦃ tbl' =>
      tbl'.length = old.length ∧
      ∀ u < old.length, tbl'.val[u]!.val = relax old q.val w.val u ⦄ := by
  unfold knapsack_min_original_loop0_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : core.iter.adapters.rev.Rev (core.ops.range.Range Usize) ×
      alloc.vec.Vec U32) => x.1.iter.end.val)
    (inv := fun (x : core.iter.adapters.rev.Rev (core.ops.range.Range Usize) ×
        alloc.vec.Vec U32) =>
      x.2.length = old.length ∧ x.1.iter.start = q ∧ q.val ≤ x.1.iter.end.val ∧
      x.1.iter.end.val ≤ old.length ∧
      (∀ u < x.1.iter.end.val, x.2.val[u]! = old[u]!) ∧
      (∀ u, x.1.iter.end.val ≤ u → u < old.length → x.2.val[u]!.val = relax old q.val w.val u))
  · rintro ⟨it, tbl⟩ ⟨hlen, hs, hq, hv, hbelow, habove⟩
    unfold knapsack_min_original_loop0_loop0.body
    simp only at hlen hs hq hv hbelow habove ⊢
    let* ⟨ o, it1, ho, hs1 ⟩ ← rev_next_spec
    split_ifs at ho with hlt
    · obtain ⟨v1, hv1, rfl, hend1⟩ := ho
      obtain ⟨⟨s1, e1⟩⟩ := it1
      simp only at hend1 hs1
      subst e1 s1
      simp only [step_simps]
      rw [hs] at hlt
      let* ⟨ i, i_post, i_post1 ⟩ ← Usize.sub_spec
      let* ⟨ i1, i1_post ⟩ ← alloc.vec.Vec.index_usize_spec
      -- Entry `i = v1 - q` is below `end`, so it still holds its old value, and so does `v1`.
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
          refine ⟨by simp [hlen], by simpa using hs, by scalar_tac, by scalar_tac, ?_, ?_, by scalar_tac⟩
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
          refine ⟨hlen, by simpa using hs, by scalar_tac, by scalar_tac,
            fun u hu => hbelow u (by scalar_tac), ?_,
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
        refine ⟨hlen, by simpa using hs, by scalar_tac, by scalar_tac,
            fun u hu => hbelow u (by scalar_tac), ?_,
          by scalar_tac⟩
        intro u hu hu'
        by_cases h : u = v1.val
        · subst h
          rw [hrelax, ite_eq_right (by simp [heq]), htv1]
        · exact hrest u hu hu' h
    · -- The loop exits with `end = q`: entries below `q` are not relaxed at all.
      obtain ⟨rfl, hend1⟩ := ho
      rw [hs] at hlt
      simp only [WP.spec_ok]
      refine ⟨hlen, fun u hu => ?_⟩
      by_cases h : u < it.iter.end.val
      · rw [hbelow u h]; unfold relax; rw [ite_eq_right (by scalar_tac)]
      · exact habove u (by scalar_tac) hu
  · exact ⟨hlen, hs, hq, hv, hbelow, habove⟩

/-- The inner loop as `knapsack_min_original` calls it: over `(q..tbl.len()).rev()`. -/
@[step]
lemma knapsack_min_original_loop0_loop0_full_spec
    (tbl : alloc.vec.Vec U32) (w : U32) (q v : Usize)
    (hv : v.val = tbl.length) (hq : q.val ≤ v.val)
    (hfits : ∀ u < tbl.length, tbl.val[u]!.val ≠ U32.max → tbl.val[u]!.val + w.val ≤ U32.max) :
    knapsack_min_original_loop0_loop0 ⟨{ start := q, «end» := v }⟩ tbl w q ⦃ tbl' =>
      tbl'.length = tbl.length ∧
      ∀ u < tbl.length, tbl'.val[u]!.val = relax tbl.val q.val w.val u ⦄ :=
  knapsack_min_original_loop0_loop0_spec tbl.val tbl w q _ rfl rfl hq (by scalar_tac)
    (by simpa using hfits) (fun _ _ => rfl) (fun u hu hu' => by scalar_tac)

/-- The outer loop: after processing the first `i` parties, the entry at the reduced weight of
any subset of them is at most its original weight. -/
@[step]
lemma knapsack_min_original_loop0_spec
    (weights reduced : Slice U16) (tbl : alloc.vec.Vec U32) (iter : core.ops.range.Range Usize)
    (RT : ℕ) (hn : iter.end.val = weights.length) (hlenr : reduced.length = weights.length)
    (hRT : RT = total reduced.val weights.length) (hW : total weights.val weights.length ≤ 65535)
    (hlen : tbl.length = RT + 1) (hi : iter.start.val ≤ weights.length)
    (h0 : tbl.val[0]!.val = 0)
    (hbound : ∀ u < tbl.length,
      tbl.val[u]!.val = U32.max ∨ tbl.val[u]!.val ≤ total weights.val iter.start.val)
    (hsub : ∀ s b, tbl.val[wsum reduced.val s b iter.start.val]!.val ≤
      wsum weights.val s b iter.start.val)
    (hlow : Dominated weights reduced → ∀ u < tbl.length,
      tbl.val[u]!.val = U32.max ∨ u ≤ tbl.val[u]!.val) :
    knapsack_min_original_loop0 iter weights reduced tbl ⦃ tbl' =>
      tbl'.length = RT + 1 ∧ tbl'.val[0]!.val = 0 ∧
      (∀ s b, tbl'.val[wsum reduced.val s b weights.length]!.val ≤
        wsum weights.val s b weights.length) ∧
      (Dominated weights reduced → ∀ u < tbl'.length,
        tbl'.val[u]!.val = U32.max ∨ u ≤ tbl'.val[u]!.val) ⦄ := by
  unfold knapsack_min_original_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : core.ops.range.Range Usize × alloc.vec.Vec U32) =>
      weights.length - x.1.start.val)
    (inv := fun (x : core.ops.range.Range Usize × alloc.vec.Vec U32) =>
      x.1.end.val = weights.length ∧
      x.2.length = RT + 1 ∧ x.1.start.val ≤ weights.length ∧ x.2.val[0]!.val = 0 ∧
      (∀ u < x.2.length,
        x.2.val[u]!.val = U32.max ∨ x.2.val[u]!.val ≤ total weights.val x.1.start.val) ∧
      (∀ s b, x.2.val[wsum reduced.val s b x.1.start.val]!.val ≤
        wsum weights.val s b x.1.start.val) ∧
      (Dominated weights reduced → ∀ u < x.2.length,
        x.2.val[u]!.val = U32.max ∨ u ≤ x.2.val[u]!.val))
  · rintro ⟨it, tbl⟩ ⟨hn, hlen, hi, h0, hbound, hsub, hlow⟩
    unfold knapsack_min_original_loop0.body
    simp only at hn hlen hi h0 hbound hsub hlow ⊢
    let* ⟨ o, it1, ho, hend1 ⟩ ← core.iter.range.IteratorRange.next_Usize_spec
    split_ifs at ho with hlt
    · obtain ⟨rfl, hstart1⟩ := ho
      simp only
      generalize it.start = i at *
      have hi' : i.val < weights.length := by scalar_tac
      have hir : i.val < reduced.length := by scalar_tac
      -- The totals of the first `i + 1` parties are at most the totals of all of them.
      have hWi := total_mono weights.val (show i.val + 1 ≤ weights.length by omega)
      have hRi := total_mono reduced.val (show i.val + 1 ≤ weights.length by omega)
      rw [total_succ] at hWi hRi
      rw [getElem!_of_lt _ _ (by scalar_tac)] at hWi
      rw [getElem!_of_lt _ _ (by scalar_tac)] at hRi
      step*
      subst iter2_post
      step*
      have hw : w.val = weights.val[i.val]!.val := by
        rw [getElem!_of_lt _ _ hi', w_post, i1_post]
      have hq : q.val = reduced.val[i.val]!.val := by
        rw [getElem!_of_lt _ _ hir, q_post, i2_post]
      rw [← getElem!_of_lt _ _ hi', ← hw] at hWi
      rw [← getElem!_of_lt _ _ hir, ← hq] at hRi
      refine ⟨by rw [hend1]; exact hn, by scalar_tac, by scalar_tac, ?_, ?_, ?_, ?_, by scalar_tac⟩
      · -- Entry 0 stays 0.
        have := min_original_weight1_post1 0 (by scalar_tac)
        have := relax_le_old tbl.val q.val w.val 0
        omega
      · -- Every entry is still `u32::MAX` or at most the total original weight.
        intro u hu
        rw [min_original_weight1_post1 u (by scalar_tac), hstart1, total_succ, ← hw]
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
        rw [hstart1, wsum_succ, wsum_succ, ← hw, ← hq]
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
      · -- If each reduced weight is at most the original one, so is every finite entry.
        intro hd u hu
        rw [min_original_weight1_post1 u (by scalar_tac)]
        rcases relax_cases tbl.val q.val w.val u with h | ⟨hqu, hne, h⟩
        · rw [h]; exact hlow hd u (by scalar_tac)
        · rw [h]
          rcases hlow hd (u - q.val) (by scalar_tac) with h' | h'
          · exact absurd h' hne
          · have := hd i.val hi'
            right; omega
    · obtain ⟨rfl, hstart1⟩ := ho
      simp only [WP.spec_ok]
      have : it.start.val = weights.length := by scalar_tac
      rw [← this]
      exact ⟨hlen, h0, hsub, hlow⟩
  · exact ⟨hn, hlen, hi, h0, hbound, hsub, hlow⟩

@[step]
lemma knapsack_min_original_spec (weights reduced : Slice U16) (reduced_total : U32)
    (hlenr : reduced.length = weights.length)
    (hRT : reduced_total.val = total reduced.val weights.length) (hRT' : reduced_total.val ≤ 65535)
    (hW : total weights.val weights.length ≤ 65535) :
    knapsack_min_original weights reduced reduced_total ⦃ tbl =>
      tbl.length = reduced_total.val + 1 ∧ tbl.val[0]!.val = 0 ∧
      (∀ s b, tbl.val[wsum reduced.val s b weights.length]!.val ≤
        wsum weights.val s b weights.length) ∧
      (Dominated weights reduced → ∀ u < tbl.length,
        tbl.val[u]!.val = U32.max ∨ u ≤ tbl.val[u]!.val) ⦄ := by
  unfold knapsack_min_original
  simp only [step_simps]
  let* ⟨ i, i_post ⟩ ← UScalar.cast_inBounds_spec
  let* ⟨ i1, i1_post ⟩ ← Usize.add_spec
  let* ⟨ tbl0, tbl0_post, tbl0_post1 ⟩ ← alloc.vec.from_elem_spec
  let* ⟨ _, index_mut_back, _, hback ⟩ ← alloc.vec.Vec.index_mut_usize_spec
  step
  -- The initial table is `0` at entry `0` and `u32::MAX` elsewhere.
  have hinit0 : (index_mut_back 0#u32).val[0]!.val = 0 := by
    rw [hback, alloc.vec.Vec.set_val_eq]; simp_lists; simp
  have hinit : ∀ u, u ≠ 0 → u < i1.val → (index_mut_back 0#u32).val[u]!.val = U32.max := by
    intro u hu hu'
    rw [hback, alloc.vec.Vec.set_val_eq]
    simp_lists [tbl0_post]
    simp [U32.rMax, U32.max_eq]
  let* ⟨ tbl, tbl_post, tbl_post1, tbl_post2, tbl_post3 ⟩ ← knapsack_min_original_loop0_spec
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
  case hlow =>
    intro _ u hu
    by_cases h : u = 0
    · subst h; right; rw [hinit0]
    · left; exact hinit u h (by rw [hback] at hu; simp at hu; scalar_tac)
  exact ⟨by scalar_tac, tbl_post1, tbl_post2, tbl_post3⟩

end WeightReductionProofs
