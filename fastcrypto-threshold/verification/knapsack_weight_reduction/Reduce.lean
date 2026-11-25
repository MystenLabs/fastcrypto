-- THIS FILE IS AI-ONLY
import knapsack_weight_reduction.Verify

/-!
What `reduce_weights` returns (`reduce_weights_spec`): under `ToStringReturns` and
`SortByPermutes`, it returns, and every reduction it returns passes `verify_reduction`. It
returns either the original weights, which pass by `identity_passes`, or a candidate that
`check_candidate` accepted, which passes by `check_candidate_spec`.
-/

open Aeneas Aeneas.Std Result ControlFlow

namespace WeightReductionProofs
open fastcrypto_threshold fastcrypto_threshold.knapsack_weight_reduction

set_option maxHeartbeats 4000000

/-- `verify_reduction(weights, t, f, delta, c)` returns `Ok(())`. -/
def Passes (weights : Slice U16) (t f delta : U16) (c : ReducedWeights) : Prop :=
  verify_reduction weights t f delta c = ok (.Ok ())

/-! ## Slice iterators -/

/-- `next` on a slice iterator yields the element at its index and advances, while the index is
in bounds. -/
@[step]
lemma slice_iter_next_spec {T : Type _} [Inhabited T] (it : core.slice.iter.Iter T) :
    core.slice.iter.IteratorSliceIter.next it ⦃ o it' =>
      (if it.i < it.slice.length then o = some it.slice.val[it.i]! ∧ it'.i = it.i + 1
       else o = none ∧ it'.i = it.i) ∧ it'.slice = it.slice ⦄ := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · rename_i h
    have h' : it.i < it.slice.length := by scalar_tac
    simp [h']
    rfl
  · rename_i h
    have h' : ¬ it.i < it.slice.length := by scalar_tac
    simp [h']

/-- `next` on `slice.iter().enumerate()` yields the index and the element at it, and advances,
while the index is in bounds. -/
@[step]
lemma enumerate_slice_next_spec {T : Type _} [Inhabited T]
    (e : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter T))
    (hc : e.count.val = e.iter.i) :
    core.iter.adapters.enumerate.IteratorEnumerate.next
      (core.iter.traits.iterator.IteratorSliceIter T) e ⦃ o e' =>
      (if e.iter.i < e.iter.slice.length then
         o = some (e.count, e.iter.slice.val[e.iter.i]!) ∧ e'.iter.i = e.iter.i + 1 ∧
           e'.count.val = e.count.val + 1
       else o = none ∧ e'.iter.i = e.iter.i ∧ e'.count = e.count) ∧
      e'.iter.slice = e.iter.slice ⦄ := by
  unfold core.iter.adapters.enumerate.IteratorEnumerate.next
  let* ⟨ o, it', ho, hs' ⟩ ← slice_iter_next_spec
  split_ifs at ho with h
  · obtain ⟨rfl, hi⟩ := ho
    simp only
    step*
  · obtain ⟨rfl, hi⟩ := ho
    simp [WP.spec_ok, h, hi, hs']

/-! ## `any_above` -/

@[step]
lemma any_above_loop_spec (values : Slice U16) (bound : U16) (iter : core.slice.iter.Iter U16)
    (hs : iter.slice = values) (hi : iter.i ≤ values.length)
    (hbelow : ∀ j < iter.i, values.val[j]!.val ≤ bound.val) :
    any_above_loop iter bound ⦃ b =>
      b = false → ∀ j < values.length, values.val[j]!.val ≤ bound.val ⦄ := by
  unfold any_above_loop
  apply loop.spec_decr_nat
    (measure := fun (it : core.slice.iter.Iter U16) => values.length - it.i)
    (inv := fun (it : core.slice.iter.Iter U16) => it.slice = values ∧ it.i ≤ values.length ∧
      ∀ j < it.i, values.val[j]!.val ≤ bound.val)
  · rintro it ⟨hs, hi, hbelow⟩
    unfold any_above_loop.body
    let* ⟨ o, it1, ho, hs1 ⟩ ← slice_iter_next_spec
    split_ifs at ho with hlt
    · obtain ⟨rfl, hi1⟩ := ho
      simp only
      split
      · simp [WP.spec_ok]
      · rename_i hle
        simp only [WP.spec_ok]
        refine ⟨by rw [hs1, hs], by scalar_tac, fun j hj => ?_, by scalar_tac⟩
        by_cases h : j = it.i
        · subst h hs; scalar_tac
        · exact hbelow j (by omega)
    · obtain ⟨rfl, hi1⟩ := ho
      simp only [WP.spec_ok]
      intro _ j hj
      exact hbelow j (by subst hs; scalar_tac)
  · exact ⟨hs, hi, hbelow⟩

@[step]
lemma any_above_spec (values : Slice U16) (bound : U16) :
    any_above values bound ⦃ b =>
      b = false → ∀ j < values.length, values.val[j]!.val ≤ bound.val ⦄ := by
  unfold any_above
  step*

/-! ## `reduce_weight` -/

@[step]
lemma reduce_weight_spec (w : U16) (d : U32) (offset : U64) (hd : 0 < d.val)
    (ho : offset.val < 100) :
    reduce_weight w d offset ⦃ _ => True ⦄ := by
  unfold reduce_weight
  have : offset.val * d.val ≤ 99 * U32.max := Nat.mul_le_mul (by omega) (by scalar_tac)
  step*

/-! ## `greedy_reject` -/

@[step]
lemma greedy_reduced_weight_loop_spec (weights reduced : Slice U16) (order : Slice Usize)
    (iter : core.slice.iter.Iter Usize) (rem rw : U32) (hlen : order.length ≤ 1000)
    (hin : ∀ x ∈ order.val, x.val < weights.length ∧ x.val < reduced.length)
    (hs : iter.slice = order) (hi : iter.i ≤ order.length) (hrw : rw.val ≤ 65535 * iter.i) :
    greedy_reduced_weight_loop iter weights reduced rem rw ⦃ r =>
      r.val ≤ 65535 * order.length ⦄ := by
  unfold greedy_reduced_weight_loop
  apply loop.spec_decr_nat
    (measure := fun (x : core.slice.iter.Iter Usize × U32 × U32) => order.length - x.1.i)
    (inv := fun (x : core.slice.iter.Iter Usize × U32 × U32) => x.1.slice = order ∧
      x.1.i ≤ order.length ∧ x.2.2.val ≤ 65535 * x.1.i)
  · rintro ⟨it, rem, rw⟩ ⟨hs, hi, hrw⟩
    unfold greedy_reduced_weight_loop.body
    simp only at hs hi hrw ⊢
    let* ⟨ o, it1, ho, hs1 ⟩ ← slice_iter_next_spec
    split_ifs at ho with hlt
    · obtain ⟨rfl, hi1⟩ := ho
      have hmem : it.slice.val[it.i]! ∈ order.val := by
        rw [← hs, getElem!_of_lt _ _ (by scalar_tac)]; exact List.getElem_mem _
      have := hin _ hmem
      subst hs
      simp only
      step*
      all_goals exact ⟨hs1, by scalar_tac, by scalar_tac, by scalar_tac⟩
    · obtain ⟨rfl, hi1⟩ := ho
      simp only [WP.spec_ok]
      subst hs
      have : it.i = it.slice.length := by scalar_tac
      rw [← this]; exact hrw
  · exact ⟨hs, hi, hrw⟩

@[step]
lemma greedy_reduced_weight_spec (weights reduced : Slice U16) (order : Slice Usize) (b : U32)
    (hlen : order.length ≤ 1000)
    (hin : ∀ x ∈ order.val, x.val < weights.length ∧ x.val < reduced.length) :
    greedy_reduced_weight weights reduced order b ⦃ r => r.val ≤ 65535 * 1000 ⦄ := by
  unfold greedy_reduced_weight
  step*

@[step]
lemma greedy_reject_loop_spec (reduced : Slice U16)
    (iter : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter U16))
    (bd : alloc.vec.Vec Usize) (hn : reduced.length ≤ 1000) (hs : iter.iter.slice = reduced)
    (hi : iter.iter.i ≤ reduced.length) (hc : iter.count.val = iter.iter.i)
    (hlen : bd.length ≤ iter.iter.i)
    (hin : ∀ x ∈ bd.val, x.val < iter.iter.i ∧ 0 < reduced.val[x.val]!.val) :
    greedy_reject_loop iter bd ⦃ bd' => bd'.length ≤ reduced.length ∧
      ∀ x ∈ bd'.val, x.val < reduced.length ∧ 0 < reduced.val[x.val]!.val ⦄ := by
  unfold greedy_reject_loop
  apply loop.spec_decr_nat
    (measure := fun (x : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter U16) ×
      alloc.vec.Vec Usize) => reduced.length - x.1.iter.i)
    (inv := fun (x : core.iter.adapters.enumerate.Enumerate (core.slice.iter.Iter U16) ×
        alloc.vec.Vec Usize) =>
      x.1.iter.slice = reduced ∧ x.1.iter.i ≤ reduced.length ∧ x.1.count.val = x.1.iter.i ∧
      x.2.length ≤ x.1.iter.i ∧
      ∀ y ∈ x.2.val, y.val < x.1.iter.i ∧ 0 < reduced.val[y.val]!.val)
  · rintro ⟨e, bd⟩ ⟨hs, hi, hc, hlen, hin⟩
    unfold greedy_reject_loop.body
    simp only at hs hi hc hlen hin ⊢
    let* ⟨ o, e1, ho, hs1 ⟩ ← enumerate_slice_next_spec
    split_ifs at ho with hlt
    · obtain ⟨rfl, hi1, hc1⟩ := ho
      subst hs
      simp only
      step*
      · refine ⟨hs1, by scalar_tac, by scalar_tac, by simp; scalar_tac, ?_, by scalar_tac⟩
        intro y hy
        rw [by_density1_post] at hy
        rcases List.mem_append.mp hy with hy | hy
        · have := hin y hy; exact ⟨by omega, this.2⟩
        · simp only [List.mem_singleton] at hy
          subst hy
          exact ⟨by scalar_tac, by scalar_tac⟩
      · refine ⟨hs1, by scalar_tac, by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        intro y hy
        have := hin y hy; exact ⟨by omega, this.2⟩
    · obtain ⟨rfl, hi1, hc1⟩ := ho
      simp only [WP.spec_ok]
      subst hs
      exact ⟨by omega, fun y hy => ⟨by have := hin y hy; scalar_tac, (hin y hy).2⟩⟩
  · exact ⟨hs, hi, hc, hlen, hin⟩

/-- The comparator of `greedy_reject` on the parties `a` and `b`: `reduced[b] * weights[a]`
compared with `reduced[a] * weights[b]`, which orders the parties by reduced weight per original
weight, densest first. -/
def densityCmp (reduced weights : Slice U16) (a b : Usize) : Ordering :=
  compare (reduced.val[b.val]!.val * weights.val[a.val]!.val)
    (reduced.val[a.val]!.val * weights.val[b.val]!.val)

lemma compare_swap_nat (x y : ℕ) : compare y x = (compare x y).swap := by
  rcases lt_trichotomy x y with h | h | h
  · rw [compare_gt_iff_gt.mpr h, compare_lt_iff_lt.mpr h]; rfl
  · subst h; rw [compare_eq_iff_eq.mpr rfl]; rfl
  · rw [compare_lt_iff_lt.mpr h, compare_gt_iff_gt.mpr h]; rfl

lemma compare_ne_gt_iff (x y : ℕ) : compare x y ≠ .gt ↔ x ≤ y := by
  rw [Ne, compare_gt_iff_gt]; omega

/-- The comparator of `greedy_reject` returns `densityCmp` on parties that are in bounds. -/
lemma greedy_comparator_call (reduced weights : Slice U16) (a b : Usize)
    (ha : a.val < reduced.length ∧ a.val < weights.length)
    (hb : b.val < reduced.length ∧ b.val < weights.length) :
    greedy_reject.closure.Insts.CoreOpsFunctionFnMutPairShared2UsizeShared3UsizeOrdering.call_mut
      (reduced, weights) (a, b) = ok (densityCmp reduced weights a b, (reduced, weights)) := by
  have h : greedy_reject.closure.Insts.CoreOpsFunctionFnMutPairShared2UsizeShared3UsizeOrdering.call_mut
      (reduced, weights) (a, b) ⦃ r => r = (densityCmp reduced weights a b, (reduced, weights)) ⦄ := by
    unfold greedy_reject.closure.Insts.CoreOpsFunctionFnMutPairShared2UsizeShared3UsizeOrdering.call_mut
    have h1 : reduced.val[b.val]!.val * weights.val[a.val]!.val ≤ 65535 * 65535 :=
      Nat.mul_le_mul (by scalar_tac) (by scalar_tac)
    have h2 : reduced.val[a.val]!.val * weights.val[b.val]!.val ≤ 65535 * 65535 :=
      Nat.mul_le_mul (by scalar_tac) (by scalar_tac)
    step*
    simp only [lift, bind_ok, WP.spec_ok, densityCmp]
    rw [getElem!_of_lt reduced.val b.val (by scalar_tac),
      getElem!_of_lt weights.val a.val (by scalar_tac),
      getElem!_of_lt reduced.val a.val (by scalar_tac),
      getElem!_of_lt weights.val b.val (by scalar_tac)]
    simp [core.cmp.impls.OrdU32.cmp, i4_post, i9_post, i1_post, i3_post, i6_post, i8_post,
      i_post, i2_post, i5_post, i7_post]
    rfl
  obtain ⟨r, hr, rfl⟩ := spec_eq_ok h
  exact hr

/-- The comparator of `greedy_reject` is a total order on parties that are in bounds and have a
positive reduced weight. -/
lemma greedy_comparator_total (reduced weights : Slice U16) (xs : List Usize)
    (h : ∀ i ∈ xs, i.val < reduced.length ∧ i.val < weights.length ∧
      0 < reduced.val[i.val]!.val) :
    TotalOrderOn
      greedy_reject.closure.Insts.CoreOpsFunctionFnMutPairShared2UsizeShared3UsizeOrdering
      (reduced, weights) xs := by
  refine ⟨densityCmp reduced weights, fun a ha b hb => ?_, fun a _ b _ => ?_,
    fun a _ b hb c _ hab hbc => ?_⟩
  · exact greedy_comparator_call reduced weights a b ⟨(h a ha).1, (h a ha).2.1⟩
      ⟨(h b hb).1, (h b hb).2.1⟩
  · exact compare_swap_nat _ _
  · simp only [densityCmp, compare_ne_gt_iff] at hab hbc ⊢
    -- With `ra = reduced[a]`, `wa = weights[a]` and so on: from `rb wa ≤ ra wb` and
    -- `rc wb ≤ rb wc`, `rb (rc wa) ≤ rb (ra wc)`, and `rb > 0`.
    have hrb := (h b hb).2.2
    refine Nat.le_of_mul_le_mul_left ?_ hrb
    calc reduced.val[b.val]!.val * (reduced.val[c.val]!.val * weights.val[a.val]!.val)
        = reduced.val[c.val]!.val * (reduced.val[b.val]!.val * weights.val[a.val]!.val) := by
          ring
      _ ≤ reduced.val[c.val]!.val * (reduced.val[a.val]!.val * weights.val[b.val]!.val) :=
          Nat.mul_le_mul_left _ hab
      _ = reduced.val[a.val]!.val * (reduced.val[c.val]!.val * weights.val[b.val]!.val) := by
          ring
      _ ≤ reduced.val[a.val]!.val * (reduced.val[b.val]!.val * weights.val[c.val]!.val) :=
          Nat.mul_le_mul_left _ hbc
      _ = reduced.val[b.val]!.val * (reduced.val[a.val]!.val * weights.val[c.val]!.val) := by
          ring

@[step]
lemma greedy_reject_closure_1_spec (weights reduced : Slice U16) (v : alloc.vec.Vec Usize)
    (b : U32) (hlen : v.length ≤ 1000)
    (hin : ∀ x ∈ v.val, x.val < weights.length ∧ x.val < reduced.length) :
    greedy_reject.closure_1.Insts.CoreOpsFunctionFnTupleU32U32.call (weights, reduced, v) b
      ⦃ r => r.val ≤ 65535 * 1000 ⦄ := by
  unfold greedy_reject.closure_1.Insts.CoreOpsFunctionFnTupleU32U32.call
  step*
  simpa using hin

@[step]
lemma greedy_reject_spec (hsort : SortByPermutes) (weights reduced : Slice U16)
    (w_total t f delta : U16) (reduced_total : U32)
    (hn : weights.length ≤ 1000) (hlenr : reduced.length = weights.length)
    (ht : 1 ≤ t.val) (htfd : t.val + f.val + delta.val ≤ w_total.val) :
    greedy_reject weights reduced w_total t f delta reduced_total ⦃ _ => True ⦄ := by
  unfold greedy_reject
  have hs : ∀ s : Slice Usize, (∀ i ∈ s.val, i.val < reduced.length ∧ i.val < weights.length ∧
      0 < reduced.val[i.val]!.val) →
      alloc.slice.Slice.sort_by
        greedy_reject.closure.Insts.CoreOpsFunctionFnMutPairShared2UsizeShared3UsizeOrdering
        s (reduced, weights) ⦃ s' => s'.val.Perm s.val ⦄ := by
    intro s h
    obtain ⟨s', h1, h2⟩ := hsort
      greedy_reject.closure.Insts.CoreOpsFunctionFnMutPairShared2UsizeShared3UsizeOrdering s
      ((reduced, weights) : greedy_reject.closure) (greedy_comparator_total reduced weights s.val h)
    rw [h1]; simpa using h2
  simp only [core.slice.Slice.iter, core.iter.traits.iterator.Iterator.enumerate.trait_default,
    core.iter.traits.iterator.Iterator.enumerate.default, bind_ok]
  let* ⟨ bd, hbd_len, hbd_in ⟩ ← greedy_reject_loop_spec reduced
  · simp
  simp only [alloc.vec.Vec.deref_mut, lift, bind_ok]
  let* ⟨ s1, hperm ⟩ ← hs
  · intro i hi
    have := hbd_in i hi
    exact ⟨this.1, by omega, this.2⟩
  have hlen1 : (({ slice := s1 } : alloc.vec.Vec Usize)).length ≤ 1000 := by
    have h1 : s1.val.length = bd.val.length := hperm.length_eq
    show s1.val.length ≤ 1000
    simp only [alloc.vec.Vec.length, Slice.length] at hbd_len hn hlenr
    omega
  have hin1 : ∀ x ∈ (({ slice := s1 } : alloc.vec.Vec Usize)).val,
      x.val < weights.length ∧ x.val < reduced.length := by
    intro x hx
    have := hbd_in x (hperm.mem_iff.mp hx)
    exact ⟨by omega, this.1⟩
  step*

/-! ## `check_candidate` -/

lemma spec_self {α : Type _} {m : Result α} {p : α → Prop} (h : m ⦃ x => p x ⦄) :
    m ⦃ x => m = ok x ∧ p x ⦄ := by
  obtain ⟨x, hx, hp⟩ := spec_eq_ok h
  rw [hx]; simpa [hx] using hp

/-- `knapsack_min_original_spec`, remembering what the call returned. -/
@[step]
lemma knapsack_min_original_spec_eq (weights reduced : Slice U16) (reduced_total : U32)
    (hlenr : reduced.length = weights.length)
    (hRT : reduced_total.val = total reduced.val weights.length) (hRT' : reduced_total.val ≤ 65535)
    (hW : total weights.val weights.length ≤ 65535) :
    knapsack_min_original weights reduced reduced_total ⦃ tbl =>
      knapsack_min_original weights reduced reduced_total = ok tbl ∧
      tbl.length = reduced_total.val + 1 ∧ tbl.val[0]!.val = 0 ∧
      (Dominated weights reduced → ∀ u < tbl.length,
        tbl.val[u]!.val = U32.max ∨ u ≤ tbl.val[u]!.val) ⦄ :=
  spec_self (WP.spec_mono (knapsack_min_original_spec weights reduced reduced_total hlenr hRT hRT' hW)
    fun _ ⟨h1, h2, _, h4⟩ => ⟨h1, h2, h4⟩)

attribute [-step] knapsack_min_original_spec max_reduced_weight_spec
attribute [local step] max_reduced_weight_gmax

/-- If `check_candidate` accepts the reduced weights `rv`, with thresholds `(t', f')`, then
`verify_reduction` accepts `(rv, t', f')`. -/
@[step]
lemma check_candidate_spec (hts : ToStringReturns) (weights : Slice U16) (w_total t f delta : U16)
    (rv : alloc.vec.Vec U16) (hlen : rv.length = weights.length) (hn : weights.length ≤ 1000)
    (hW : w_total.val = total weights.val weights.length)
    (hRT : total rv.val weights.length ≤ 65535)
    (ht : 1 ≤ t.val) (hf : 1 ≤ f.val) (hft : f.val < t.val)
    (htf : t.val + 2 * f.val ≤ w_total.val) (htfd : t.val + f.val + delta.val ≤ w_total.val) :
    check_candidate weights w_total t f delta (alloc.vec.Vec.deref rv) ⦃ r =>
      ∀ tp fp, r = .Ok (tp, fp) → Passes weights t f delta ⟨rv, tp, fp⟩ ⦄ := by
  unfold check_candidate
  have := to_string_spec hts
  step*
  all_goals try vr_tac
  -- The success case: every check passed.
  intro tp' fp' h
  simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [deref_val, deref_length] at *
  rw [i1_post, i_post] at i2_post
  rw [i3_post] at fp_post
  rw [b1_post, i7_post, i4_post, i5_post, i6_post] at i8_post
  rw [b2_post, i15_post, i13_post, i10_post, i11_post, i12_post, i14_post] at i16_post
  have hRT' : reduced_total.val = total rv.val weights.length := by rw [reduced_total_post, hlen]
  have hmono := gmax_mono min_original_weight_map.val (show f.val ≤ t.val - 1 by omega)
  have hfp : fp.val ≠ 0 := fun h => ‹¬fp = 0#u32› (UScalar.eq_of_val_eq (by simpa using h))
  have hL3' : tp.val ≤ i9.val := by have := ‹¬i9 < tp›; scalar_tac
  have hL1' : i18.val ≤ i17.val := by have := ‹¬i17 < i18›; scalar_tac
  refine verify_reduction_accepts hts weights t f delta ⟨rv, i19, i20⟩ min_original_weight_map
    reduced_total hlen hn (by scalar_tac) hRT' (by scalar_tac) min_original_weight_map_post
    min_original_weight_map_post1 min_original_weight_map_post2 ht hf hft (by omega) (by omega)
    ?_ ?_ ?_ ?_ ?_ ?_ ?_
  all_goals simp only [i19_post, i20_post]
  all_goals (try rw [← hW]); omega

/-! ## `sweep` -/

@[step]
lemma sweep_loop0_spec (weights : Slice U16) (iter : core.slice.iter.Iter U16) (m : U64)
    (hs : iter.slice = weights) (hi : iter.i ≤ weights.length) (hm : m.val ≤ 65535) :
    sweep_loop0 iter m ⦃ r => r.val ≤ 65535 ⦄ := by
  unfold sweep_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : core.slice.iter.Iter U16 × U64) => weights.length - x.1.i)
    (inv := fun (x : core.slice.iter.Iter U16 × U64) => x.1.slice = weights ∧
      x.1.i ≤ weights.length ∧ x.2.val ≤ 65535)
  · rintro ⟨it, m⟩ ⟨hs, hi, hm⟩
    unfold sweep_loop0.body
    simp only at hs hi hm ⊢
    let* ⟨ o, it1, ho, hs1 ⟩ ← slice_iter_next_spec
    split_ifs at ho with hlt
    · obtain ⟨rfl, hi1⟩ := ho
      simp only
      step*
      exact ⟨by rw [hs1, hs], by scalar_tac, by scalar_tac, by scalar_tac⟩
    · obtain ⟨rfl, hi1⟩ := ho
      simp [WP.spec_ok, hm]
  · exact ⟨hs, hi, hm⟩

@[step]
lemma sweep_loop1_loop0_spec (weights : Slice U16) (iter : core.slice.iter.Iter U16)
    (offset : U64) (d : U32) (reduced : alloc.vec.Vec U16) (hd : 0 < d.val)
    (ho : offset.val < 100)
    (hs : iter.slice = weights) (hi : iter.i ≤ weights.length) (hlen : reduced.length = iter.i) :
    sweep_loop1_loop0 iter offset d reduced ⦃ r => r.length = weights.length ⦄ := by
  unfold sweep_loop1_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : core.slice.iter.Iter U16 × alloc.vec.Vec U16) => weights.length - x.1.i)
    (inv := fun (x : core.slice.iter.Iter U16 × alloc.vec.Vec U16) => x.1.slice = weights ∧
      x.1.i ≤ weights.length ∧ x.2.length = x.1.i)
  · rintro ⟨it, reduced⟩ ⟨hs, hi, hlen⟩
    unfold sweep_loop1_loop0.body
    simp only at hs hi hlen ⊢
    let* ⟨ o, it1, ho', hs1 ⟩ ← slice_iter_next_spec
    split_ifs at ho' with hlt
    · obtain ⟨rfl, hi1⟩ := ho'
      simp only
      step*
      exact ⟨by rw [hs1, hs], by scalar_tac, by simp [reduced1_post]; scalar_tac, by scalar_tac⟩
    · obtain ⟨rfl, hi1⟩ := ho'
      simp only [WP.spec_ok]
      scalar_tac
  · exact ⟨hs, hi, hlen⟩

@[step]
lemma sweep_loop1_loop1_spec (weights : Slice U16) (offset : U64) (reduced : alloc.vec.Vec U16)
    (iter : core.ops.range.Range Usize) (next : U32) (ho : offset.val < 100)
    (hlen : reduced.length = weights.length) (hend : iter.end.val = weights.length)
    (hi : iter.start.val ≤ weights.length) :
    sweep_loop1_loop1 iter weights offset reduced next ⦃ _ => True ⦄ := by
  unfold sweep_loop1_loop1
  apply loop.spec_decr_nat
    (measure := fun (x : core.ops.range.Range Usize × U32) => weights.length - x.1.start.val)
    (inv := fun (x : core.ops.range.Range Usize × U32) =>
      x.1.end.val = weights.length ∧ x.1.start.val ≤ weights.length)
  · rintro ⟨it, next⟩ ⟨hend, hi⟩
    unfold sweep_loop1_loop1.body
    simp only at hend hi ⊢
    let* ⟨ o, it1, ho', hend1 ⟩ ← core.iter.range.IteratorRange.next_Usize_spec
    split_ifs at ho' with hlt
    · obtain ⟨rfl, hstart1⟩ := ho'
      simp only
      step*
      have : i3.val / i6.val ≤ i3.val := Nat.div_le_self _ _
      scalar_tac
    · obtain ⟨rfl, hstart1⟩ := ho'
      simp [WP.spec_ok]
  · exact ⟨hend, hi⟩

@[step]
lemma sweep_loop1_loop2_spec (weights : Slice U16) (offset : U64) (reduced : alloc.vec.Vec U16)
    (iter : core.ops.range.Range Usize) (next : U32) (ho : offset.val < 100)
    (hlen : reduced.length = weights.length) (hend : iter.end.val = weights.length)
    (hi : iter.start.val ≤ weights.length) :
    sweep_loop1_loop2 iter weights offset reduced next ⦃ _ => True ⦄ := by
  unfold sweep_loop1_loop2
  apply loop.spec_decr_nat
    (measure := fun (x : core.ops.range.Range Usize × U32) => weights.length - x.1.start.val)
    (inv := fun (x : core.ops.range.Range Usize × U32) =>
      x.1.end.val = weights.length ∧ x.1.start.val ≤ weights.length)
  · rintro ⟨it, next⟩ ⟨hend, hi⟩
    unfold sweep_loop1_loop2.body
    simp only at hend hi ⊢
    let* ⟨ o, it1, ho', hend1 ⟩ ← core.iter.range.IteratorRange.next_Usize_spec
    split_ifs at ho' with hlt
    · obtain ⟨rfl, hstart1⟩ := ho'
      simp only
      step*
      have : i3.val / i6.val ≤ i3.val := Nat.div_le_self _ _
      scalar_tac
    · obtain ⟨rfl, hstart1⟩ := ho'
      simp [WP.spec_ok]
  · exact ⟨hend, hi⟩

@[step]
lemma sweep_loop1_loop3_spec (weights : Slice U16) (offset : U64) (reduced : alloc.vec.Vec U16)
    (iter : core.ops.range.Range Usize) (next : U32) (ho : offset.val < 100)
    (hlen : reduced.length = weights.length) (hend : iter.end.val = weights.length)
    (hi : iter.start.val ≤ weights.length) :
    sweep_loop1_loop3 iter weights offset reduced next ⦃ _ => True ⦄ := by
  unfold sweep_loop1_loop3
  apply loop.spec_decr_nat
    (measure := fun (x : core.ops.range.Range Usize × U32) => weights.length - x.1.start.val)
    (inv := fun (x : core.ops.range.Range Usize × U32) =>
      x.1.end.val = weights.length ∧ x.1.start.val ≤ weights.length)
  · rintro ⟨it, next⟩ ⟨hend, hi⟩
    unfold sweep_loop1_loop3.body
    simp only at hend hi ⊢
    let* ⟨ o, it1, ho', hend1 ⟩ ← core.iter.range.IteratorRange.next_Usize_spec
    split_ifs at ho' with hlt
    · obtain ⟨rfl, hstart1⟩ := ho'
      simp only
      step*
      have : i3.val / i6.val ≤ i3.val := Nat.div_le_self _ _
      scalar_tac
    · obtain ⟨rfl, hstart1⟩ := ho'
      simp [WP.spec_ok]
  · exact ⟨hend, hi⟩

/-- What `sweep` returns: a candidate that `check_candidate` accepted, so that it passes
`verify_reduction`, with as many weights as `weights` and a total of at most `best_total`. -/
def SweepResult (weights : Slice U16) (t f delta : U16) (best_total : U32)
    (o : Option ReducedWeights) : Prop :=
  ∀ c, o = some c → Passes weights t f delta c ∧ c.weights.length = weights.length ∧
    total c.weights.val weights.length ≤ best_total.val

@[step]
lemma sweep_loop1_spec (hts : ToStringReturns) (hsort : SortByPermutes) (weights : Slice U16)
    (w_total t f delta lower_bound : U16) (offset : U64) (best_total d : U32)
    (hn : weights.length ≤ 1000) (hW : w_total.val = total weights.val weights.length)
    (hbt : best_total.val ≤ 65535) (ho : offset.val < 100)
    (ht : 1 ≤ t.val) (hf : 1 ≤ f.val) (hft : f.val < t.val)
    (htf : t.val + 2 * f.val ≤ w_total.val) (htfd : t.val + f.val + delta.val ≤ w_total.val) :
    sweep_loop1 weights w_total t f delta lower_bound offset best_total d ⦃ o =>
      SweepResult weights t f delta best_total o ⦄ := by
  unfold sweep_loop1
  apply loop.spec_decr_nat (measure := fun (d : U32) => d.val) (inv := fun _ => True)
  · intro d _
    unfold sweep_loop1.body
    step*
    all_goals try (simp [SweepResult]; done)
    · simp [alloc.vec.Vec.with_capacity, iter_post]
    · have := ‹¬reduced_total > best_total›
      simp only [deref_val, deref_length] at reduced_total_post
      rw [← reduced1_post]; scalar_tac
    · obtain ⟨tp, fp⟩ := p
      have hp := r_post tp fp ‹r = _›
      have := ‹¬reduced_total > best_total›
      simp only [deref_val, deref_length] at reduced_total_post
      refine (WP.spec_ok (done (some ({ weights := reduced1, t := tp, f := fp } :
        ReducedWeights)) : ControlFlow U32 (Option ReducedWeights))).mpr ?_
      show SweepResult weights t f delta best_total _
      simp only [SweepResult, Option.some.injEq]
      rintro c rfl
      exact ⟨hp, reduced1_post, by rw [← reduced1_post]; scalar_tac⟩
  · trivial

@[step]
lemma sweep_spec (hts : ToStringReturns) (hsort : SortByPermutes) (weights : Slice U16)
    (w_total t f delta lower_bound : U16) (offset : U64) (best_total : U32)
    (hn : weights.length ≤ 1000) (hW : w_total.val = total weights.val weights.length)
    (hbt : best_total.val ≤ 65535) (ho : offset.val < 100)
    (ht : 1 ≤ t.val) (hf : 1 ≤ f.val) (hft : f.val < t.val)
    (htf : t.val + 2 * f.val ≤ w_total.val) (htfd : t.val + f.val + delta.val ≤ w_total.val)
    (hne : 0 < weights.length) :
    sweep weights w_total t f delta lower_bound offset best_total ⦃ o =>
      SweepResult weights t f delta best_total o ⦄ := by
  unfold sweep
  step*
  have : i.val / i1.val ≤ i.val := Nat.div_le_self _ _
  scalar_tac

/-! ## `reduce_weights` -/

@[step]
lemma is_better_spec (a b : ReducedWeights) (ha : a.weights.length ≤ 1000)
    (hb : b.weights.length ≤ 1000) : is_better a b ⦃ _ => True ⦄ := by
  unfold is_better
  step*

@[step]
lemma keep_better_spec (best : ReducedWeights) (candidate : Option ReducedWeights)
    (hb : best.weights.length ≤ 1000)
    (hc : ∀ c, candidate = some c → c.weights.length ≤ 1000) :
    keep_better best candidate ⦃ r => r = best ∨ candidate = some r ⦄ := by
  unfold keep_better
  split
  · simp [WP.spec_ok]
  · rename_i c
    have := hc c rfl
    step*

/-- If each finite entry of the table is at least its index, then `gmax tbl b ≤ b`. -/
lemma gmax_le_of_low (tbl : alloc.vec.Vec U32) (b : ℕ) (hb : b < U32.max)
    (hlow : ∀ u < tbl.length, tbl.val[u]!.val = U32.max ∨ u ≤ tbl.val[u]!.val) :
    gmax tbl.val b ≤ b := by
  by_cases hm : gmax tbl.val b = 0
  · omega
  · have hP : tbl.val[gmax tbl.val b]!.val ≤ b := by
      unfold gmax at hm ⊢
      exact Nat.findGreatest_of_ne_zero (P := fun u => tbl.val[u]!.val ≤ b) rfl hm
    have hle := gmax_le tbl.val b
    rcases hlow (gmax tbl.val b) (by simp only [alloc.vec.Vec.length]; omega) with h | h
    · omega
    · omega

/-- The original weights pass `verify_reduction`. -/
lemma identity_passes (hts : ToStringReturns) (weights : Slice U16) (t f delta : U16)
    (v : alloc.vec.Vec U16) (W : U32) (hv : v.val = weights.val) (hn : weights.length ≤ 1000)
    (hW : W.val = total weights.val weights.length) (hW' : W.val ≤ 65535)
    (ht : 1 ≤ t.val) (hf : 1 ≤ f.val) (hft : f.val < t.val)
    (htf : t.val + 2 * f.val ≤ W.val) (htfd : t.val + f.val + delta.val ≤ W.val) :
    Passes weights t f delta ⟨v, t, f⟩ := by
  have hlen : v.length = weights.length := by
    simp only [alloc.vec.Vec.length, Slice.length, hv]
  have hRT : W.val = total (alloc.vec.Vec.deref v).val weights.length := by simp [hv, hW]
  obtain ⟨tbl, htbl, hlenT, h0, -, hlow⟩ := spec_eq_ok (knapsack_min_original_spec weights
    (alloc.vec.Vec.deref v) W (by simpa using hlen) hRT hW' (by omega))
  have hdom : Dominated weights (alloc.vec.Vec.deref v) := fun j _ => by simp [hv]
  have hlow := hlow hdom
  have g1 := gmax_le_of_low tbl (t.val - 1) (by scalar_tac) hlow
  have g2 := gmax_le_of_low tbl f.val (by scalar_tac) hlow
  have g3 := gmax_le_of_low tbl (W.val - (t.val + delta.val)) (by scalar_tac) hlow
  have g4 := gmax_le_of_low tbl (W.val - (t.val + f.val + delta.val)) (by scalar_tac) hlow
  rw [hW] at g3 g4
  exact verify_reduction_accepts hts weights t f delta ⟨v, t, f⟩ tbl W hlen hn (by omega)
    (by simp [hv, hW]) hW' htbl hlenT h0 ht hf hft (by rw [← hW]; omega) (by rw [← hW]; omega)
    ht hf hft
    (by dsimp only; omega) g2 (by dsimp only; omega) (by dsimp only; omega)

/-- The invariant of the loop over rounding offsets: `best` passes `verify_reduction`, and has as
many weights as `weights` and a total of at most `W`. -/
def BestInv (weights : Slice U16) (t f delta : U16) (W : ℕ) (best : ReducedWeights) : Prop :=
  Passes weights t f delta best ∧ best.weights.length = weights.length ∧
    total best.weights.val weights.length ≤ W

@[step]
lemma reduce_weights_loop_spec (hts : ToStringReturns) (hsort : SortByPermutes)
    (weights : Slice U16) (t f delta lb w_total : U16)
    (iter : core.iter.adapters.step_by.StepBy (core.ops.range.Range U64))
    (best : ReducedWeights) (hn : weights.length ≤ 1000)
    (hW : w_total.val = total weights.val weights.length)
    (ht : 1 ≤ t.val) (hf : 1 ≤ f.val) (hft : f.val < t.val)
    (htf : t.val + 2 * f.val ≤ w_total.val) (htfd : t.val + f.val + delta.val ≤ w_total.val)
    (hend : iter.iter.end.val = 100) (hstep : iter.step_by.val = 10)
    (hstart : iter.iter.start.val ≤ 100) (hbest : BestInv weights t f delta w_total.val best)
    (hne : 0 < weights.length) :
    reduce_weights_loop iter weights t f delta lb w_total best ⦃ r =>
      BestInv weights t f delta w_total.val r ⦄ := by
  unfold reduce_weights_loop
  apply loop.spec_decr_nat
    (measure := fun (x : core.iter.adapters.step_by.StepBy (core.ops.range.Range U64) ×
      ReducedWeights) => 100 - x.1.iter.start.val)
    (inv := fun (x : core.iter.adapters.step_by.StepBy (core.ops.range.Range U64) ×
      ReducedWeights) => x.1.iter.end.val = 100 ∧ x.1.step_by.val = 10 ∧
      x.1.iter.start.val ≤ 100 ∧ BestInv weights t f delta w_total.val x.2)
  · rintro ⟨it, best⟩ ⟨hend, hstep, hstart, hbest⟩
    unfold reduce_weights_loop.body
    simp only at hend hstep hstart hbest ⊢
    let* ⟨ o, it1, ho, hend1, hstep1 ⟩ ←
      core.iter.adapters.step_by.IteratorStepBy.next_Range_U64_spec
    split_ifs at ho with hlt
    · obtain ⟨rfl, hstart1⟩ := ho
      obtain ⟨hp, hl, htot⟩ := hbest
      simp only
      step*
      · simp only [deref_val, deref_length] at *; scalar_tac
      · intro c hc; rw [(candidate_post c hc).2.1]; exact hn
      · refine ⟨by rw [hend1]; exact hend, by rw [hstep1]; exact hstep, by scalar_tac, ?_,
          by scalar_tac⟩
        rcases best1_post with rfl | h
        · exact ⟨hp, hl, htot⟩
        · obtain ⟨hp', hl', htot'⟩ := candidate_post _ h
          simp only [deref_val, deref_length] at best_total_post
          exact ⟨hp', hl', by rw [hl] at best_total_post; omega⟩
    · obtain ⟨rfl, hstart1⟩ := ho
      simp [WP.spec_ok, hbest]
  · exact ⟨hend, hstep, hstart, hbest⟩

/-- For every input, `reduce_weights` returns, and every reduction it returns passes
`verify_reduction`. -/
lemma reduce_weights_spec (hts : ToStringReturns) (hsort : SortByPermutes) (weights : Slice U16)
    (t f delta lb : U16) :
    reduce_weights weights t f delta lb ⦃ r =>
      ∀ b, r = .Ok b → Passes weights t f delta b ⦄ := by
  unfold reduce_weights
  step*
  all_goals try vr_tac
  · -- The loop starts from the original weights, which pass `verify_reduction`.
    have hv : v.val = weights.val := by rw [weights_post]; rfl
    have hlen : v.length = weights.length := by
      simp only [alloc.vec.Vec.length, Slice.length, hv]
    refine ⟨identity_passes hts weights t f delta v total_weight hv (by scalar_tac)
      total_weight_post (by vr_tac) (by scalar_tac) (by scalar_tac) (by scalar_tac)
      (by scalar_tac) (by scalar_tac), hlen, ?_⟩
    simp only [hv]; scalar_tac
  · intro b h
    simp only [core.result.Result.Ok.injEq] at h
    exact h ▸ best_post.1

end WeightReductionProofs
