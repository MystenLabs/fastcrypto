/-
Copyright (c) 2022, Mysten Labs, Inc.
SPDX-License-Identifier: Apache-2.0
-/
import DkgMerge.Funs
import DkgMerge.Spec

open Aeneas Aeneas.Std Result ControlFlow

namespace DkgMerge

set_option maxHeartbeats 2000000

-- Reason about casts as exact, with a proof obligation that the value fits, instead of modulo.
attribute [-step] UScalar.cast.step_spec
attribute [local step] UScalar.cast_inBounds_spec

variable {G EG : Type _}

/-! ## Clones

The derived `Clone`s of the stand-in types return their input if the `Clone`s of `G` and `EG` do. -/

@[step]
theorem complaint_clone_spec (cloneEG : core.clone.Clone EG) (hEG : ∀ x, cloneEG.clone x = ok x)
    (c : Complaint EG) :
    Complaint.Insts.CoreCloneClone.clone cloneEG c ⦃ r => r = c ⦄ := by
  unfold Complaint.Insts.CoreCloneClone.clone
  simp [hEG, lift, WP.spec_ok]

theorem vec_clone_spec (cloneG : core.clone.Clone G) (hG : ∀ x, cloneG.clone x = ok x)
    (v : alloc.vec.Vec G) :
    alloc.vec.CloneVec.clone cloneG v ⦃ r => r = v ⦄ := by
  unfold alloc.vec.CloneVec.clone
  apply WP.spec_bind (Slice.clone_spec (fun x _ => hG x))
  rintro s rfl
  simp [WP.spec_ok]

@[step]
theorem processedMessage_clone_spec (cloneG : core.clone.Clone G)
    (cloneEG : core.clone.Clone EG) (hG : ∀ x, cloneG.clone x = ok x)
    (hEG : ∀ x, cloneEG.clone x = ok x) (m : ProcessedMessage G EG) :
    ProcessedMessage.Insts.CoreCloneClone.clone cloneG cloneEG m ⦃ r => r = m ⦄ := by
  obtain ⟨⟨sender, vss_pk, encrypted_shares⟩, shares, complaint⟩ := m
  unfold ProcessedMessage.Insts.CoreCloneClone.clone Message.Insts.CoreCloneClone.clone
  simp only [hG, hEG, lift, core.clone.impls.CloneU16.clone, bind_ok]
  apply WP.spec_bind (vec_clone_spec cloneG hG shares)
  rintro v rfl
  cases complaint <;>
    simp [core.option.Option.Insts.CoreCloneClone.clone, Complaint.Insts.CoreCloneClone.clone, hEG,
      lift, WP.spec_ok]

/-! ## `<[u16]>::contains` -/

theorem contains_u16 (s : Slice U16) (x : U16) :
    core.slice.Slice.contains core.cmp.PartialEqU16 s x = ok (decide (x ∈ s.val)) := by
  unfold core.slice.Slice.contains
  generalize s.val = l
  induction l with
  | nil => simp [List.anyM]; rfl
  | cons a l ih =>
    simp only [List.anyM, liftFun2, core.cmp.impls.PartialEqU16.eq]
    by_cases h : x = a
    · simp_all; rfl
    · simp_all

/-! ## Slice iterators -/

theorem next_some {T : Type _} (it : core.slice.iter.Iter T) (h : it.i < it.slice.val.length) :
    core.slice.iter.IteratorSliceIter.next it =
      ok (some it.slice.val[it.i], { it with i := it.i + 1 }) := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · simp only [ok.injEq, Prod.mk.injEq, Option.some.injEq, and_true]
    exact Slice.getElem_Nat_eq _ _ h
  · exfalso; scalar_tac

theorem next_none {T : Type _} (it : core.slice.iter.Iter T) (h : ¬ it.i < it.slice.val.length) :
    core.slice.iter.IteratorSliceIter.next it = ok (none, it) := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · exfalso; scalar_tac
  · rfl

/-! ## `UsedProcessedMessages::from` -/

theorem from_loop_spec (cloneG : core.clone.Clone G) (cloneEG : core.clone.Clone EG)
    (hG : ∀ x, cloneG.clone x = ok x) (hEG : ∀ x, cloneEG.clone x = ok x)
    (msgs : Slice (ProcessedMessage G EG)) (iter : core.slice.iter.Iter (ProcessedMessage G EG))
    (sendersV : alloc.vec.Vec U16) (filtered : alloc.vec.Vec (ProcessedMessage G EG))
    (hslice : iter.slice = msgs) (hi : iter.i ≤ msgs.length)
    (hf : filtered.val = firstBySender (msgs.val.take iter.i))
    (hs : sendersV.val = senders filtered.val) :
    UsedProcessedMessages.Insts.CoreConvertFromShared0SliceProcessedMessage.from_loop
      cloneG cloneEG iter sendersV filtered ⦃ r => r.val = firstBySender msgs.val ⦄ := by
  unfold UsedProcessedMessages.Insts.CoreConvertFromShared0SliceProcessedMessage.from_loop
  apply loop.spec_decr_nat
    (measure := fun (x : core.slice.iter.Iter (ProcessedMessage G EG) × alloc.vec.Vec U16 ×
      alloc.vec.Vec (ProcessedMessage G EG)) => msgs.length - x.1.i)
    (inv := fun x => x.1.slice = msgs ∧ x.1.i ≤ msgs.length ∧
      x.2.2.val = firstBySender (msgs.val.take x.1.i) ∧ x.2.1.val = senders x.2.2.val)
  · rintro ⟨it, sv, fl⟩ ⟨hsl, hit, hfl, hsv⟩
    dsimp only at hsl hit hfl hsv
    subst hsl
    unfold UsedProcessedMessages.Insts.CoreConvertFromShared0SliceProcessedMessage.from_loop.body
    dsimp only
    by_cases hlt : it.i < it.slice.val.length
    · have htake := List.take_succ_eq_append_getElem hlt
      have hflen : fl.val.length ≤ it.i := by
        rw [hfl]
        exact ((firstBySender_sublist _).length_le).trans (by simp)
      have hmax : it.slice.val.length ≤ Usize.max := Slice.length_ineq _
      have hsvlen : sv.val.length = fl.val.length := by simp [hsv, senders]
      rw [next_some it hlt]
      simp only [bind_ok, uncurry_apply_pair]
      simp only [alloc.vec.Vec.deref, contains_u16, Slice.from_val, decide_eq_true_eq, bind_ok]
      split
      · rename_i hmem
        have hf' : fl.val = firstBySender (List.take (it.i + 1) it.slice.val) := by
          rw [htake, firstBySender_append_singleton, ← hfl, keepFirst, ite_eq_left (by rwa [← hsv])]
        simp only [WP.spec_ok]
        and_intros <;> (try first | assumption | scalar_tac)
      · rename_i hmem
        step*
        have hf' : filtered1.val = firstBySender (List.take (it.i + 1) it.slice.val) := by
          rw [filtered1_post, pm_post, htake, firstBySender_append_singleton, ← hfl, keepFirst,
            ite_eq_right (by rwa [← hsv])]
        have hs' : senders1.val = senders filtered1.val := by
          rw [senders1_post, filtered1_post, hsv, pm_post]
          simp [senders]
        and_intros <;> (try first | assumption | scalar_tac)
    · rw [next_none it hlt]
      simp only [bind_ok, uncurry_apply_pair]
      simp only [WP.spec_ok]
      have : it.i = it.slice.val.length := by simp at hit; omega
      rw [hfl, this, List.take_length]
  · exact ⟨hslice, hi, hf, hs⟩

@[step]
theorem from_spec (cloneG : core.clone.Clone G) (cloneEG : core.clone.Clone EG)
    (hG : ∀ x, cloneG.clone x = ok x) (hEG : ∀ x, cloneEG.clone x = ok x)
    (msgs : Slice (ProcessedMessage G EG)) :
    UsedProcessedMessages.Insts.CoreConvertFromShared0SliceProcessedMessage.from
      cloneG cloneEG msgs ⦃ r => r.val = firstBySender msgs.val ⦄ := by
  unfold UsedProcessedMessages.Insts.CoreConvertFromShared0SliceProcessedMessage.from
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  apply WP.spec_bind (from_loop_spec cloneG cloneEG hG hEG msgs ⟨msgs, 0⟩ (alloc.vec.Vec.new U16)
    (alloc.vec.Vec.new (ProcessedMessage G EG)) rfl (by simp) (by simp [firstBySender])
    (by simp [senders]))
  intro r hr
  simpa [WP.spec_ok] using hr

/-! ## `Nodes::node_id_to_node` -/

@[step]
theorem node_id_to_node_spec (nodes : Nodes G) (id : U16) :
    Nodes.node_id_to_node nodes id ⦃ r =>
      r = match nodes.nodes.val[id.val]? with
        | some n => .Ok n
        | none => .Err .InvalidInput ⦄ := by
  unfold Nodes.node_id_to_node
  step*
  simp only [core.slice.Slice.get, core.slice.index.Usize.get, bind_ok]
  have : (alloc.vec.Vec.deref nodes.nodes)[i]? = nodes.nodes.val[id.val]? := by
    simp [alloc.vec.Vec.deref, i_post]
  rw [this]
  cases nodes.nodes.val[id.val]? <;> simp [core.option.Option.ok_or, WP.spec_ok]

/-! ## The loops of `Party::merge` -/

/-- The first loop sums the weights of the senders. -/
theorem merge_loop0_spec (self : Party G EG) (used : List (ProcessedMessage G EG))
    (iter : core.slice.iter.Iter (ProcessedMessage G EG)) (total : U32)
    (hslice : iter.slice.val = used) (hi : iter.i ≤ used.length) (hlen : used.length ≤ 65536)
    (hsenders : ∀ m ∈ used, m.message.sender.val < self.nodes.nodes.length)
    (htotal : total.val = weightOf self.nodes.nodes.val (used.take iter.i)) :
    Party.merge_loop0 iter self total ⦃ r =>
      r.1 = self ∧ r.2.val = weightOf self.nodes.nodes.val used ⦄ := by
  unfold Party.merge_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : core.slice.iter.Iter (ProcessedMessage G EG) × U32) => used.length - x.1.i)
    (inv := fun x => x.1.slice.val = used ∧ x.1.i ≤ used.length ∧
      x.2.val = weightOf self.nodes.nodes.val (used.take x.1.i))
  · rintro ⟨it, tw⟩ ⟨hsl, hit, htw⟩
    dsimp only at hsl hit htw
    unfold Party.merge_loop0.body
    dsimp only
    by_cases hlt : it.i < it.slice.val.length
    · have hlt' : it.i < used.length := by rwa [← hsl]
      have hm : it.slice.val[it.i] = used[it.i] := by simp [hsl]
      have hsender := hsenders used[it.i] (List.getElem_mem hlt')
      have hget : self.nodes.nodes.val[used[it.i].message.sender.val]? =
          some self.nodes.nodes.val[used[it.i].message.sender.val] :=
        List.getElem?_eq_getElem (by simpa using hsender)
      have hbound := weightOf_le self.nodes.nodes.val (used.take it.i)
      have htake := List.take_succ_eq_append_getElem hlt'
      rw [next_some it hlt]
      simp only [bind_ok, uncurry_apply_pair]
      simp only [hm]
      apply WP.spec_bind (node_id_to_node_spec self.nodes used[it.i].message.sender)
      rintro r rfl
      simp only [hget, core.result.Result.expect, bind_ok]
      have hw := (self.nodes.nodes.val[used[it.i].message.sender.val]).weight.hBounds
      simp only [List.length_take] at hbound
      step*
      have htw' : total_weight1.val = weightOf self.nodes.nodes.val (List.take (it.i + 1) used) := by
        rw [total_weight1_post, i_post, htw, htake, weightOf_append_singleton, hget]
        simp
      and_intros <;> (try first | assumption | scalar_tac)
    · rw [next_none it hlt]
      simp only [bind_ok, uncurry_apply_pair]
      simp only [WP.spec_ok]
      have : it.i = used.length := by rw [← hsl] at hit ⊢; omega
      have htw' : tw.val = weightOf self.nodes.nodes.val used := by rw [htw, this, List.take_length]
      and_intros <;> trivial
  · exact ⟨hslice, hi, htotal⟩

/-- The second loop collects the complaints, and checks whether every message has one. -/
theorem merge_loop1_spec (cloneEG : core.clone.Clone EG) (hEG : ∀ x, cloneEG.clone x = ok x)
    (used : List (ProcessedMessage G EG)) (iter : core.slice.iter.Iter (ProcessedMessage G EG))
    (v : alloc.vec.Vec (Complaint EG)) (allC : Bool)
    (hslice : iter.slice.val = used) (hi : iter.i ≤ used.length)
    (hv : v.val = complaints (used.take iter.i))
    (hall : allC = (used.take iter.i).all (·.complaint.isSome)) :
    Party.merge_loop1 cloneEG iter v allC ⦃ r =>
      r.1.val = complaints used ∧ r.2 = used.all (·.complaint.isSome) ⦄ := by
  unfold Party.merge_loop1
  apply loop.spec_decr_nat
    (measure := fun (x : core.slice.iter.Iter (ProcessedMessage G EG) ×
      alloc.vec.Vec (Complaint EG) × Bool) => used.length - x.1.i)
    (inv := fun x => x.1.slice.val = used ∧ x.1.i ≤ used.length ∧
      x.2.1.val = complaints (used.take x.1.i) ∧
      x.2.2 = (used.take x.1.i).all (·.complaint.isSome))
  · rintro ⟨it, v, allC⟩ ⟨hsl, hit, hv, hall⟩
    dsimp only at hsl hit hv hall
    unfold Party.merge_loop1.body
    dsimp only
    by_cases hlt : it.i < it.slice.val.length
    · have hlt' : it.i < used.length := by rwa [← hsl]
      have hm : it.slice.val[it.i] = used[it.i] := by simp [hsl]
      have htake := List.take_succ_eq_append_getElem hlt'
      have hmax : used.length ≤ Usize.max := hsl ▸ Slice.length_ineq _
      have hvlen : v.val.length ≤ it.i := by
        rw [hv]
        exact (List.length_filterMap_le _ _).trans (by simp)
      rw [next_some it hlt]
      simp only [bind_ok, uncurry_apply_pair]
      split
      · rename_i hnone
        rw [hm] at hnone
        have hv' : v.val = complaints (List.take (it.i + 1) used) := by
          rw [htake, complaints_append_singleton, hnone, ← hv]; simp
        have hall' : false = (List.take (it.i + 1) used).all (·.complaint.isSome) := by
          rw [htake, List.all_append]
          simp only [List.all_cons, List.all_nil, hnone, Option.isSome_none, Bool.and_false,
            Bool.false_and]
        simp only [WP.spec_ok]
        and_intros <;> (try first | assumption | scalar_tac)
      · rename_i c hsome
        rw [hm] at hsome
        step*
        have hv' : v1.val = complaints (List.take (it.i + 1) used) := by
          rw [v1_post, htake, complaints_append_singleton, hsome, ← hv, c_post]; simp
        have hall' : allC = (List.take (it.i + 1) used).all (·.complaint.isSome) := by
          rw [htake, List.all_append, hall]
          simp only [List.all_cons, List.all_nil, hsome, Option.isSome_some, Bool.and_true]
        and_intros <;> (try first | assumption | scalar_tac)
    · rw [next_none it hlt]
      simp only [bind_ok, uncurry_apply_pair]
      simp only [WP.spec_ok]
      have : it.i = used.length := by rw [← hsl] at hit ⊢; omega
      rw [hv, hall, this, List.take_length]
      and_intros <;> rfl
  · exact ⟨hslice, hi, hv, hall⟩

/-! ## `Party::merge` -/

theorem unwrap_or_eq (o : Option U16) (d : U16) : core.option.Option.unwrap_or o d = o.getD d := by
  cases o <;> simp

/-- **Main theorem.** Assume that every message passed to `merge` has a valid sender (the
assumption in its doc comment: the messages come from `process_message`). Let `used` be the input
keeping only the first message of each sender, in order, `w` the total weight of their senders, and
`t' = old_t.unwrap_or(t)`. Then `merge` doesn't panic, and:
- if `w < t'`, it returns `Err(NotEnoughInputs)`;
- otherwise, if every message in `used` has a complaint, it returns `Err(GeneralError(_))`;
- otherwise, it returns `Ok((conf, used))`, where `conf.sender` is the party's id and
  `conf.complaints` are the complaints of `used`, in order.

`hG` and `hEG` say that cloning the fields of the stand-in types that hold group data returns the
same value, as the derived `Clone`s of the production types do. -/
theorem merge_spec (cloneG : core.clone.Clone G) (cloneEG : core.clone.Clone EG)
    (hG : ∀ x, cloneG.clone x = ok x) (hEG : ∀ x, cloneEG.clone x = ok x)
    (self : Party G EG) (msgs : Slice (ProcessedMessage G EG))
    (hsenders : ∀ m ∈ msgs.val, m.message.sender.val < self.nodes.nodes.length) :
    Party.merge cloneG cloneEG self msgs ⦃ r =>
      let used := firstBySender msgs.val
      let w := weightOf self.nodes.nodes.val used
      let t' := (self.old_t.getD self.t).val
      if w < t' then
        r = .Err .NotEnoughInputs
      else if ∀ m ∈ used, m.complaint.isSome then
        ∃ s, r = .Err (.GeneralError s)
      else
        ∃ conf used', r = .Ok (conf, used') ∧
          used'.val = used ∧ conf.sender = self.id ∧ conf.complaints.val = complaints used ⦄ := by
  unfold Party.merge
  apply WP.spec_bind (from_spec cloneG cloneEG hG hEG msgs)
  intro used hused
  have hsub : used.val.Sublist msgs.val := hused ▸ firstBySender_sublist msgs.val
  have hlen : used.val.length ≤ 65536 :=
    hused ▸ length_le_of_senders_nodup _ (firstBySender_nodup msgs.val)
  have hsend : ∀ m ∈ used.val, m.message.sender.val < self.nodes.nodes.length :=
    fun m hm => hsenders m (hsub.subset hm)
  simp only [alloc.vec.Vec.index, core.slice.index.SliceIndexRangeFullSlice.index,
    SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  apply WP.spec_bind (merge_loop0_spec self used.val ⟨used.slice, 0⟩ 0#u32 rfl (by simp) hlen hsend
    (by simp [weightOf]))
  rintro ⟨self1, total⟩ ⟨hself, htotal⟩
  dsimp only at hself htotal
  subst hself
  rw [← hused]
  have hcast : (UScalar.cast .U32 (self1.old_t.getD self1.t)).val =
      (self1.old_t.getD self1.t).val := by
    simp
  simp only [unwrap_or_eq, lift, bind_ok, uncurry_apply_pair]
  by_cases hw : weightOf self1.nodes.nodes.val used.val < (self1.old_t.getD self1.t).val
  · -- Not enough weight.
    have hlt : total < UScalar.cast .U32 (self1.old_t.getD self1.t) := by scalar_tac
    simp only [ite_eq_left hw, ite_eq_left hlt, WP.spec_ok]
  · have hnot_lt : ¬ total < UScalar.cast .U32 (self1.old_t.getD self1.t) := by scalar_tac
    simp only [ite_eq_right hw, ite_eq_right hnot_lt]
    apply WP.spec_bind (merge_loop1_spec cloneEG hEG used.val ⟨used.slice, 0⟩
      (alloc.vec.Vec.new (Complaint EG)) true rfl (by simp) (by simp [complaints]) (by simp))
    rintro ⟨v, allC⟩ ⟨hv, hall⟩
    dsimp only at hv hall
    simp only [uncurry_apply_pair]
    by_cases hc : ∀ m ∈ used.val, m.complaint.isSome
    · -- Every message has a complaint.
      have hallC : allC = true := by rw [hall, List.all_eq_true]; exact hc
      simp only [hallC, ite_eq_left hc, alloc.string.ToString.Blanket.to_string, bind_ok,
        WP.spec_ok, ↓reduceIte]
      exact ⟨_, rfl⟩
    · have hallC : allC = false := by
        rw [hall, ← Bool.not_eq_true, List.all_eq_true]; exact hc
      simp only [hallC, ite_eq_right hc, WP.spec_ok, Bool.false_eq_true, ↓reduceIte]
      exact ⟨_, _, rfl, rfl, rfl, hv⟩

end DkgMerge
