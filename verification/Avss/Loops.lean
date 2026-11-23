import Avss.Generated.Funs

/-!
What the loops of the generated `Receiver::recover` compute.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- `recover`'s first loop collects the responders' ids. -/
theorem recover_loop0_spec
    (it : core.slice.iter.Iter threshold_schnorr.avss.VerifiedComplaintResponse)
    (acc : alloc.vec.Vec Std.U16)
    (hlen : acc.length + (it.slice.length - it.i) ≤ Usize.max) :
    threshold_schnorr.avss.Receiver.recover_loop0 it acc ⦃ res =>
      res.val = acc.val ++ (it.slice.val.drop it.i).map (·.responder_id) ⦄ := by
  unfold threshold_schnorr.avss.Receiver.recover_loop0
  apply loop.spec_decr_nat (fun p => p.1.slice.length - p.1.i)
    (fun p => p.1.slice = it.slice ∧
      p.2.val ++ (p.1.slice.val.drop p.1.i).map (·.responder_id) =
        acc.val ++ (it.slice.val.drop it.i).map (·.responder_id) ∧
      p.2.length + (p.1.slice.length - p.1.i) ≤ Usize.max)
  · rintro ⟨it', acc'⟩ ⟨hs, heq, hl⟩
    dsimp only at hs heq hl ⊢
    unfold threshold_schnorr.avss.Receiver.recover_loop0.body
    simp only [core.slice.iter.IteratorSliceIter.next]
    by_cases hi : it'.i < it'.slice.len.val
    · simp only [hi, ↓reduceDIte]
      simp only [bind_ok]
      have hlt : it'.i < it'.slice.length := by simpa using hi
      apply WP.spec_bind (alloc.vec.Vec.push_spec acc' _ (by scalar_tac))
      intro v hv
      simp only [WP.spec_ok]
      refine ⟨⟨hs, ?_, ?_⟩, by scalar_tac⟩
      · rw [← heq, hv, List.drop_eq_getElem_cons hlt, List.map_cons]
        simp only [List.append_assoc, List.singleton_append]
        rfl
      · simp [hv]; scalar_tac
    · simp only [hi, ↓reduceDIte]
      simp only [bind_ok]
      have hge : it'.slice.length ≤ it'.i := by simpa using hi
      rw [← heq, List.drop_of_length_le (by simpa using hge)]
      simp
  · exact ⟨rfl, rfl, hlen⟩

/-- `recover`'s third loop collects the responses' shares. -/
theorem recover_loop2_spec
    (it : alloc.vec.into_iter.IntoIter threshold_schnorr.avss.VerifiedComplaintResponse)
    (acc : alloc.vec.Vec threshold_schnorr.avss.SharesForNode)
    (hlen : acc.length + (alloc.vec.Vec.length it) ≤ Usize.max) :
    threshold_schnorr.avss.Receiver.recover_loop2 it acc ⦃ res =>
      res.val = acc.val ++ (alloc.vec.Vec.val it).map (·.shares) ⦄ := by
  unfold threshold_schnorr.avss.Receiver.recover_loop2
  apply loop.spec_decr_nat (fun p => (alloc.vec.Vec.val p.1).length)
    (fun p => p.2.val ++ (alloc.vec.Vec.val p.1).map (·.shares) =
        acc.val ++ (alloc.vec.Vec.val it).map (·.shares) ∧
      p.2.length + (alloc.vec.Vec.length p.1) ≤ Usize.max)
  · rintro ⟨it', acc'⟩ ⟨heq, hl⟩
    dsimp only at heq hl ⊢
    unfold threshold_schnorr.avss.Receiver.recover_loop2.body
    unfold alloc.vec.into_iter.IteratorIntoIter.next
    split
    · rename_i hnil
      simp only [bind_ok]
      rw [← heq, hnil]
      simp
    · rename_i hd tl hcons
      simp only [bind_ok]
      apply WP.spec_bind (alloc.vec.Vec.push_spec acc' _ (by simp [hcons] at hl; scalar_tac))
      intro v hv
      simp only [WP.spec_ok]
      refine ⟨⟨?_, ?_⟩, ?_⟩
      · rw [← heq, hv]; simp [hcons]
      · simp [hv, hcons] at hl ⊢; scalar_tac
      · simp [hcons]
  · exact ⟨rfl, hlen⟩

/-- `nodes.weight_of(j)`, as the generated code calls it. -/
noncomputable abbrev weightOf (ns : nodes.Nodes fastcrypto.groups.ristretto255.RistrettoPoint
    fastcrypto.groups.ristretto255.RistrettoScalar) (j : Std.U16) :=
  nodes.Nodes.weight_of
    fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
    fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize ns j

/-- `recover`'s second loop adds up the responders' weights, if `weight_of` returns `W j` for each
responder `j` and the sum fits in a `u16`. -/
theorem recover_loop1_spec (ns : nodes.Nodes fastcrypto.groups.ristretto255.RistrettoPoint
      fastcrypto.groups.ristretto255.RistrettoScalar) (W : Std.U16 → Std.U16)
    (it : core.slice.iter.Iter Std.U16) (total : Std.U16) (unk : Bool)
    (hw : ∀ j ∈ it.slice.val.drop it.i, weightOf ns j = ok (core.result.Result.Ok (W j)))
    (hsum : total.val + ((it.slice.val.drop it.i).map (fun j => (W j).val)).sum ≤ U16.max) :
    threshold_schnorr.avss.Receiver.recover_loop1 it ns total unk ⦃ res =>
      res.1.val = total.val + ((it.slice.val.drop it.i).map (fun j => (W j).val)).sum ∧
        res.2 = unk ⦄ := by
  unfold threshold_schnorr.avss.Receiver.recover_loop1
  apply loop.spec_decr_nat (fun p => p.1.slice.length - p.1.i)
    (fun p => p.1.slice = it.slice ∧
      p.2.1.val + ((p.1.slice.val.drop p.1.i).map (fun j => (W j).val)).sum =
        total.val + ((it.slice.val.drop it.i).map (fun j => (W j).val)).sum ∧
      p.2.2 = unk ∧
      (∀ j ∈ p.1.slice.val.drop p.1.i, weightOf ns j = ok (core.result.Result.Ok (W j))) ∧
      p.2.1.val + ((p.1.slice.val.drop p.1.i).map (fun j => (W j).val)).sum ≤ U16.max)
  · rintro ⟨it', tot', unk'⟩ ⟨hs, heq, hu, hw', hb⟩
    dsimp only at hs heq hu hw' hb ⊢
    unfold threshold_schnorr.avss.Receiver.recover_loop1.body
    simp only [core.slice.iter.IteratorSliceIter.next]
    by_cases hi : it'.i < it'.slice.len.val
    · simp only [hi, ↓reduceDIte, bind_ok]
      have hlt : it'.i < it'.slice.length := by simpa using hi
      have hd := List.drop_eq_getElem_cons hlt
      generalize hx : it'.slice[it'.i]'hi = x
      have hxv : x = it'.slice.val[it'.i]'hlt := by rw [← hx]; rfl
      have hj : weightOf ns x = ok (core.result.Result.Ok (W x)) :=
        hw' _ (by rw [hd, hxv]; exact List.mem_cons_self ..)
      simp only [weightOf] at hj
      simp only [Std.uncurry_apply_pair, hj, bind_ok]
      rw [hd, ← hxv] at heq hb
      simp only [List.map_cons, List.sum_cons] at heq hb
      apply WP.spec_bind (UScalar.add_spec (by scalar_tac))
      intro z hz
      simp only [WP.spec_ok]
      refine ⟨⟨hs, ?_, hu, ?_, ?_⟩, by scalar_tac⟩
      · rw [hz, ← heq]; simp; omega
      · intro j hjm; exact hw' j (by rw [hd]; exact List.mem_cons_of_mem _ hjm)
      · rw [hz]; scalar_tac
    · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, WP.spec_ok]
      have hge : it'.slice.length ≤ it'.i := by simpa using hi
      rw [List.drop_of_length_le (by simpa using hge)] at heq
      simp only [List.map_nil, List.sum_nil, Nat.add_zero] at heq
      exact ⟨heq, hu⟩
  · exact ⟨rfl, rfl, rfl, hw, hsum⟩

/-- `all_distinct`'s loop keeps `distinct` true while the values seen so far are distinct, and
`seen` marks exactly the values seen so far. -/
theorem all_distinct_loop_spec (values : Slice Std.U16) (hnd : values.val.Nodup)
    (it : core.slice.iter.Iter Std.U16) (seen : alloc.vec.Vec Bool)
    (hs : it.slice = values) (hlen : seen.length = 65536)
    (hseen : ∀ x : Std.U16, seen.val[x.val]? = some (decide (x ∈ values.val.take it.i))) :
    threshold_schnorr.avss.all_distinct_loop it seen true ⦃ b => b = true ⦄ := by
  unfold threshold_schnorr.avss.all_distinct_loop
  apply loop.spec_decr_nat (fun p => p.1.slice.length - p.1.i)
    (fun p => p.1.slice = values ∧ p.2.1.length = 65536 ∧ p.2.2 = true ∧
      ∀ x : Std.U16, p.2.1.val[x.val]? = some (decide (x ∈ values.val.take p.1.i)))
  · rintro ⟨it', seen', d⟩ ⟨hs', hl, hd, hx⟩
    dsimp only at hs' hl hd hx ⊢
    subst hd hs'
    unfold threshold_schnorr.avss.all_distinct_loop.body
    simp only [core.slice.iter.IteratorSliceIter.next]
    by_cases hi : it'.i < it'.slice.len.val
    · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair]
      have hlt : it'.i < it'.slice.length := by simpa using hi
      generalize hy : it'.slice[it'.i]'hi = y
      have hyv : y = it'.slice.val[it'.i]'hlt := by rw [← hy]; rfl
      have hyb : y.val < seen'.length := by rw [hl]; scalar_tac
      have hnot : y ∉ it'.slice.val.take it'.i := by
        intro hm
        have := List.nodup_append.mp (List.take_append_drop it'.i it'.slice.val ▸ hnd)
        rw [List.drop_eq_getElem_cons hlt] at this
        exact this.2.2 y hm y (by rw [hyv]; exact List.mem_cons_self ..) rfl
      have hcast : (UScalar.cast .Usize y).val = y.val := U16.cast_Usize_val_eq y
      simp only [lift, bind_ok, alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
      apply WP.spec_bind (alloc.vec.Vec.index_usize_spec seen' _ (by rw [hcast]; exact hyb))
      intro b hb
      have hbf : b = false := by
        have h1 : seen'.val[(UScalar.cast .Usize y).val]? = some b := by rw [hb]; simp
        rw [hcast, hx y, Option.some.injEq] at h1
        rw [← h1]; simpa using hnot
      subst hbf
      simp only [Bool.false_eq_true, ↓reduceIte, bind_ok]
      apply WP.spec_bind (alloc.vec.Vec.index_mut_usize_spec seen' _ (by rw [hcast]; exact hyb))
      rintro ⟨_, back⟩ ⟨-, hback⟩
      subst hback
      simp only [Std.uncurry_apply_pair, WP.spec_ok]
      refine ⟨⟨by simp, by simp [hl], by simp, ?_⟩, by scalar_tac⟩
      intro x
      simp only [alloc.vec.Vec.set_val_eq, List.getElem?_set, hcast]
      rw [List.take_succ_eq_append_getElem hlt, ← hyv]
      by_cases hxy : y.val = x.val
      · have : y = x := by scalar_tac
        subst this
        simp [hl]; scalar_tac
      · have : y ≠ x := fun h => hxy (h ▸ rfl)
        simp only [hxy, ↓reduceIte, hx x, List.mem_append, List.mem_singleton]
        simp [Ne.symm this]
    · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, WP.spec_ok]
  · exact ⟨hs, hlen, rfl, hseen⟩

/-- `all_distinct` returns `true` for distinct values. -/
theorem all_distinct_spec (values : Slice Std.U16) (hnd : values.val.Nodup) :
    threshold_schnorr.avss.all_distinct values ⦃ b => b = true ⦄ := by
  unfold threshold_schnorr.avss.all_distinct
  apply WP.spec_bind (Usize.ShiftLeft_IScalar_spec 1#usize 16#i32 (by decide)
    (by cases System.Platform.numBits_eq <;> simp_all))
  rintro n ⟨hn, -⟩
  have hn' : n.val = 65536 := by
    rw [hn]; cases System.Platform.numBits_eq <;> simp_all [Usize.size, Usize.numBits]
  apply WP.spec_bind (alloc.vec.from_elem_spec core.clone.CloneBool false n rfl)
  rintro seen ⟨hsv, hsl⟩
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_ok]
  apply all_distinct_loop_spec values hnd _ seen rfl (by rw [hsl, hn'])
  intro x
  simp only [hsv, List.take_zero, List.not_mem_nil, decide_false]
  rw [List.getElem?_replicate]; simp [hn']; scalar_tac

end AvssProofs
