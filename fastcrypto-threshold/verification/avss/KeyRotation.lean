-- THIS FILE IS AI-ONLY
import avss.Generated.Funs
import avss.Result
import avss.FeldmanBinding
import avss.RecoverComplete

/-!
What the generated `DkOutput::complete_key_rotation` returns.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

universe u

/-- If a loop returns `ok r`, `r` satisfies `Post`, when each step that returns keeps `Inv` and
decreases `μ`, and each step that stops gives `Post`. -/
theorem loop_ok_induct {α β : Type u} (body : α → Result (ControlFlow α β)) (μ : α → ℕ)
    (Inv : α → Prop) (Post : β → Prop)
    (h : ∀ x, Inv x → ∀ c, body x = ok c →
      match c with
      | .cont y => Inv y ∧ μ y < μ x
      | .done r => Post r) :
    ∀ x r, Inv x → loop body x = ok r → Post r := by
  intro x
  induction hm : μ x using Nat.strong_induction_on generalizing x with
  | _ n ih =>
  intro r hx hl
  rw [loop] at hl
  obtain ⟨c, hc, hl⟩ := bind_eq_ok hl
  have := h x hx c hc
  cases c with
  | cont y =>
    exact ih (μ y) (hm ▸ this.2) y rfl r this.1 hl
  | done r' =>
    simp only [Result.ok_injective.eq_iff] at hl
    subst hl; exact this

/-- `share_for_index` returns a share of `sh` with the asked index. -/
theorem share_for_index_some (sh : threshold_schnorr.avss.SharesForNode) index s
    (h : threshold_schnorr.avss.SharesForNode.share_for_index sh index = ok (some s)) :
    s ∈ sh.shares.val ∧ ∃ u, nzGet s.index = ok u ∧ nzGet index = ok u := by
  unfold threshold_schnorr.avss.SharesForNode.share_for_index at h
  simp only [SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
    bind_ok] at h
  unfold threshold_schnorr.avss.SharesForNode.share_for_index_loop at h
  refine loop_ok_induct _ (fun it => it.slice.length - it.i)
    (fun it => it.slice = alloc.vec.Vec.deref sh.shares)
    (fun r => ∀ s, r = some s → s ∈ sh.shares.val ∧ ∃ u, nzGet s.index = ok u ∧ nzGet index = ok u)
    ?_ _ _ rfl h s rfl
  intro it hit c hc
  unfold threshold_schnorr.avss.SharesForNode.share_for_index_loop.body at hc
  simp only [core.slice.iter.IteratorSliceIter.next] at hc
  by_cases hi : it.i < it.slice.len.val
  · have hlt : it.i < it.slice.length := by simpa using hi
    simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair] at hc
    generalize hy : it.slice[it.i]'hi = y at hc
    have hyv : y = it.slice.val[it.i]'hlt := by rw [← hy]; rfl
    obtain ⟨u, hu, hc⟩ := bind_eq_ok hc
    obtain ⟨u', hu', hc⟩ := bind_eq_ok hc
    split at hc
    · rename_i heq
      simp only [Result.ok_injective.eq_iff] at hc
      subst hc
      rintro s' ⟨⟩
      refine ⟨?_, u, hu, ?_⟩
      · rw [hyv]
        have : it.slice.val = sh.shares.val := by rw [hit, vec_deref_val]
        rw [← this]; exact List.getElem_mem _
      · simp only [nzGet, hu', heq]
    · simp only [Result.ok_injective.eq_iff] at hc
      subst hc
      exact ⟨hit, by dsimp only; omega⟩
  · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hc
    subst hc
    intro s' h'; cases h'

abbrev Scalar := fastcrypto.groups.secp256k1.Scalar

/-- `f` maps secp256k1 scalars into a field, and the scalar arithmetic that
`complete_key_rotation` uses (`zero`, `+=`, and the two forms of `*`) to the field's. -/
structure ScalarHom {F : Type} [Field F] (f : Scalar → F) : Prop where
  zero : ∀ z, fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsAdditiveGroup.zero = ok z →
    f z = 0
  addAssign : ∀ a b r,
    fastcrypto.groups.secp256k1.Scalar.Insts.CoreOpsArithAddAssignScalar.add_assign a b = ok r →
      f r = f a + f b
  mul : ∀ a b r, Shared0Scalar.Insts.CoreOpsArithMulScalarScalar.mul a b = ok r → f r = f a * f b
  mul' : ∀ a b r,
    fastcrypto.groups.secp256k1.Scalar.Insts.CoreOpsArithMulShared0ScalarScalar.mul a b = ok r →
      f r = f a * f b

/-- `Vec::push` appends, when it returns. -/
theorem push_ok {α : Type _} {v : alloc.vec.Vec α} {x : α} {v1 : alloc.vec.Vec α}
    (h : v.push x = ok v1) : v1.val = v.val ++ [x] := by
  unfold alloc.vec.Vec.push at h
  dsimp only at h
  split at h
  · simp only [Result.ok_injective.eq_iff] at h
    subst h; simp [alloc.vec.Vec.from_val]
  · exact absurd h fail_ne_ok

/-- The first loop collects the outputs' indices and their values. -/
theorem ckr_loop0_ok it oi ov r
    (h : threshold_schnorr.avss.DkOutput.complete_key_rotation_loop0 it oi ov = ok r) :
    r.1.val = oi.val ++ (it.slice.val.drop it.i).map (·.index) := by
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop0 at h
  refine loop_ok_induct _ (fun st => st.1.slice.length - st.1.i)
    (fun st => st.1.slice = it.slice ∧
      st.2.1.val ++ (st.1.slice.val.drop st.1.i).map (·.index) =
        oi.val ++ (it.slice.val.drop it.i).map (·.index))
    (fun r => r.1.val = oi.val ++ (it.slice.val.drop it.i).map (·.index)) ?_ _ _ ⟨rfl, rfl⟩ h
  rintro ⟨it', oi', ov'⟩ ⟨hs, heq⟩ c hc
  dsimp only at hs heq hc ⊢
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop0.body at hc
  simp only [core.slice.iter.IteratorSliceIter.next] at hc
  by_cases hi : it'.i < it'.slice.len.val
  · have hlt : it'.i < it'.slice.length := by simpa using hi
    simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair] at hc
    generalize hy : it'.slice[it'.i]'hi = y at hc
    have hyv : y = it'.slice.val[it'.i]'hlt := by rw [← hy]; rfl
    obtain ⟨a, ha, hc⟩ := bind_eq_ok hc
    obtain ⟨_, -, hc⟩ := bind_eq_ok hc
    obtain ⟨_, -, hc⟩ := bind_eq_ok hc
    simp only [Result.ok_injective.eq_iff] at hc
    subst hc
    refine ⟨⟨hs, ?_⟩, by dsimp only; omega⟩
    rw [push_ok ha, ← heq, List.drop_eq_getElem_cons hlt, ← hyv]
    simp
  · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hc
    subst hc
    have hge : it'.slice.length ≤ it'.i := by simpa using hi
    rw [← heq, List.drop_of_length_le (by simpa using hge)]
    simp

/-- The second loop multiplies each Lagrange coefficient by `c`. -/
theorem ckr_loop1_ok {F : Type} [Field F] {f : Scalar → F} (hf : ScalarHom f) it c acc r
    (h : threshold_schnorr.avss.DkOutput.complete_key_rotation_loop1 it c acc = ok r) :
    r.val.map f = acc.val.map f ++ (it.slice.val.drop it.i).map (fun l => f l * f c) := by
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop1 at h
  refine loop_ok_induct _ (fun st => st.1.slice.length - st.1.i)
    (fun st => st.1.slice = it.slice ∧
      st.2.val.map f ++ (st.1.slice.val.drop st.1.i).map (fun l => f l * f c) =
        acc.val.map f ++ (it.slice.val.drop it.i).map (fun l => f l * f c))
    (fun r => r.val.map f = acc.val.map f ++ (it.slice.val.drop it.i).map (fun l => f l * f c))
    ?_ _ _ ⟨rfl, rfl⟩ h
  rintro ⟨it', acc'⟩ ⟨hs, heq⟩ c' hc
  dsimp only at hs heq hc ⊢
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop1.body at hc
  simp only [core.slice.iter.IteratorSliceIter.next] at hc
  by_cases hi : it'.i < it'.slice.len.val
  · have hlt : it'.i < it'.slice.length := by simpa using hi
    simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair] at hc
    generalize hy : it'.slice[it'.i]'hi = y at hc
    have hyv : y = it'.slice.val[it'.i]'hlt := by rw [← hy]; rfl
    obtain ⟨m, hm, hc⟩ := bind_eq_ok hc
    obtain ⟨a, ha, hc⟩ := bind_eq_ok hc
    simp only [Result.ok_injective.eq_iff] at hc
    subst hc
    refine ⟨⟨hs, ?_⟩, by dsimp only; omega⟩
    rw [push_ok ha, ← heq, List.drop_eq_getElem_cons hlt, ← hyv]
    simp [hf.mul _ _ _ hm]
  · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hc
    subst hc
    have hge : it'.slice.length ≤ it'.i := by simpa using hi
    rw [← heq, List.drop_of_length_le (by simpa using hge)]
    simp

abbrev OutIter := core.slice.iter.Iter (types.IndexedValue threshold_schnorr.avss.AvssOutput)

/-- The inner share loop: if no share was missing, the value is the sum of each output's share
(`V o` in the field) times its coefficient. -/
theorem ckr_inner_ok {F : Type} [Field F] {f : Scalar → F} (hf : ScalarHom f) nz
    (V : types.IndexedValue threshold_schnorr.avss.AvssOutput → F)
    (z : core.iter.adapters.zip.Zip OutIter (core.slice.iter.Iter Scalar)) miss val r
    (hV : ∀ o ∈ z.fst.slice.val.drop z.fst.i, ∀ s,
      threshold_schnorr.avss.AvssOutput.share_for_index o.value nz = ok (some s) → f s.value = V o)
    (h : threshold_schnorr.avss.DkOutput.complete_key_rotation_loop3_loop0 z miss nz val = ok r) :
    r.1 = false → miss = false ∧ f r.2 = f val +
      (((z.fst.slice.val.drop z.fst.i).zip (z.snd.slice.val.drop z.snd.i)).map
        fun p => V p.1 * f p.2).sum := by
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop3_loop0 at h
  let rem := fun (z' : core.iter.adapters.zip.Zip OutIter (core.slice.iter.Iter Scalar)) =>
    (((z'.fst.slice.val.drop z'.fst.i).zip (z'.snd.slice.val.drop z'.snd.i)).map
      fun p => V p.1 * f p.2).sum
  refine loop_ok_induct _ (fun st => st.1.fst.slice.length - st.1.fst.i)
    (fun st => st.1.fst.slice = z.fst.slice ∧
      (∀ o ∈ st.1.fst.slice.val.drop st.1.fst.i, ∀ s,
        threshold_schnorr.avss.AvssOutput.share_for_index o.value nz = ok (some s) →
          f s.value = V o) ∧
      (st.2.1 = false → miss = false ∧ f st.2.2 + rem st.1 = f val + rem z))
    (fun r => r.1 = false → miss = false ∧ f r.2 = f val + rem z) ?_ _ _
    ⟨rfl, hV, fun hm => ⟨hm, rfl⟩⟩ h
  rintro ⟨z', m', v'⟩ ⟨hs, hV', hinv⟩ c hc
  dsimp only at hs hV' hinv hc ⊢
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop3_loop0.body at hc
  simp only [core.iter.adapters.zip.Zip.Insts.CoreIterTraitsIteratorIteratorPair.next,
    core.slice.iter.IteratorSliceIter.next] at hc
  by_cases ha : z'.fst.i < z'.fst.slice.len.val
  · have hla : z'.fst.i < z'.fst.slice.length := by simpa using ha
    by_cases hb : z'.snd.i < z'.snd.slice.len.val
    · have hlb : z'.snd.i < z'.snd.slice.length := by simpa using hb
      simp only [ha, hb, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair] at hc
      generalize hx : z'.fst.slice[z'.fst.i]'ha = x at hc
      generalize hy : z'.snd.slice[z'.snd.i]'hb = y at hc
      have hxv : x = z'.fst.slice.val[z'.fst.i]'hla := by rw [← hx]; rfl
      have hyv : y = z'.snd.slice.val[z'.snd.i]'hlb := by rw [← hy]; rfl
      have hd1 := List.drop_eq_getElem_cons hla
      have hd2 := List.drop_eq_getElem_cons hlb
      rw [← hxv] at hd1
      rw [← hyv] at hd2
      have hremz : rem ⟨z'.fst, z'.snd⟩ = V x * f y +
          rem ⟨⟨z'.fst.slice, z'.fst.i + 1⟩, ⟨z'.snd.slice, z'.snd.i + 1⟩⟩ := by
        simp only [rem, hd1, hd2, List.zip_cons_cons, List.map_cons, List.sum_cons]
      obtain ⟨o, ho, hc⟩ := bind_eq_ok hc
      rw [hd1] at hV'
      cases o with
      | none =>
        simp only [Result.ok_injective.eq_iff] at hc
        subst hc
        refine ⟨⟨hs, fun o' ho' => hV' o' (List.mem_cons_of_mem _ ho'), by simp⟩, by dsimp only; omega⟩
      | some sh =>
        obtain ⟨a, hma, hc⟩ := bind_eq_ok hc
        obtain ⟨b, hab, hc⟩ := bind_eq_ok hc
        simp only [Result.ok_injective.eq_iff] at hc
        subst hc
        refine ⟨⟨hs, fun o' ho' => hV' o' (List.mem_cons_of_mem _ ho'), ?_⟩, by dsimp only; omega⟩
        intro hm
        obtain ⟨hmiss, hsum⟩ := hinv hm
        refine ⟨hmiss, ?_⟩
        rw [← hsum, hremz, hf.addAssign _ _ _ hab, hf.mul' _ _ _ hma,
          hV' x (List.mem_cons_self ..) sh ho]
        ring
    · simp only [ha, hb, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair,
        Result.ok_injective.eq_iff] at hc
      subst hc
      intro hm
      obtain ⟨hmiss, hsum⟩ := hinv hm
      have hge : z'.snd.slice.length ≤ z'.snd.i := by simpa using hb
      have h0 : rem z' = 0 := by
        simp [rem, List.drop_of_length_le (l := z'.snd.slice.val) (by simpa using hge)]
      exact ⟨hmiss, by rw [← hsum, h0, add_zero]⟩
  · simp only [ha, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hc
    subst hc
    intro hm
    obtain ⟨hmiss, hsum⟩ := hinv hm
    have hge : z'.fst.slice.length ≤ z'.fst.i := by simpa using ha
    have h0 : rem z' = 0 := by
      simp [rem, List.drop_of_length_le (l := z'.fst.slice.val) (by simpa using hge)]
    exact ⟨hmiss, by rw [← hsum, h0, add_zero]⟩

/-- The outer share loop: if no share was missing, the share at each of `my_indices` is the sum
of the outputs' shares there (`V o nz`) times their coefficients. -/
theorem ckr_loop3_ok {F : Type} [Field F] {f : Scalar → F} (hf : ScalarHom f)
    (outputs : Slice (types.IndexedValue threshold_schnorr.avss.AvssOutput))
    (lc : alloc.vec.Vec Scalar)
    (V : types.IndexedValue threshold_schnorr.avss.AvssOutput →
      core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner → F)
    (it : core.slice.iter.Iter
      (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner))
    shares miss r
    (hV : ∀ nz ∈ it.slice.val.drop it.i, ∀ o ∈ outputs.val, ∀ s,
      threshold_schnorr.avss.AvssOutput.share_for_index o.value nz = ok (some s) →
        f s.value = V o nz)
    (h : threshold_schnorr.avss.DkOutput.complete_key_rotation_loop3 it outputs lc shares miss =
      ok r) :
    r.2 = false → miss = false ∧
      r.1.val.map (fun s => (s.index, f s.value)) =
        shares.val.map (fun s => (s.index, f s.value)) ++ (it.slice.val.drop it.i).map
          fun nz => (nz, ((outputs.val.zip lc.val).map fun p => V p.1 nz * f p.2).sum) := by
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop3 at h
  let g := fun s : types.IndexedValue Scalar => (s.index, f s.value)
  let W := fun nz => (nz, ((outputs.val.zip lc.val).map fun p => V p.1 nz * f p.2).sum)
  refine loop_ok_induct _ (fun st => st.1.slice.length - st.1.i)
    (fun st => st.1.slice = it.slice ∧
      (∀ nz ∈ st.1.slice.val.drop st.1.i, ∀ o ∈ outputs.val, ∀ s,
        threshold_schnorr.avss.AvssOutput.share_for_index o.value nz = ok (some s) →
          f s.value = V o nz) ∧
      (st.2.2 = false → miss = false ∧
        st.2.1.val.map g ++ (st.1.slice.val.drop st.1.i).map W =
          shares.val.map g ++ (it.slice.val.drop it.i).map W))
    (fun r => r.2 = false → miss = false ∧
      r.1.val.map g = shares.val.map g ++ (it.slice.val.drop it.i).map W) ?_ _ _
    ⟨rfl, hV, fun hm => ⟨hm, rfl⟩⟩ h
  rintro ⟨it', sh', m'⟩ ⟨hs, hV', hinv⟩ c hc
  dsimp only at hs hV' hinv hc ⊢
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop3.body at hc
  simp only [core.slice.iter.IteratorSliceIter.next] at hc
  by_cases hi : it'.i < it'.slice.len.val
  · have hlt : it'.i < it'.slice.length := by simpa using hi
    simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, core.slice.Slice.iter,
      core.iter.traits.iterator.Iterator.zip.trait_default,
      core.iter.traits.iterator.Iterator.zip.default,
      SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter] at hc
    generalize hy : it'.slice[it'.i]'hi = nz at hc
    have hyv : nz = it'.slice.val[it'.i]'hlt := by rw [← hy]; rfl
    have hd := List.drop_eq_getElem_cons hlt
    rw [← hyv] at hd
    rw [hd] at hV'
    obtain ⟨z0, hz0, hc⟩ := bind_eq_ok hc
    obtain ⟨⟨m1, v1⟩, hin, hc⟩ := bind_eq_ok hc
    obtain ⟨sh1, hpush, hc⟩ := bind_eq_ok hc
    simp only [Result.ok_injective.eq_iff] at hc
    subst hc
    have hinner := ckr_inner_ok hf nz (fun o => V o nz) _ _ _ _
      (fun o ho s hs' => hV' nz (List.mem_cons_self ..) o (by simpa using ho) s hs') hin
    refine ⟨⟨hs, fun nz' hnz' => hV' nz' (List.mem_cons_of_mem _ hnz'), ?_⟩, by dsimp only; omega⟩
    intro hm
    obtain ⟨hm', hval⟩ := hinner hm
    obtain ⟨hmiss, heq⟩ := hinv hm'
    refine ⟨hmiss, ?_⟩
    rw [← heq, hd, push_ok hpush]
    simp only [List.map_append, List.map_cons, List.map_nil, List.append_assoc, List.cons_append,
      List.nil_append, g, W]
    rw [hval, hf.zero _ hz0, zero_add]
    simp [vec_deref_val]
  · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hc
    subst hc
    intro hm
    obtain ⟨hmiss, heq⟩ := hinv hm
    have hge : it'.slice.length ≤ it'.i := by simpa using hi
    refine ⟨hmiss, ?_⟩
    rw [← heq, List.drop_of_length_le (by simpa using hge)]
    simp

theorem map_zip_eq_zipWith {α β γ δ : Type _} (g : α → γ → δ) (f : β → γ) :
    ∀ (l₁ : List α) (l₂ : List β),
      (l₁.zip l₂).map (fun p => g p.1 (f p.2)) = List.zipWith g l₁ (l₂.map f)
  | [], _ => by simp
  | _ :: _, [] => by simp
  | a :: l₁, b :: l₂ => by simp [map_zip_eq_zipWith g f l₁ l₂]

/-- `Poly::get_lagrange_coefficients_for_c0(t, indices.iter())` for share indices in a slice. -/
noncomputable abbrev lagrangeC0 (t : Std.U16)
    (s : Slice (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner)) :=
  polynomial.Poly.get_lagrange_coefficients_for_c0
    fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
    fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar
    (Shared0T.Insts.CoreBorrowBorrow
      (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner))
    (core.iter.traits.iterator.IteratorSliceIter
      (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner)) t ⟨s, 0⟩

/-- `complete_key_rotation(t, my_id, nodes, outputs) = Ok(dk)` ⇒ there are `t` outputs, and with
`(c, λ)` the Lagrange coefficients for the outputs' indices, the share of `dk` at each of
`share_ids_of(my_id)` is `Σᵤ Vᵤ · λᵤ · c`, where `Vᵤ` is output `u`'s share there (in the field
`f` maps the scalars to). -/
theorem complete_key_rotation_ok {F : Type} [Field F] {f : Scalar → F} (hf : ScalarHom f)
    (hnz : NonZeroGetInj) t my ns outputs dk
    (V : types.IndexedValue threshold_schnorr.avss.AvssOutput →
      core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner → F)
    (hV : ∀ o ∈ outputs.val, ∀ s ∈ (o : types.IndexedValue _).value.my_shares.shares.val,
      f s.value = V o s.index)
    (h : threshold_schnorr.avss.DkOutput.complete_key_rotation t my ns outputs =
      ok (core.result.Result.Ok dk)) :
    ∃ ids c lambdas,
    ∃ oi : alloc.vec.Vec (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner),
      nodes.Nodes.share_ids_of
        fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
        fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize ns my =
          ok (core.result.Result.Ok ids) ∧
      outputs.val.length = t.val ∧ oi.val = outputs.val.map (·.index) ∧
      lagrangeC0 t (alloc.vec.Vec.deref oi) = ok (core.result.Result.Ok (c, lambdas)) ∧
      dk.my_shares.shares.val.map (fun s => (s.index, f s.value)) =
        ids.val.map fun nz => (nz, (List.zipWith (fun o l => V o nz * l) outputs.val
          (lambdas.val.map fun l => f l * f c)).sum) := by
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation at h
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter,
    core.slice.Slice.iter, SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
    lift, bind_ok] at h
  ok_inv at h
  subst h
  simp only [Bool.not_eq_true] at *
  have h0 := ckr_loop0_ok _ _ _ _ ‹threshold_schnorr.avss.DkOutput.complete_key_rotation_loop0 _ _ _ = ok _›
  have h1 := ckr_loop1_ok hf _ _ _ _ ‹threshold_schnorr.avss.DkOutput.complete_key_rotation_loop1 _ _ _ = ok _›
  have h3 := fun hV' => ckr_loop3_ok hf outputs _ V _ _ _ _ hV'
    ‹threshold_schnorr.avss.DkOutput.complete_key_rotation_loop3 _ _ _ _ _ = ok _›
  have hV' : ∀ nz ∈ (alloc.vec.Vec.deref ‹alloc.vec.Vec (core.num.nonzero.NonZero Std.U16
      core.num.niche_types.NonZeroU16Inner)›).val.drop 0, ∀ o ∈ outputs.val, ∀ s,
      threshold_schnorr.avss.AvssOutput.share_for_index o.value nz = ok (some s) →
        f s.value = V o nz := by
    intro nz _ o ho s hs
    unfold threshold_schnorr.avss.AvssOutput.share_for_index at hs
    obtain ⟨hmem, u, hu1, hu2⟩ := share_for_index_some _ _ _ hs
    rw [← hnz _ _ u hu1 hu2]
    exact hV o ho s hmem
  obtain ⟨-, hm⟩ := h3 hV' (by assumption)
  have hlen : outputs.len = UScalar.cast .Usize t := by
    simpa using ‹(outputs.len != UScalar.cast .Usize t) = false›
  refine ⟨_, _, _, _, ‹nodes.Nodes.share_ids_of _ _ _ _ = ok _›, ?_, ?_,
    ‹polynomial.Poly.get_lagrange_coefficients_for_c0 _ _ _ _ _ _ = ok _›, ?_⟩
  · have := congrArg UScalar.val hlen
    simpa [U16.cast_Usize_val_eq] using this
  · simpa using h0
  · rw [hm]
    simp only [List.drop_zero, vec_deref_val]
    apply List.map_congr_left
    intro nz _
    simp only [Prod.mk.injEq, true_and]
    rw [map_zip_eq_zipWith (fun o l => V o nz * l) f, h1]
    simp [vec_deref_val]

end AvssProofs
