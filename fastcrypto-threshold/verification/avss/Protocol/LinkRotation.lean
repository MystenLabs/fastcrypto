-- THIS FILE IS AI-ONLY
import avss.Protocol.Link
import avss.KeyRotation
import avss.RotationCommitment
import avss.Protocol.KeyRotation

/-!
`rotation_interpolates` and `rotation_commitments` of `RotationContracts`, for the generated code:
each share from `complete_key_rotation` is `recover_c0` of the outputs' shares at its index, and
each of its commitments is the same combination of the outputs' commitments there.
(`process_matches_commitment` is in `LinkCommitment.lean`.)
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs.Link

/-- `dk.commitment_for_index(k)` as an element of `F`: `some x` if it returns
`Some(G::generator() * x)`, and `none` if it returns `None` (or a point that is not a multiple of
`G::generator()`, which does not happen in secp256k1). -/
noncomputable def commitmentForIndexOf (Z : Scalars) (dk : threshold_schnorr.avss.DkOutput)
    (k : Protocol.Shamir.ShareIndex) : Option Z.F :=
  open Classical in
  match okVal (threshold_schnorr.avss.DkOutput.commitment_for_index dk (Z.ofIndex k)) with
  | some (some e) => if h : ∃ x, e.value = Z.gen x then some h.choose else none
  | _ => none

/-- `complete_dkg`, which the generated code does not include (it takes a `HashMap`), stays
abstract. -/
noncomputable def dkgApi (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (completeDkg : List (Party C.ns × threshold_schnorr.avss.AvssOutput) →
      Option threshold_schnorr.avss.DkOutput) :
    Protocol.Avss.DkgApi (Party C.ns) (api C Z D) where
  DkOutput := threshold_schnorr.avss.DkOutput
  completeDkg := completeDkg
  shares dk := dk.my_shares
  commitmentForIndex := commitmentForIndexOf Z

/-- `DkOutput::complete_key_rotation(t, i, nodes, outputs)` as the spec's `completeKeyRotation`,
with the outputs' share indices made into `NonZeroU16`s by `ofIndex`. -/
noncomputable def completeKeyRotation (C : Receivers) (Z : Scalars) (t : ℕ) (i : Party C.ns)
    (os : List (Protocol.Shamir.ShareIndex × threshold_schnorr.avss.AvssOutput)) :
    Option threshold_schnorr.avss.DkOutput :=
  if h : t < 2 ^ 16 ∧ os.length ≤ Usize.max then
    toOption (threshold_schnorr.avss.DkOutput.complete_key_rotation
      (UScalar.ofNatCore t (by simpa using h.1)) i.val C.ns
      (Slice.from (os.map fun o => ⟨Z.ofIndex o.1, o.2⟩) (by simpa using h.2)))
  else none

/-- `Poly::recover_c0` is `Σⱼ yⱼ·λⱼ·c` for the Lagrange coefficients `(c, λ)` that
`get_lagrange_coefficients_for_c0` returns for the same indices, as `recover_c0` computes it. -/
def LagrangeRecover (Z : Scalars) : Prop :=
  ∀ t s c lambdas, lagrangeC0 t s = ok (core.result.Result.Ok (c, lambdas)) →
    ∀ ys : List Z.F, ys.length = s.val.length →
      Z.recoverC0 t.val (List.zipWith Protocol.Shamir.Eval.mk (s.val.map idx) ys) =
        .ok (List.zipWith (· * ·) ys (lambdas.val.map fun l => Z.toF l * Z.toF c)).sum

theorem idx_ofIndex (Z : Scalars) (hnz : NonZeroModel Z) k : idx (Z.ofIndex k) = k := by
  obtain ⟨hpos, -, hof⟩ := hnz
  obtain ⟨u, hu, huv⟩ := hof k
  have h : ∃ u : Std.U16, nzGet (Z.ofIndex k) = ok u ∧ 0 < u.val := ⟨u, hu, huv ▸ k.2.1⟩
  have hc : h.choose = u := by
    have h2 : ok u = ok h.choose := hu.symm.trans h.choose_spec.1
    rw [Result.ok_injective.eq_iff] at h2
    exact h2.symm
  apply Subtype.ext
  unfold idx
  rw [dite_eq_left_of_eq_true (eq_true h)]
  simp [hc, huv]

theorem rotation_interpolates (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (completeDkg : List (Party C.ns × threshold_schnorr.avss.AvssOutput) →
      Option threshold_schnorr.avss.DkOutput)
    (hf : ScalarHom Z.toF) (hnz : NonZeroModel Z) (hlr : LagrangeRecover Z)
    (t : ℕ) (i : Party C.ns)
    (os : List (Protocol.Shamir.ShareIndex × threshold_schnorr.avss.AvssOutput))
    (dk : threshold_schnorr.avss.DkOutput)
    (v : Protocol.Shamir.ShareIndex × threshold_schnorr.avss.AvssOutput →
      Protocol.Shamir.ShareIndex → Z.F)
    (h : completeKeyRotation C Z t i os = some dk)
    (hos : ∀ o ∈ os, (api C Z D).shareList ((api C Z D).shares o.2) =
      ((api C Z D).shareIds i).map fun k => ⟨k, v o k⟩) :
    ∃ w : Protocol.Shamir.ShareIndex → Z.F,
      (api C Z D).shareList ((dkgApi C Z D completeDkg).shares dk) =
        ((api C Z D).shareIds i).map (fun k => ⟨k, w k⟩) ∧
      ∀ k ∈ (api C Z D).shareIds i,
        (api C Z D).Sh.recoverC0 t (os.map fun o => ⟨o.1, v o k⟩) = .ok (w k) := by
  unfold completeKeyRotation at h
  split at h
  swap
  · simp at h
  rename_i ht
  have hck := toOption_eq_some.mp h
  set L := os.map fun o =>
    (⟨Z.ofIndex o.1, o.2⟩ : types.IndexedValue threshold_schnorr.avss.AvssOutput) with hL
  let V := fun (iv : types.IndexedValue threshold_schnorr.avss.AvssOutput) nz =>
    v (idx iv.index, iv.value) (idx nz)
  have hV : ∀ o ∈ (Slice.from L (by simpa [hL] using ht.2)).val,
      ∀ s ∈ (o : types.IndexedValue _).value.my_shares.shares.val, Z.toF s.value = V o s.index := by
    intro o ho s hs
    rw [Slice.from_val, hL, List.mem_map] at ho
    obtain ⟨⟨u, out⟩, hmem, rfl⟩ := ho
    have hsl := hos _ hmem
    have hin : (⟨idx s.index, Z.toF s.value⟩ : Protocol.Shamir.Eval Z.F) ∈
        (api C Z D).shareList ((api C Z D).shares (u, out).2) := by
      show _ ∈ out.my_shares.shares.val.map _
      exact List.mem_map_of_mem hs
    rw [hsl] at hin
    obtain ⟨k, -, hk⟩ := List.mem_map.mp hin
    have hk1 := congrArg Protocol.Shamir.Eval.index hk
    have hk2 := congrArg Protocol.Shamir.Eval.value hk
    simp only at hk1 hk2
    simp only [V, idx_ofIndex Z hnz]
    rw [← hk1, hk2]
  obtain ⟨ids, c, lambdas, oi, hsid, hlen, hoi, hlag, hmap⟩ :=
    complete_key_rotation_ok hf hnz.2.1 _ _ _ _ dk V hV hck
  have hsids : (api C Z D).shareIds i = ids.val.map idx := by
    show ((toOption (shareIdsOf C.ns i.val)).map _).getD [] = _
    rw [toOption_eq_some.mpr hsid]
    rfl
  let lam := lambdas.val.map fun l => Z.toF l * Z.toF c
  refine ⟨fun k => (List.zipWith (fun o l => v o k * l) os lam).sum, ?_, ?_⟩
  · rw [hsids]
    show dk.my_shares.shares.val.map
      (fun s => (⟨idx s.index, Z.toF s.value⟩ : Protocol.Shamir.Eval Z.F)) = _
    have := congrArg (List.map fun p => (⟨idx p.1, p.2⟩ : Protocol.Shamir.Eval Z.F)) hmap
    simp only [List.map_map, Function.comp_def] at this
    rw [this, List.map_map]
    apply List.map_congr_left
    intro nz _
    simp only [Function.comp_apply]
    rw [Slice.from_val, hL, List.zipWith_map_left]
    simp only [V, idx_ofIndex Z hnz]
    rfl
  · intro k _
    have hys : (os.map fun o => v o k).length = (alloc.vec.Vec.deref oi).val.length := by
      rw [vec_deref_val, hoi, Slice.from_val]; simp [hL]
    have hr := hlr _ _ c lambdas hlag (os.map fun o => v o k) hys
    have hidx : (alloc.vec.Vec.deref oi).val.map idx = os.map (·.1) := by
      rw [vec_deref_val, hoi, Slice.from_val, hL, List.map_map, List.map_map]
      apply List.map_congr_left
      intro o _
      simp [idx_ofIndex Z hnz]
    rw [hidx] at hr
    have hzip : List.zipWith Protocol.Shamir.Eval.mk (os.map (·.1)) (os.map fun o => v o k) =
        os.map fun o => ⟨o.1, v o k⟩ := by
      rw [List.zipWith_map_left, List.zipWith_map_right, List.zipWith_self]
    rw [hzip, List.zipWith_map_left] at hr
    exact hr

/-- `Poly::eval` on commitments over secp256k1 returns, and returns a multiple of
`G::generator()` (the group has prime order). -/
def EvalInGroup (Z : Scalars) : Prop :=
  ∀ p k, ∃ x iv, evalG p k = ok iv ∧ iv.value = Z.gen x

theorem rotation_commitments (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (completeDkg : List (Party C.ns × threshold_schnorr.avss.AvssOutput) →
      Option threshold_schnorr.avss.DkOutput)
    (hf : ScalarHom Z.toF) (hnz : NonZeroModel Z) (hlr : LagrangeRecover Z)
    (hpclone : PolyCloneIsId) (hmsm : MsmEval Z.toF Z.gen) (hrange : EvalRangeSound)
    (hgrp : EvalInGroup Z) (hinj : Function.Injective Z.gen)
    (t : ℕ) (i : Party C.ns)
    (os : List (Protocol.Shamir.ShareIndex × threshold_schnorr.avss.AvssOutput))
    (dk : threshold_schnorr.avss.DkOutput) (k : Protocol.Shamir.ShareIndex) (x : Z.F)
    (h : completeKeyRotation C Z t i os = some dk)
    (hx : (dkgApi C Z D completeDkg).commitmentForIndex dk k = some x) :
    (api C Z D).Sh.recoverC0 t (os.map fun o => ⟨o.1, (api C Z D).committed o.2 k⟩) = .ok x := by
  unfold completeKeyRotation at h
  split at h
  swap
  · simp at h
  rename_i ht
  have hck := toOption_eq_some.mp h
  change commitmentForIndexOf Z dk k = some x at hx
  unfold commitmentForIndexOf at hx
  split at hx
  swap
  · simp at hx
  rename_i e he
  split at hx
  swap
  · simp at hx
  rename_i hex
  simp only [Option.some.injEq] at hx
  have hgx : e.value = Z.gen x := hx ▸ hex.choose_spec
  have he' := okVal_eq_some.mp he
  set L := os.map fun o =>
    (⟨Z.ofIndex o.1, o.2⟩ : types.IndexedValue threshold_schnorr.avss.AvssOutput) with hL
  -- `y p`: the `x` with `p.eval(k) = G::generator() * x`, as `committedOf` takes it.
  let y := fun (p : polynomial.Poly Point) =>
    open Classical in
    if h : ∃ x iv, evalG p (Z.ofIndex k) = ok iv ∧ iv.value = Z.gen x then h.choose else 0
  have hy : ∀ o ∈ (Slice.from L (by simpa [hL] using ht.2)).val,
      ∃ iv, evalG (o : types.IndexedValue _).value.feldman_commitment (Z.ofIndex k) = ok iv ∧
        iv.value = Z.gen (y o.value.feldman_commitment) := by
    intro o _
    have hex := hgrp o.value.feldman_commitment (Z.ofIndex k)
    simp only [y, dite_eq_left_of_eq_true (eq_true hex)]
    obtain ⟨iv, hiv, hv⟩ := hex.choose_spec
    exact ⟨iv, hiv, hv⟩
  obtain ⟨c, lambdas, oi, hoi, hlag, hval⟩ :=
    complete_key_rotation_commitment hf hnz.2.1 hpclone hmsm hrange _ _ _ _ dk _ e y hy hck he'
  have hys : (os.map fun o => y o.2.feldman_commitment).length =
      (alloc.vec.Vec.deref oi).val.length := by
    rw [vec_deref_val, hoi, Slice.from_val]; simp [hL]
  have hr := hlr _ _ c lambdas hlag (os.map fun o => y o.2.feldman_commitment) hys
  have hidx : (alloc.vec.Vec.deref oi).val.map idx = os.map (·.1) := by
    rw [vec_deref_val, hoi, Slice.from_val, hL, List.map_map, List.map_map]
    apply List.map_congr_left
    intro o _
    simp [idx_ofIndex Z hnz]
  rw [hidx, List.zipWith_map_left, List.zipWith_map_right, List.zipWith_self] at hr
  have hsum : Z.gen x = Z.gen (List.zipWith (fun o l => y o.2.feldman_commitment * l) os
      (lambdas.val.map fun l => Z.toF l * Z.toF c)).sum := by
    rw [← hgx, hval, Slice.from_val, hL, List.zipWith_map_left]
  rw [hinj hsum, ← List.zipWith_map_left]
  exact hr

end AvssProofs.Link
