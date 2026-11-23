import Avss.Protocol.Link
import Avss.KeyRotation
import Avss.Protocol.KeyRotation

/-!
`rotation_interpolates` of `RotationContracts`, for the generated code: each share from
`complete_key_rotation` is `recover_c0` of the outputs' shares at its index.
(`process_matches_commitment` is in `LinkCommitment.lean`.)
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs.Link

/-- `complete_dkg` and `commitment_for_index`, which the generated code does not include, stay
abstract. -/
noncomputable def dkgApi (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (completeDkg : List (Party C.ns × threshold_schnorr.avss.AvssOutput) →
      Option threshold_schnorr.avss.DkOutput)
    (commitmentForIndex : threshold_schnorr.avss.DkOutput → Protocol.Shamir.ShareIndex →
      Option Z.F) :
    Protocol.Avss.DkgApi (Party C.ns) (api C Z D) where
  DkOutput := threshold_schnorr.avss.DkOutput
  completeDkg := completeDkg
  shares dk := dk.my_shares
  commitmentForIndex := commitmentForIndex

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
    (commitmentForIndex : threshold_schnorr.avss.DkOutput → Protocol.Shamir.ShareIndex →
      Option Z.F)
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
      (api C Z D).shareList ((dkgApi C Z D completeDkg commitmentForIndex).shares dk) =
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

end AvssProofs.Link
