import AvssProofs.Link
import AvssProofs.VerifyComplete
import AvssProofs.KeyRotation
import FastcryptoSpecs.Avss.KeyRotation

/-!
The contracts of fastcrypto-specs' `RotationContracts`, for the generated code:
`process_matches_commitment` (a receiver created with `commitment = Some(G::generator() * s)` that
accepts a message gets only polynomials with constant term `s`) and `rotation_interpolates` (each
share from `complete_key_rotation` is `recover_c0` of the outputs' shares at its index).
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs.Link

/-- `G::generator() * s` for `s` in the spec's field. -/
abbrev Generator (Z : Scalars) := Z.F → fastcrypto.groups.secp256k1.ProjectivePoint

/-- Feldman commitments over secp256k1 open to a polynomial, which depends on the group and on
`Poly::verify_share`, `Poly::eval` and `Poly::c0`: a commitment `c` of degree `d` commits to a
polynomial `p` over the scalars of degree at most `d` whose `eval` returns, such that a share
passes `verify_share` exactly when its value is `p.eval` at its index, and
`c.c0() = G::generator() * p.c0()`. This implies `CommitmentBinding`. -/
def CommitmentOpening (Z : Scalars) (gen : Generator Z) : Prop :=
  ∀ (c : polynomial.Poly fastcrypto.groups.secp256k1.ProjectivePoint) d, degreeG c = ok d →
    ∃ p e, degreeS p = ok e ∧ e.val ≤ d.val ∧ (∀ k, ∃ iv, evalS p k = ok iv) ∧
      (∀ k v, verifyShare c k v = ok (core.result.Result.Ok ()) ↔
        ∃ iv, evalS p k = ok iv ∧ iv.value = v) ∧
      ∃ x y, @polynomial.Poly.c0 _
          fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar.ModuleInst.AdditiveGroupInst
          p = ok x ∧
        polynomial.Poly.c0
          fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup c = ok y ∧
        gen (Z.toF x) = y

/-- `PartialEq` for secp256k1 points returns `true` only for equal points. -/
def PointEqSound : Prop :=
  ∀ a b, (fastcrypto.groups.secp256k1.ProjectivePoint.Insts.CoreCmpPartialEqProjectivePoint).eq a b =
    ok true → a = b

/-- The parties' share ids include `t` distinct indices. -/
def SharesCoverT (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop :=
  ∃ l : List FastcryptoSpecs.Shamir.ShareIndex, l.Nodup ∧ l.length = (setup C).t ∧
    ∀ k ∈ l, ∃ j, k ∈ (api C Z D).shareIds j

/-- A `process_message` result that is not `invalid` is a returned `Ok`. -/
theorem not_invalid' {R E : Type _}
    {x : Result (core.result.Result threshold_schnorr.avss.ProcessedMessage E × R)}
    (h : toProcessed x ≠ .invalid) : ∃ y, x = ok y ∧ ¬ IsErr y.1 := by
  unfold toProcessed at h
  split at h
  · rename_i o g hx
    exact ⟨_, okVal_eq_some.mp hx, by simp [IsErr]⟩
  · rename_i c g hx
    exact ⟨_, okVal_eq_some.mp hx, by simp [IsErr]⟩
  · exact absurd rfl h

theorem process_matches_commitment (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (gen : Generator Z) (s : Z.F) (hcomm : ∀ j, (C.recv j).commitment = some (gen s))
    (hopen : CommitmentOpening Z gen) (hinj : Function.Injective gen) (hpeq : PointEqSound)
    (hnz : NonZeroModel Z) (hcover : SharesCoverT C Z D)
    (hSh : FastcryptoSpecs.Shamir.Contracts (api C Z D).Sh)
    (i : Party C.ns) (m : threshold_schnorr.avss.Message)
    (hpm : (api C Z D).processMessage i m ≠ .invalid)
    (p : (api C Z D).Sh.Poly) (hp : (api C Z D).Sh.degreeBound p < (setup C).t)
    (hfit : ∀ j sh, (api C Z D).verifyShares m j sh = true →
      (api C Z D).shareList sh = ((api C Z D).shareIds j).map ((api C Z D).Sh.eval p)) :
    (api C Z D).Sh.c0 p = s := by
  obtain ⟨⟨x, g⟩, hx, hnx⟩ := not_invalid' hpm
  have hcheck := process_message_check C.rngInst _ m _ g x hx hnx
  obtain ⟨d, hd, hdt⟩ := check_message_degree _ m hcheck
  obtain ⟨pp, hpp, hne⟩ := check_message_commitment _ m (gen s) hcheck (hcomm i.val)
  have hpps : pp = gen s := by
    apply hpeq
    simp only [core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default] at hne
    obtain ⟨b, hb, hne⟩ := bind_eq_ok hne
    simp only [Result.ok_injective.eq_iff] at hne
    have hbt : b = true := by cases b <;> simp at hne ⊢
    rw [hbt] at hb; exact hb
  obtain ⟨q, e, he, hed, hevall, hiff, cx, cy, hcx, hcy, hgen⟩ := hopen _ d hd
  have hq : (api C Z D).Sh.c0 q = s := by
    rw [hcy, Result.ok_injective.eq_iff] at hpp
    rw [hpp, hpps] at hgen
    have := hinj hgen
    show c0Of Z q = s
    simp [c0Of, okVal_eq_some.mpr hcx, this]
  rw [← hq]
  -- `p` and `q` agree at every party's share ids.
  have hagree : ∀ j : Party C.ns, ∀ k ∈ (api C Z D).shareIds j,
      (api C Z D).Sh.eval p k = (api C Z D).Sh.eval q k := by
    intro j k hk
    have hsids : (api C Z D).shareIds j =
        ((toOption (shareIdsOf C.ns j.val)).map fun ids => ids.val.map idx).getD [] := rfl
    rw [hsids] at hk
    cases hto : toOption (shareIdsOf C.ns j.val) with
    | none => simp [hto] at hk
    | some ids =>
      have hids := toOption_eq_some.mp hto
      simp only [hto, Option.map_some, Option.getD_some] at hk
      -- The shares `q` gives party `j`, which verify.
      let val := fun nz => (hevall nz).choose
      let l := ids.val.map fun nz =>
        (⟨nz, (val nz).value⟩ : types.IndexedValue fastcrypto.groups.secp256k1.Scalar)
      have hlen : l.length ≤ Usize.max := by simp only [l, List.length_map]; scalar_tac
      let sh : threshold_schnorr.avss.SharesForNode := ⟨alloc.vec.Vec.from l hlen⟩
      have hver : threshold_schnorr.avss.SharesForNode.verify sh m (alloc.vec.Vec.deref ids) j.val =
          ok (core.result.Result.Ok ()) := by
        apply verify_complete
        · simp [sh, l, alloc.vec.Vec.from_val, vec_deref_val, List.map_map, Function.comp_def]
        · intro k _; obtain ⟨u, hu, -⟩ := hnz.1 k; exact ⟨u, hu⟩
        · intro s hs
          simp only [sh, l, alloc.vec.Vec.from_val, List.mem_map] at hs
          obtain ⟨nz, -, rfl⟩ := hs
          exact (hiff nz _).mpr ⟨val nz, (hevall nz).choose_spec, rfl⟩
      have hvs : (api C Z D).verifyShares m j sh = true := by
        simp only [api, decide_eq_true_eq]
        exact ⟨ids, hids, hver⟩
      have hfj := hfit j sh hvs
      rw [hsids, hto] at hfj
      simp only [Option.map_some, Option.getD_some] at hfj
      have hsl : (api C Z D).shareList sh = (ids.val.map idx).map ((api C Z D).Sh.eval q) := by
        show (alloc.vec.Vec.from l hlen).val.map _ = _
        rw [alloc.vec.Vec.from_val, List.map_map, List.map_map]
        apply List.map_congr_left
        intro nz _
        simp only [Function.comp_apply]
        show _ = evalAt Z q (idx nz)
        simp only [evalAt, ofIndex_idx Z hnz, okVal_eq_some.mpr (hevall nz).choose_spec,
          Option.map_some, Option.getD_some, val]
      have := hsl.symm.trans hfj
      exact ((List.map_inj_left.mp this) k hk).symm
  obtain ⟨l, hnd, hlen, hl⟩ := hcover
  have hqt : (api C Z D).Sh.degreeBound q < (setup C).t := by
    show degreeBound q < (C.recv 0#u16).params.t.val
    simp only [degreeBound, okVal_eq_some.mpr he, Option.map_some, Option.getD_some]
    rw [C.params_eq 0#u16 i.val]; omega
  have h1 := hSh.recover_c0 _ p l hp hnd hlen
  have h2 := hSh.recover_c0 _ q l hqt hnd hlen
  have hmap : l.map ((api C Z D).Sh.eval p) = l.map ((api C Z D).Sh.eval q) := by
    apply List.map_congr_left
    intro k hk
    obtain ⟨j, hj⟩ := hl k hk
    exact hagree j k hj
  rw [hmap, h2] at h1
  simpa using h1.symm

/-- `complete_dkg`, which the generated code does not include, stays abstract. -/
noncomputable def dkgApi (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (completeDkg : List (Party C.ns × threshold_schnorr.avss.AvssOutput) →
      Option threshold_schnorr.avss.DkOutput) :
    FastcryptoSpecs.Avss.DkgApi (Party C.ns) (api C Z D) where
  DkOutput := threshold_schnorr.avss.DkOutput
  completeDkg := completeDkg
  shares dk := dk.my_shares

/-- `DkOutput::complete_key_rotation(t, i, nodes, outputs)` as the spec's `completeKeyRotation`,
with the outputs' share indices made into `NonZeroU16`s by `ofIndex`. -/
noncomputable def completeKeyRotation (C : Receivers) (Z : Scalars) (t : ℕ) (i : Party C.ns)
    (os : List (FastcryptoSpecs.Shamir.ShareIndex × threshold_schnorr.avss.AvssOutput)) :
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
      Z.recoverC0 t.val (List.zipWith FastcryptoSpecs.Shamir.Eval.mk (s.val.map idx) ys) =
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
    (os : List (FastcryptoSpecs.Shamir.ShareIndex × threshold_schnorr.avss.AvssOutput))
    (dk : threshold_schnorr.avss.DkOutput)
    (v : FastcryptoSpecs.Shamir.ShareIndex × threshold_schnorr.avss.AvssOutput →
      FastcryptoSpecs.Shamir.ShareIndex → Z.F)
    (h : completeKeyRotation C Z t i os = some dk)
    (hos : ∀ o ∈ os, (api C Z D).shareList ((api C Z D).shares o.2) =
      ((api C Z D).shareIds i).map fun k => ⟨k, v o k⟩) :
    ∃ w : FastcryptoSpecs.Shamir.ShareIndex → Z.F,
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
    have hin : (⟨idx s.index, Z.toF s.value⟩ : FastcryptoSpecs.Shamir.Eval Z.F) ∈
        (api C Z D).shareList ((api C Z D).shares (u, out).2) := by
      show _ ∈ out.my_shares.shares.val.map _
      exact List.mem_map_of_mem hs
    rw [hsl] at hin
    obtain ⟨k, -, hk⟩ := List.mem_map.mp hin
    have hk1 := congrArg FastcryptoSpecs.Shamir.Eval.index hk
    have hk2 := congrArg FastcryptoSpecs.Shamir.Eval.value hk
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
      (fun s => (⟨idx s.index, Z.toF s.value⟩ : FastcryptoSpecs.Shamir.Eval Z.F)) = _
    have := congrArg (List.map fun p => (⟨idx p.1, p.2⟩ : FastcryptoSpecs.Shamir.Eval Z.F)) hmap
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
    have hzip : List.zipWith FastcryptoSpecs.Shamir.Eval.mk (os.map (·.1)) (os.map fun o => v o k) =
        os.map fun o => ⟨o.1, v o k⟩ := by
      rw [List.zipWith_map_left, List.zipWith_map_right, List.zipWith_self]
    rw [hzip, List.zipWith_map_left] at hr
    exact hr

end AvssProofs.Link
