import AvssProofs.Link
import AvssProofs.VerifyComplete

/-!
`process_matches_commitment` of fastcrypto-specs' `RotationContracts`, for the generated code: a
receiver created with `commitment = Some(G::generator() * s)` that accepts a message gets only
polynomials with constant term `s`.
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

end AvssProofs.Link
