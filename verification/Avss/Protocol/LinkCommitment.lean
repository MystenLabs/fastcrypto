import Avss.Protocol.Link
import Avss.VerifyComplete
import Avss.OutputCommitment

/-!
The lemmas about Feldman commitments, for the generated code: `output_commitment` of `Contracts`
(an output's commitment evaluates to `G::generator()` times the polynomial an accepted message
binds to) and `process_matches_commitment` of `RotationContracts` (a receiver created with
`commitment = Some(G::generator() * s)` that accepts a message gets only polynomials with constant
term `s`).
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs.Link

/-- `Poly::eval` on a commitment over secp256k1. -/
noncomputable abbrev evalG := @polynomial.Poly.eval _ _
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
  fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsModuleScalar

/-- Feldman commitments over secp256k1 open to a polynomial, which depends on the group and on
`Poly::verify_share`, `Poly::eval` and `Poly::c0`: a commitment `c` of degree `d` commits to a
polynomial `p` over the scalars of degree at most `d` such that `p.eval(k)` returns and
`c.eval(k) = G::generator() * p.eval(k)` for every `k`, a share passes `verify_share` exactly when
its value is `p.eval` at its index, and `c.c0() = G::generator() * p.c0()`. This implies
`CommitmentBinding`. -/
def CommitmentOpening (Z : Scalars) : Prop :=
  ∀ (c : polynomial.Poly fastcrypto.groups.secp256k1.ProjectivePoint) d, degreeG c = ok d →
    ∃ p e, degreeS p = ok e ∧ e.val ≤ d.val ∧
      (∀ k, ∃ iv, evalS p k = ok iv ∧
        ∃ iv', evalG c k = ok iv' ∧ iv'.value = Z.gen (Z.toF iv.value)) ∧
      (∀ k v, verifyShare c k v = ok (core.result.Result.Ok ()) ↔
        ∃ iv, evalS p k = ok iv ∧ iv.value = v) ∧
      ∃ x y, @polynomial.Poly.c0 _
          fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar.ModuleInst.AdditiveGroupInst
          p = ok x ∧
        polynomial.Poly.c0
          fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup c = ok y ∧
        Z.gen (Z.toF x) = y

/-- `PartialEq` for secp256k1 points returns `true` only for equal points. -/
def PointEqSound : Prop :=
  ∀ a b, (fastcrypto.groups.secp256k1.ProjectivePoint.Insts.CoreCmpPartialEqProjectivePoint).eq a b =
    ok true → a = b

/-- The parties' share ids include `t` distinct indices. -/
def SharesCoverT (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop :=
  ∃ l : List Protocol.Shamir.ShareIndex, l.Nodup ∧ l.length = (setup C).t ∧
    ∀ k ∈ l, ∃ j, k ∈ (api C Z D).shareIds j

/-- Scalar polynomials of degree `< t` that agree at `t` distinct indices agree at every index
(`Poly::eval`, `Poly::degree`). -/
def EvalDetermined (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop :=
  ∀ p q (l : List Protocol.Shamir.ShareIndex),
    (api C Z D).Sh.degreeBound p < (setup C).t → (api C Z D).Sh.degreeBound q < (setup C).t →
    l.Nodup → l.length = (setup C).t →
    (∀ k ∈ l, (api C Z D).Sh.eval p k = (api C Z D).Sh.eval q k) →
    ∀ k, (api C Z D).Sh.eval p k = (api C Z D).Sh.eval q k

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

/-- A message that passes `Rᵢ.check_message` opens to a polynomial `q` of degree `< t`, and every
polynomial that all verifying shares fit agrees with `q` at every party's share ids. -/
theorem opening_agrees (C : Receivers) (Z : Scalars) (D : Dealers Z) (hopen : CommitmentOpening Z)
    (hnz : NonZeroModel Z) (i : Party C.ns) (m : threshold_schnorr.avss.Message)
    (hcheck : threshold_schnorr.avss.Receiver.check_message (C.recv i.val) m =
      ok (core.result.Result.Ok ())) :
    ∃ q : (api C Z D).Sh.Poly, (api C Z D).Sh.degreeBound q < (setup C).t ∧
      (∀ k, ∃ iv, evalS q k = ok iv ∧
        ∃ iv', evalG m.feldman_commitment k = ok iv' ∧ iv'.value = Z.gen (Z.toF iv.value)) ∧
      (∃ x y, @polynomial.Poly.c0 _
          fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar.ModuleInst.AdditiveGroupInst
          q = ok x ∧
        polynomial.Poly.c0
          fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
          m.feldman_commitment = ok y ∧
        Z.gen (Z.toF x) = y) ∧
      ∀ p : (api C Z D).Sh.Poly, (∀ j sh, (api C Z D).verifyShares m j sh = true →
        (api C Z D).shareList sh = ((api C Z D).shareIds j).map ((api C Z D).Sh.eval p)) →
        ∀ j : Party C.ns, ∀ k ∈ (api C Z D).shareIds j,
          (api C Z D).Sh.eval p k = (api C Z D).Sh.eval q k := by
  obtain ⟨d, hd, hdt⟩ := check_message_degree _ m hcheck
  obtain ⟨q, e, he, hed, hevall, hiff, hc0⟩ := hopen _ d hd
  refine ⟨q, ?_, hevall, hc0, ?_⟩
  · show degreeBound q < (C.recv 0#u16).params.t.val
    simp only [degreeBound, okVal_eq_some.mpr he, Option.map_some, Option.getD_some]
    rw [C.params_eq 0#u16 i.val]; omega
  intro p hfit j k hk
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
        exact (hiff nz _).mpr ⟨val nz, (hevall nz).choose_spec.1, rfl⟩
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
      simp only [evalAt, ofIndex_idx Z hnz, okVal_eq_some.mpr (hevall nz).choose_spec.1,
        Option.map_some, Option.getD_some, val]
    have := hsl.symm.trans hfj
    exact ((List.map_inj_left.mp this) k hk).symm

theorem process_matches_commitment (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (s : Z.F) (hcomm : ∀ j, (C.recv j).commitment = some (Z.gen s))
    (hopen : CommitmentOpening Z) (hinj : Function.Injective Z.gen) (hpeq : PointEqSound)
    (hnz : NonZeroModel Z) (hcover : SharesCoverT C Z D)
    (hSh : Protocol.Shamir.Contracts (api C Z D).Sh)
    (i : Party C.ns) (m : threshold_schnorr.avss.Message)
    (hpm : (api C Z D).processMessage i m ≠ .invalid)
    (p : (api C Z D).Sh.Poly) (hp : (api C Z D).Sh.degreeBound p < (setup C).t)
    (hfit : ∀ j sh, (api C Z D).verifyShares m j sh = true →
      (api C Z D).shareList sh = ((api C Z D).shareIds j).map ((api C Z D).Sh.eval p)) :
    (api C Z D).Sh.c0 p = s := by
  obtain ⟨⟨x, g⟩, hx, hnx⟩ := not_invalid' hpm
  have hcheck := process_message_check C.rngInst _ m _ g x hx hnx
  obtain ⟨pp, hpp, hne⟩ := check_message_commitment _ m (Z.gen s) hcheck (hcomm i.val)
  have hpps : pp = Z.gen s := by
    apply hpeq
    simp only [core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default] at hne
    obtain ⟨b, hb, hne⟩ := bind_eq_ok hne
    simp only [Result.ok_injective.eq_iff] at hne
    have hbt : b = true := by cases b <;> simp at hne ⊢
    rw [hbt] at hb; exact hb
  obtain ⟨q, hqt, -, ⟨cx, cy, hcx, hcy, hgen⟩, hagree⟩ := opening_agrees C Z D hopen hnz i m hcheck
  have hq : (api C Z D).Sh.c0 q = s := by
    rw [hcy, Result.ok_injective.eq_iff] at hpp
    rw [hpp, hpps] at hgen
    have := hinj hgen
    show c0Of Z q = s
    simp [c0Of, okVal_eq_some.mpr hcx, this]
  rw [← hq]
  obtain ⟨l, hnd, hlen, hl⟩ := hcover
  have h1 := hSh.recover_c0 _ p l hp hnd hlen
  have h2 := hSh.recover_c0 _ q l hqt hnd hlen
  have hmap : l.map ((api C Z D).Sh.eval p) = l.map ((api C Z D).Sh.eval q) := by
    apply List.map_congr_left
    intro k hk
    obtain ⟨j, hj⟩ := hl k hk
    exact hagree p hfit j k hj
  rw [hmap, h2] at h1
  simpa using h1.symm

theorem output_commitment (C : Receivers) (Z : Scalars) (D : Dealers Z)
    (hpclone : PolyCloneIsId) (hopen : CommitmentOpening Z) (hinj : Function.Injective Z.gen)
    (hnz : NonZeroModel Z) (hcover : SharesCoverT C Z D) (hdet : EvalDetermined C Z D) :
    OutputCommitment C Z D := by
  intro i m o hpm hsrc p hp hfit k
  obtain ⟨⟨x, g⟩, hx, hnx⟩ := not_invalid' hpm
  have hcheck := process_message_check C.rngInst _ m _ g x hx hnx
  obtain ⟨q, hqt, hevall, -, hagree⟩ := opening_agrees C Z D hopen hnz i m hcheck
  -- `p` and `q` agree everywhere.
  obtain ⟨l, hnd, hlen, hl⟩ := hcover
  have hpq := hdet p q l hp hqt hnd hlen (fun k hk => by
    obtain ⟨j, hj⟩ := hl k hk
    exact hagree p hfit j k hj) k
  -- `o` carries the message's commitment.
  have hfc : o.feldman_commitment = m.feldman_commitment := by
    rcases hsrc with hv | ⟨vs, hr⟩
    · obtain ⟨g', hg'⟩ := toProcessed_valid.mp hv
      exact verify_message_commitment hpclone _ m o (process_valid_output C.rngInst _ m _ g' o hg')
    · simp only [api] at hr
      split at hr
      · exact recover_commitment hpclone _ m _ o (toOption_eq_some.mp hr)
      · simp at hr
  -- `committed o k` is `q.eval(k)`.
  obtain ⟨iv, hiv, iv', hiv', hval⟩ := hevall (Z.ofIndex k)
  show committedOf Z o k = _
  rw [hpq]
  show _ = (evalAt Z q k).value
  have hex : ∃ x iv, evalG o.feldman_commitment (Z.ofIndex k) = ok iv ∧ iv.value = Z.gen x :=
    ⟨_, iv', by rw [hfc]; exact hiv', hval⟩
  unfold committedOf
  rw [dite_eq_left_of_eq_true (eq_true hex)]
  obtain ⟨iv'', hiv'', hval''⟩ := hex.choose_spec
  rw [hfc, hiv', Result.ok_injective.eq_iff] at hiv''
  subst hiv''
  simp only [evalAt, okVal_eq_some.mpr hiv, Option.map_some, Option.getD_some]
  exact hinj (hval''.symm.trans hval)

end AvssProofs.Link
