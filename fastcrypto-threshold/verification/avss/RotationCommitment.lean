-- THIS FILE IS AI-ONLY
import avss.KeyRotation
import avss.HandleAccepts

/-!
The commitments of the generated `DkOutput::complete_key_rotation`: what
`dk.commitment_for_index(k)` returns is the combination, with the Lagrange coefficients, of the
outputs' Feldman commitments evaluated at `k`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

abbrev Point := fastcrypto.groups.secp256k1.ProjectivePoint

/-- `Poly::eval` on a commitment over secp256k1. -/
noncomputable abbrev evalG := @polynomial.Poly.eval _ _
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
  fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsModuleScalar

/-- `Poly::multi_scalar_mul` on commitments over secp256k1. -/
noncomputable abbrev msmPoly := @polynomial.Poly.multi_scalar_mul _ _ _
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsGroupElementScalar
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsMultiScalarMulScalar

/-- `Poly::multi_scalar_mul(ps, ss) = Ok(q)` ⇒ `q.eval(k)` returns `Σⱼ ss[j] · ps[j].eval(k)`: if
each `ps[j].eval(k)` returns `G::generator() * y(ps[j])` (`gen`, with `f` mapping the scalars into
`F`), `q.eval(k)` returns `G::generator() * Σⱼ y(ps[j]) · f(ss[j])`. -/
def MsmEval {F : Type} [Field F] (f : Scalar → F) (gen : F → Point) : Prop :=
  ∀ ps ss q, msmPoly ps ss = ok (core.result.Result.Ok q) →
    ∀ k (y : polynomial.Poly Point → F),
      (∀ p ∈ ps.val, ∃ iv, evalG p k = ok iv ∧ iv.value = gen (y p)) →
      ∃ iv, evalG q k = ok iv ∧ iv.value = gen (List.zipWith (fun p s => y p * f s) ps.val ss.val).sum

/-- `p.eval_range(m).to_vec()` returns evaluations of `p`: each entry `e` is `p.eval(e.index)`. -/
def EvalRangeSound : Prop :=
  ∀ (p : polynomial.Poly Point) m er v,
    polynomial.Poly.eval_range
      fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
      fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar
      fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsModuleScalar p m = ok er →
    polynomial.EvalRange.to_vec fastcrypto.groups.secp256k1.ProjectivePoint.Insts.CoreCloneClone
      er = ok v →
    ∀ e ∈ v.val, evalG p e.index = ok e

/-- `commitment_for_index` returns an entry of `dk.commitments` with the asked index. -/
theorem commitment_for_index_some (dk : threshold_schnorr.avss.DkOutput) index e
    (h : threshold_schnorr.avss.DkOutput.commitment_for_index dk index = ok (some e)) :
    e ∈ dk.commitments.val ∧ ∃ u, nzGet e.index = ok u ∧ nzGet index = ok u := by
  unfold threshold_schnorr.avss.DkOutput.commitment_for_index at h
  simp only [SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
    bind_ok] at h
  unfold threshold_schnorr.avss.DkOutput.commitment_for_index_loop at h
  refine loop_ok_induct _ (fun it => it.slice.length - it.i)
    (fun it => it.slice = alloc.vec.Vec.deref dk.commitments)
    (fun r => ∀ e, r = some e → e ∈ dk.commitments.val ∧ ∃ u, nzGet e.index = ok u ∧
      nzGet index = ok u)
    ?_ _ _ rfl h e rfl
  intro it hit c hc
  unfold threshold_schnorr.avss.DkOutput.commitment_for_index_loop.body at hc
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
      rintro e' ⟨⟩
      refine ⟨?_, u, hu, ?_⟩
      · rw [hyv]
        have : it.slice.val = dk.commitments.val := by rw [hit, vec_deref_val]
        rw [← this]; exact List.getElem_mem _
      · simp only [nzGet, hu', heq]
    · simp only [Result.ok_injective.eq_iff] at hc
      subst hc
      exact ⟨hit, by dsimp only; omega⟩
  · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hc
    subst hc
    intro e' h'; cases h'

/-- The third loop collects the outputs' Feldman commitments (and their constant terms). -/
theorem ckr_loop2_ok (hpclone : PolyCloneIsId) (it : OutIter) oc oc0 r
    (h : threshold_schnorr.avss.DkOutput.complete_key_rotation_loop2 it oc oc0 = ok r) :
    r.1.val = oc.val ++ (it.slice.val.drop it.i).map (·.value.feldman_commitment) := by
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop2 at h
  let g := fun (o : types.IndexedValue threshold_schnorr.avss.AvssOutput) =>
    o.value.feldman_commitment
  refine loop_ok_induct _ (fun st => st.1.slice.length - st.1.i)
    (fun st => st.1.slice = it.slice ∧
      st.2.1.val ++ (st.1.slice.val.drop st.1.i).map g = oc.val ++ (it.slice.val.drop it.i).map g)
    (fun r => r.1.val = oc.val ++ (it.slice.val.drop it.i).map g) ?_ _ _ ⟨rfl, rfl⟩ h
  rintro ⟨it', oc', oc0'⟩ ⟨hs, heq⟩ c hc
  dsimp only at hs heq hc ⊢
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation_loop2.body at hc
  simp only [core.slice.iter.IteratorSliceIter.next] at hc
  by_cases hi : it'.i < it'.slice.len.val
  · have hlt : it'.i < it'.slice.length := by simpa using hi
    simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair] at hc
    generalize hy : it'.slice[it'.i]'hi = y at hc
    have hyv : y = it'.slice.val[it'.i]'hlt := by rw [← hy]; rfl
    rw [hpclone, bind_ok] at hc
    obtain ⟨a, ha, hc⟩ := bind_eq_ok hc
    obtain ⟨_, -, hc⟩ := bind_eq_ok hc
    obtain ⟨_, -, hc⟩ := bind_eq_ok hc
    simp only [Result.ok_injective.eq_iff] at hc
    subst hc
    refine ⟨⟨hs, ?_⟩, by dsimp only; omega⟩
    rw [push_ok ha, ← heq, List.drop_eq_getElem_cons hlt, ← hyv]
    simp [g]
  · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hc
    subst hc
    have hge : it'.slice.length ≤ it'.i := by simpa using hi
    rw [← heq, List.drop_of_length_le (by simpa using hge)]
    simp

/-- `complete_key_rotation(t, my_id, nodes, outputs) = Ok(dk)` and
`dk.commitment_for_index(k) = Some(e)` ⇒ with `(c, λ)` the Lagrange coefficients for the outputs'
indices, `e = G::generator() * Σᵤ yᵤ · λᵤ · c`, where output `u`'s commitment evaluates to
`G::generator() * yᵤ` at `k`. -/
theorem complete_key_rotation_commitment {F : Type} [Field F] {f : Scalar → F} {gen : F → Point}
    (hf : ScalarHom f) (hnz : NonZeroGetInj) (hpclone : PolyCloneIsId) (hmsm : MsmEval f gen)
    (hrange : EvalRangeSound) t my ns outputs dk index e
    (y : polynomial.Poly Point → F)
    (hy : ∀ o ∈ (outputs : Slice (types.IndexedValue threshold_schnorr.avss.AvssOutput)).val,
      ∃ iv, evalG o.value.feldman_commitment index = ok iv ∧
        iv.value = gen (y o.value.feldman_commitment))
    (h : threshold_schnorr.avss.DkOutput.complete_key_rotation t my ns outputs =
      ok (core.result.Result.Ok dk))
    (he : threshold_schnorr.avss.DkOutput.commitment_for_index dk index = ok (some e)) :
    ∃ c lambdas,
    ∃ oi : alloc.vec.Vec (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner),
      oi.val = outputs.val.map (·.index) ∧
      lagrangeC0 t (alloc.vec.Vec.deref oi) = ok (core.result.Result.Ok (c, lambdas)) ∧
      e.value = gen (List.zipWith (fun o l => y o.value.feldman_commitment * l) outputs.val
        (lambdas.val.map fun l => f l * f c)).sum := by
  obtain ⟨hmem, u, hu1, hu2⟩ := commitment_for_index_some _ _ _ he
  have hidx := hnz _ _ u hu1 hu2
  unfold threshold_schnorr.avss.DkOutput.complete_key_rotation at h
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter,
    core.slice.Slice.iter, SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
    lift, bind_ok] at h
  ok_inv at h
  subst h
  have h0 := ckr_loop0_ok _ _ _ _ ‹threshold_schnorr.avss.DkOutput.complete_key_rotation_loop0 _ _ _ = ok _›
  have h1 := ckr_loop1_ok hf _ _ _ _ ‹threshold_schnorr.avss.DkOutput.complete_key_rotation_loop1 _ _ _ = ok _›
  have h2 := ckr_loop2_ok hpclone _ _ _ _
    ‹threshold_schnorr.avss.DkOutput.complete_key_rotation_loop2 _ _ _ = ok _›
  have hev := hrange _ _ _ _ ‹polynomial.Poly.eval_range _ _ _ _ _ = ok _›
    ‹polynomial.EvalRange.to_vec _ _ = ok _› e hmem
  rw [hidx] at hev
  have h2' : (alloc.vec.Vec.deref ‹alloc.vec.Vec (polynomial.Poly Point)›).val =
      outputs.val.map (·.value.feldman_commitment) := by
    rw [vec_deref_val, h2]; simp [alloc.vec.Vec.from_val]
  have hps : ∀ p ∈ (alloc.vec.Vec.deref ‹alloc.vec.Vec (polynomial.Poly Point)›).val,
      ∃ iv, evalG p index = ok iv ∧ iv.value = gen (y p) := by
    intro p hp
    rw [h2'] at hp
    obtain ⟨o, ho, rfl⟩ := List.mem_map.mp hp
    exact hy o ho
  obtain ⟨iv, hiv, hval⟩ := hmsm _ _ _ ‹msmPoly _ _ = ok _› index y hps
  rw [hev, Result.ok_injective.eq_iff] at hiv
  subst hiv
  refine ⟨_, _, _, by simpa using h0,
    ‹polynomial.Poly.get_lagrange_coefficients_for_c0 _ _ _ _ _ _ = ok _›, ?_⟩
  rw [hval]
  congr 2
  rw [h2', vec_deref_val]
  simp [alloc.vec.Vec.from_val] at h1
  rw [List.zipWith_map_left, ← h1, List.zipWith_map_right]

end AvssProofs
