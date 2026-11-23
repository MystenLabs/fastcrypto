-- THIS FILE IS AI-ONLY
import avss.Generated.Funs
import avss.Result
import avss.ProcessInvalidIff
import avss.RecoverComplete

/-!
`feldman_binding` for the code Aeneas generated from `Receiver::process_message` and
`SharesForNode::verify`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- `Poly::verify_share` on a commitment over secp256k1. -/
noncomputable abbrev verifyShare := @polynomial.Poly.verify_share _ _
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
  fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsModuleScalar

/-- `SharesForNode::verify`'s second loop returns `Ok` only if every remaining share passes
`verify_share`. -/
theorem verify_loop1_ok (m : threshold_schnorr.avss.Message) (n : Nat) :
    ∀ (it : core.slice.iter.Iter (types.IndexedValue fastcrypto.groups.secp256k1.Scalar)),
      it.slice.length - it.i = n →
      threshold_schnorr.avss.SharesForNode.verify_loop1 it m = ok (core.result.Result.Ok ()) →
      ∀ s ∈ it.slice.val.drop it.i,
        verifyShare m.feldman_commitment s.index s.value = ok (core.result.Result.Ok ()) := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
  intro it hn h s hs
  unfold threshold_schnorr.avss.SharesForNode.verify_loop1 at h
  rw [loop] at h
  obtain ⟨r, hr, h⟩ := bind_eq_ok h
  unfold threshold_schnorr.avss.SharesForNode.verify_loop1.body at hr
  simp only [core.slice.iter.IteratorSliceIter.next] at hr
  by_cases hi : it.i < it.slice.len.val
  · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair] at hr
    have hlt : it.i < it.slice.length := by simpa using hi
    generalize hy : it.slice[it.i]'hi = y at hr
    have hyv : y = it.slice.val[it.i]'hlt := by rw [← hy]; rfl
    obtain ⟨v, hv, hr⟩ := bind_eq_ok hr
    rw [List.drop_eq_getElem_cons hlt, ← hyv] at hs
    cases v with
    | Err e => simp only [Result.ok_injective.eq_iff] at hr; subst hr; simp at h
    | Ok u =>
      simp only [Result.ok_injective.eq_iff] at hr
      subst hr
      rcases List.mem_cons.mp hs with rfl | hs'
      · cases u; exact hv
      · exact ih _ (by rw [← hn]; dsimp only; omega) { slice := it.slice, i := it.i + 1 } rfl
          (by unfold threshold_schnorr.avss.SharesForNode.verify_loop1; exact h) s hs'
  · have hge : it.slice.length ≤ it.i := by simpa using hi
    rw [List.drop_of_length_le (by simpa using hge)] at hs
    simp at hs

/-- `NonZero<u16>::get`. -/
noncomputable abbrev nzGet := @core.num.nonzero.NonZero.get Std.U16 _
  U16.Insts.CoreNumNonzeroZeroablePrimitiveNonZeroU16Inner

/-- `SharesForNode::verify`'s first loop returns `true` only if it started with `true` and each
remaining pair of a share and an expected id has the same index. -/
theorem verify_loop0_ok (n : Nat) :
    ∀ (z : core.iter.adapters.zip.Zip
        (core.slice.iter.Iter (types.IndexedValue fastcrypto.groups.secp256k1.Scalar))
        (core.slice.iter.Iter (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner)))
      (b : Bool),
      z.fst.slice.length - z.fst.i = n →
      threshold_schnorr.avss.SharesForNode.verify_loop0 z b = ok true →
      b = true ∧ ∀ p ∈ (z.fst.slice.val.drop z.fst.i).zip (z.snd.slice.val.drop z.snd.i),
        ∃ u, nzGet p.1.index = ok u ∧ nzGet p.2 = ok u := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
  intro z b hn h
  unfold threshold_schnorr.avss.SharesForNode.verify_loop0 at h
  rw [loop] at h
  obtain ⟨r, hr, h⟩ := bind_eq_ok h
  unfold threshold_schnorr.avss.SharesForNode.verify_loop0.body at hr
  simp only [core.iter.adapters.zip.Zip.Insts.CoreIterTraitsIteratorIteratorPair.next,
    core.slice.iter.IteratorSliceIter.next] at hr
  by_cases ha : z.fst.i < z.fst.slice.len.val
  · have hla : z.fst.i < z.fst.slice.length := by simpa using ha
    by_cases hb : z.snd.i < z.snd.slice.len.val
    · have hlb : z.snd.i < z.snd.slice.length := by simpa using hb
      simp only [ha, hb, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair] at hr
      generalize hx : z.fst.slice[z.fst.i]'ha = x at hr
      generalize hy : z.snd.slice[z.snd.i]'hb = y at hr
      have hxv : x = z.fst.slice.val[z.fst.i]'hla := by rw [← hx]; rfl
      have hyv : y = z.snd.slice.val[z.snd.i]'hlb := by rw [← hy]; rfl
      obtain ⟨u, hu, hr⟩ := bind_eq_ok hr
      obtain ⟨u', hu', hr⟩ := bind_eq_ok hr
      have hrec : ∀ b', r = ControlFlow.cont (⟨⟨z.fst.slice, z.fst.i + 1⟩,
          ⟨z.snd.slice, z.snd.i + 1⟩⟩, b') → b' = true ∧
          ∀ p ∈ (z.fst.slice.val.drop (z.fst.i + 1)).zip (z.snd.slice.val.drop (z.snd.i + 1)),
            ∃ u, nzGet p.1.index = ok u ∧ nzGet p.2 = ok u := by
        intro b' hr'
        subst hr'
        refine ih _ ?_ ⟨⟨z.fst.slice, z.fst.i + 1⟩, ⟨z.snd.slice, z.snd.i + 1⟩⟩ b' rfl
          (by unfold threshold_schnorr.avss.SharesForNode.verify_loop0; exact h)
        rw [← hn]; dsimp only; omega
      rw [List.drop_eq_getElem_cons hla, List.drop_eq_getElem_cons hlb, ← hxv, ← hyv,
        List.zip_cons_cons]
      split at hr
      · simp only [Result.ok_injective.eq_iff] at hr
        exact absurd (hrec false hr.symm).1 Bool.false_ne_true
      · rename_i hne
        simp only [Result.ok_injective.eq_iff] at hr
        obtain ⟨hbt, hall⟩ := hrec b hr.symm
        refine ⟨hbt, ?_⟩
        intro p hp
        rcases List.mem_cons.mp hp with rfl | hp'
        · refine ⟨u, hu, ?_⟩
          simp at hne
          have : u = u' := by scalar_tac
          simp only [nzGet, hu', this]
        · exact hall p hp'
    · simp only [ha, hb, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair,
        Result.ok_injective.eq_iff] at hr
      subst hr
      simp only [Result.ok_injective.eq_iff] at h
      refine ⟨h, ?_⟩
      have hge : z.snd.slice.length ≤ z.snd.i := by simpa using hb
      rw [List.drop_of_length_le (l := z.snd.slice.val) (by simpa using hge)]
      simp
  · simp only [ha, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, Result.ok_injective.eq_iff] at hr
    subst hr
    simp only [Result.ok_injective.eq_iff] at h
    refine ⟨h, ?_⟩
    have hge : z.fst.slice.length ≤ z.fst.i := by simpa using ha
    rw [List.drop_of_length_le (l := z.fst.slice.val) (by simpa using hge)]
    simp

/-- `SharesForNode::verify` returns `Ok` only if the shares' indices are the expected ids, in
order, and every share passes `verify_share`. -/
theorem verify_ok (sh : threshold_schnorr.avss.SharesForNode) (m : threshold_schnorr.avss.Message)
    (ids : Slice (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner)) (j : Std.U16)
    (h : threshold_schnorr.avss.SharesForNode.verify sh m ids j = ok (core.result.Result.Ok ())) :
    List.Forall₂ (fun s k => ∃ u, nzGet s.index = ok u ∧ nzGet k = ok u) sh.shares.val ids.val ∧
      ∀ s ∈ sh.shares.val,
        verifyShare m.feldman_commitment s.index s.value = ok (core.result.Result.Ok ()) := by
  unfold threshold_schnorr.avss.SharesForNode.verify at h
  simp only [core.slice.Slice.iter, core.iter.traits.iterator.Iterator.zip.trait_default,
    core.iter.traits.iterator.Iterator.zip.default,
    core.iter.traits.collect.IntoIterator.Blanket.into_iter, bind_ok] at h
  obtain ⟨b, hb, h⟩ := bind_eq_ok h
  cases b with
  | false => simp at h
  | true =>
  obtain ⟨hbt, hzip⟩ := verify_loop0_ok _ ⟨⟨alloc.vec.Vec.deref sh.shares, 0⟩, ⟨ids, 0⟩⟩ _ rfl hb
  simp only [↓reduceIte, SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter,
    bind_ok] at h
  have hall := verify_loop1_ok m _ _ rfl h
  simp only [vec_deref_val, List.drop_zero] at hzip hall
  refine ⟨?_, hall⟩
  rw [List.forall₂_iff_zip]
  refine ⟨?_, fun hp => hzip _ hp⟩
  have := congrArg UScalar.val (of_decide_eq_true hbt)
  simpa using this

/-- `Poly::degree` and `Poly::eval` for polynomials over secp256k1's scalars, and `Poly::degree`
for commitments. -/
noncomputable abbrev degreeS := @polynomial.Poly.degree _
  fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar.ModuleInst.AdditiveGroupInst
noncomputable abbrev evalS := @polynomial.Poly.eval _ _
  fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar.ModuleInst.AdditiveGroupInst
  fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar
  fastcrypto.groups.secp256k1.Scalar.Insts.FastcryptoGroupsScalar.ModuleInst
noncomputable abbrev degreeG := @polynomial.Poly.degree _
  fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup

/-- Feldman commitments over secp256k1 are binding: a commitment of degree `d` commits to a
polynomial `p` over the scalars of degree at most `d`, and a share passes `verify_share` only if it
is `p` evaluated at the share's index. -/
def CommitmentBinding : Prop :=
  ∀ (c : polynomial.Poly fastcrypto.groups.secp256k1.ProjectivePoint) d, degreeG c = ok d →
    ∃ p e, degreeS p = ok e ∧ e.val ≤ d.val ∧
      ∀ k v, verifyShare c k v = ok (core.result.Result.Ok ()) →
        ∃ iv, evalS p k = ok iv ∧ iv.value = v

/-- `NonZero<u16>` values are determined by `get`. -/
def NonZeroGetInj : Prop := ∀ a b u, nzGet a = ok u → nzGet b = ok u → a = b

/-- A message that passes `check_message` has a commitment of degree `t - 1`. -/
theorem check_message_degree (r : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message)
    (h : threshold_schnorr.avss.Receiver.check_message r m = ok (core.result.Result.Ok ())) :
    ∃ d, degreeG m.feldman_commitment = ok d ∧ d.val + 1 = r.params.t.val := by
  unfold threshold_schnorr.avss.Receiver.check_message at h
  obtain ⟨d, hd, h⟩ := bind_eq_ok h
  obtain ⟨d1, hd1, h⟩ := bind_eq_ok h
  obtain ⟨t', ht', h⟩ := bind_eq_ok h
  refine ⟨d, hd, ?_⟩
  have hadd := UScalar.add_equiv d 1#usize
  rw [hd1] at hadd
  simp at hadd
  simp only [lift, Result.ok_injective.eq_iff] at ht'
  subst ht'
  split at h
  · simp at h
  · rename_i hne
    simp at hne
    omega

theorem feldman_binding {R : Type} (hbind : CommitmentBinding) (hnz : NonZeroGetInj)
    (rngInst : fastcrypto.traits.AllowedRng R) (r : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message) (g g' : R)
    (x : core.result.Result threshold_schnorr.avss.ProcessedMessage fastcrypto.error.FastCryptoError)
    (hpm : threshold_schnorr.avss.Receiver.process_message rngInst r m g = ok (x, g'))
    (hx : ¬ IsErr x) :
    ∃ p e, degreeS p = ok e ∧ e.val < r.params.t.val ∧
      ∀ (sh : threshold_schnorr.avss.SharesForNode) ids j,
        threshold_schnorr.avss.SharesForNode.verify sh m ids j = ok (core.result.Result.Ok ()) →
        List.Forall₂ (fun k s => ∃ iv, evalS p k = ok iv ∧ iv.value = s.value)
          ids.val sh.shares.val := by
  obtain ⟨d, hd, hdt⟩ := check_message_degree r m (process_message_check rngInst r m g g' x hpm hx)
  obtain ⟨p, e, he, hed, hp⟩ := hbind _ d hd
  refine ⟨p, e, he, by omega, ?_⟩
  intro sh ids j hv
  obtain ⟨hf, hall⟩ := verify_ok sh m ids j hv
  rw [List.forall₂_iff_zip] at hf ⊢
  refine ⟨hf.1.symm, ?_⟩
  intro k s hks
  have hsk : (s, k) ∈ sh.shares.val.zip ids.val := by
    have := List.mem_map_of_mem (f := Prod.swap) hks
    rwa [List.zip_swap] at this
  obtain ⟨u, hu1, hu2⟩ := hf.2 hsk
  have heq : s.index = k := hnz _ _ u hu1 hu2
  rw [← heq]
  exact hp _ _ (hall s (List.of_mem_zip hsk).1)

end AvssProofs
