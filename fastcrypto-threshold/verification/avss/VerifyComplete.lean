-- THIS FILE IS AI-ONLY
import avss.Generated.Funs
import avss.Result
import avss.Loops
import avss.RecoverComplete
import avss.FeldmanBinding

/-!
`SharesForNode::verify` accepts shares whose indices are the expected ids and that each pass
`verify_share`: the converse of `verify_ok`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- The index-matching loop keeps `indices_match` when each share's index is the expected id. -/
theorem verify_loop0_spec (b : Bool)
    (z : core.iter.adapters.zip.Zip
      (core.slice.iter.Iter (types.IndexedValue fastcrypto.groups.secp256k1.Scalar))
      (core.slice.iter.Iter (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner)))
    (heq : (z.fst.slice.val.drop z.fst.i).map (·.index) = z.snd.slice.val.drop z.snd.i)
    (hget : ∀ k ∈ z.snd.slice.val.drop z.snd.i, ∃ u, nzGet k = ok u) :
    threshold_schnorr.avss.SharesForNode.verify_loop0 z b ⦃ r => r = b ⦄ := by
  unfold threshold_schnorr.avss.SharesForNode.verify_loop0
  apply loop.spec_decr_nat (fun p => p.1.fst.slice.length - p.1.fst.i)
    (fun p => p.1.fst.slice = z.fst.slice ∧ p.1.snd.slice = z.snd.slice ∧ p.2 = b ∧
      (p.1.fst.slice.val.drop p.1.fst.i).map (·.index) = p.1.snd.slice.val.drop p.1.snd.i ∧
      ∀ k ∈ p.1.snd.slice.val.drop p.1.snd.i, ∃ u, nzGet k = ok u)
  · rintro ⟨z', b'⟩ ⟨h1, h2, hb, he, hg⟩
    dsimp only at h1 h2 hb he hg ⊢
    subst hb
    unfold threshold_schnorr.avss.SharesForNode.verify_loop0.body
    simp only [core.iter.adapters.zip.Zip.Insts.CoreIterTraitsIteratorIteratorPair.next,
      core.slice.iter.IteratorSliceIter.next]
    by_cases ha : z'.fst.i < z'.fst.slice.len.val
    · have hla : z'.fst.i < z'.fst.slice.length := by simpa using ha
      have hd1 := List.drop_eq_getElem_cons hla
      have hlb : z'.snd.i < z'.snd.slice.length := by
        have := congrArg List.length he
        simp only [List.length_map, List.length_drop] at this
        have : z'.fst.slice.val.length = z'.fst.slice.length := rfl
        have : z'.snd.slice.val.length = z'.snd.slice.length := rfl
        omega
      have hb' : z'.snd.i < z'.snd.slice.len.val := by simpa using hlb
      have hd2 := List.drop_eq_getElem_cons hlb
      simp only [ha, hb', ↓reduceDIte, bind_ok, Std.uncurry_apply_pair]
      generalize hx : z'.fst.slice[z'.fst.i]'ha = x
      generalize hy : z'.snd.slice[z'.snd.i]'hb' = y
      have hxv : x = z'.fst.slice.val[z'.fst.i]'hla := by rw [← hx]; rfl
      have hyv : y = z'.snd.slice.val[z'.snd.i]'hlb := by rw [← hy]; rfl
      rw [hd1, hd2, ← hxv, ← hyv, List.map_cons] at he
      obtain ⟨hxy, he'⟩ := List.cons_eq_cons.mp he
      rw [hd2, ← hyv] at hg
      obtain ⟨u, hu⟩ := hg y (List.mem_cons_self ..)
      have hu' : nzGet x.index = ok u := by rw [hxy]; exact hu
      simp only [nzGet] at hu hu'
      simp only [hu, hu', bind_ok, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
      refine ⟨⟨h1, h2, by simp, he', fun k hk => hg k (List.mem_cons_of_mem _ hk)⟩, ?_⟩
      omega
    · simp only [ha, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, WP.spec_ok]
  · exact ⟨rfl, rfl, rfl, heq, hget⟩

/-- The share-checking loop returns `Ok` when each remaining share passes `verify_share`. -/
theorem verify_loop1_spec (m : threshold_schnorr.avss.Message)
    (it : core.slice.iter.Iter (types.IndexedValue fastcrypto.groups.secp256k1.Scalar))
    (hv : ∀ s ∈ it.slice.val.drop it.i,
      verifyShare m.feldman_commitment s.index s.value = ok (core.result.Result.Ok ())) :
    threshold_schnorr.avss.SharesForNode.verify_loop1 it m ⦃ r => r = core.result.Result.Ok () ⦄ := by
  unfold threshold_schnorr.avss.SharesForNode.verify_loop1
  apply loop.spec_decr_nat (fun it' => it'.slice.length - it'.i)
    (fun it' => it'.slice = it.slice ∧ ∀ s ∈ it'.slice.val.drop it'.i,
      verifyShare m.feldman_commitment s.index s.value = ok (core.result.Result.Ok ()))
  · rintro it' ⟨hs, hv'⟩
    unfold threshold_schnorr.avss.SharesForNode.verify_loop1.body
    simp only [core.slice.iter.IteratorSliceIter.next]
    by_cases hi : it'.i < it'.slice.len.val
    · have hlt : it'.i < it'.slice.length := by simpa using hi
      simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair]
      generalize hy : it'.slice[it'.i]'hi = y
      have hyv : y = it'.slice.val[it'.i]'hlt := by rw [← hy]; rfl
      rw [List.drop_eq_getElem_cons hlt, ← hyv] at hv'
      have h0 := hv' y (List.mem_cons_self ..)
      simp only [verifyShare] at h0
      simp only [h0, bind_ok, WP.spec_ok]
      refine ⟨⟨hs, fun s hs' => hv' s (List.mem_cons_of_mem _ hs')⟩, ?_⟩
      omega
    · simp only [hi, ↓reduceDIte, bind_ok, Std.uncurry_apply_pair, WP.spec_ok]
  · exact ⟨rfl, hv⟩

/-- `SharesForNode::verify` returns `Ok` for shares whose indices are the expected ids, in order,
and that each pass `verify_share`. -/
theorem verify_complete (sh : threshold_schnorr.avss.SharesForNode)
    (m : threshold_schnorr.avss.Message)
    (ids : Slice (core.num.nonzero.NonZero Std.U16 core.num.niche_types.NonZeroU16Inner)) (j : Std.U16)
    (hidx : sh.shares.val.map (·.index) = ids.val)
    (hget : ∀ k ∈ ids.val, ∃ u, nzGet k = ok u)
    (hv : ∀ s ∈ sh.shares.val,
      verifyShare m.feldman_commitment s.index s.value = ok (core.result.Result.Ok ())) :
    threshold_schnorr.avss.SharesForNode.verify sh m ids j = ok (core.result.Result.Ok ()) := by
  have hlen : sh.shares.len = ids.len := by
    apply UScalar.eq_of_val_eq
    have := congrArg List.length hidx
    simpa using this
  unfold threshold_schnorr.avss.SharesForNode.verify
  simp only [core.slice.Slice.iter, core.iter.traits.iterator.Iterator.zip.trait_default,
    core.iter.traits.iterator.Iterator.zip.default,
    core.iter.traits.collect.IntoIterator.Blanket.into_iter, bind_ok, hlen, decide_true]
  obtain ⟨b, hb, rfl⟩ := spec_eq_ok (verify_loop0_spec true
    ⟨⟨alloc.vec.Vec.deref sh.shares, 0⟩, ⟨ids, 0⟩⟩ (by simpa using hidx) (by simpa using hget))
  simp only [hb, bind_ok, ↓reduceIte,
    SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter]
  obtain ⟨r, hr, rfl⟩ := spec_eq_ok (verify_loop1_spec m ⟨alloc.vec.Vec.deref sh.shares, 0⟩
    (by simpa using hv))
  exact hr

end AvssProofs
