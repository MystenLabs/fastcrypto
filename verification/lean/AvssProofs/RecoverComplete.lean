import Avss.Funs
import AvssProofs.Result
import AvssProofs.Loops
import AvssProofs.ProcessInvalidIff
import AvssProofs.HandleAccepts

/-!
`recover_complete` for the code Aeneas generated from `Receiver::recover`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- The completeness of share recovery, which depends on code outside `avss.rs` (the `Nodes`
functions and polynomial interpolation): for a message that passes `check_message`, the shares of
responses that `verify_complaint_response` returned for distinct responders of total weight at
least `t` interpolate to shares that verify for this receiver. -/
def InterpolationComplete (r : threshold_schnorr.avss.Receiver) : Prop :=
  ∀ (m : threshold_schnorr.avss.Message) (vs : List threshold_schnorr.avss.VerifiedComplaintResponse)
    (W : Std.U16 → Std.U16) ids (other : Slice threshold_schnorr.avss.SharesForNode),
    threshold_schnorr.avss.Receiver.check_message r m = ok (core.result.Result.Ok ()) →
    (∀ v ∈ vs, ∃ j c, threshold_schnorr.avss.Receiver.verify_complaint_response r m j c =
      ok (core.result.Result.Ok v)) →
    (vs.map (·.responder_id)).Nodup →
    (∀ v ∈ vs, weightOf r.nodes v.responder_id = ok (core.result.Result.Ok (W v.responder_id))) →
    r.params.t.val ≤ (vs.map (fun v => (W v.responder_id).val)).sum →
    nodes.Nodes.share_ids_of
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize r.nodes r.id
      = ok (core.result.Result.Ok ids) →
    other.val = vs.map (·.shares) →
    ∃ s, threshold_schnorr.avss.SharesForNode.recover ids r.params.t other =
        ok (core.result.Result.Ok s) ∧
      threshold_schnorr.avss.SharesForNode.verify s m (alloc.vec.Vec.deref ids) r.id =
        ok (core.result.Result.Ok ())

@[simp] theorem vec_deref_val {T : Type _} (v : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref v).val = v.val := by
  simp only [alloc.vec.Vec.deref, Slice.from_val]

/-- Charon emits the loops of `recover` twice, once per branch of the commitment check. -/
theorem recover_loop3_eq : threshold_schnorr.avss.Receiver.recover_loop3 =
    threshold_schnorr.avss.Receiver.recover_loop0 := by
  funext it acc
  unfold threshold_schnorr.avss.Receiver.recover_loop3 threshold_schnorr.avss.Receiver.recover_loop0
  rfl

theorem recover_loop4_eq : threshold_schnorr.avss.Receiver.recover_loop4 =
    threshold_schnorr.avss.Receiver.recover_loop1 := by
  funext it n tot unk
  unfold threshold_schnorr.avss.Receiver.recover_loop4 threshold_schnorr.avss.Receiver.recover_loop1
  rfl

theorem recover_loop5_eq : threshold_schnorr.avss.Receiver.recover_loop5 =
    threshold_schnorr.avss.Receiver.recover_loop2 := by
  funext it acc
  unfold threshold_schnorr.avss.Receiver.recover_loop5 threshold_schnorr.avss.Receiver.recover_loop2
  rfl

/-- A message that passes `check_message` has the commitment `c0` that the receiver expects. -/
theorem check_message_commitment (r : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message) (c)
    (h : threshold_schnorr.avss.Receiver.check_message r m = ok (core.result.Result.Ok ()))
    (hc : r.commitment = some c) :
    ∃ pp, polynomial.Poly.c0
        fastcrypto.groups.secp256k1.ProjectivePoint.Insts.FastcryptoGroupsAdditiveGroup
        m.feldman_commitment = ok pp ∧
      core.cmp.PartialEq.ne.trait_default
        fastcrypto.groups.secp256k1.ProjectivePoint.Insts.CoreCmpPartialEqProjectivePoint pp c =
        ok false := by
  unfold threshold_schnorr.avss.Receiver.check_message at h
  rw [hc] at h
  ok_inv at h
  all_goals
    refine ⟨_, ‹polynomial.Poly.c0 _ _ = ok _›, ?_⟩
    rw [‹core.cmp.PartialEq.ne.trait_default _ _ _ = ok _›]
    simp_all

/-- A `process_message` call that does not return an error passed `check_message`. -/
theorem process_message_check {R : Type} (rngInst : fastcrypto.traits.AllowedRng R)
    (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message) (g g' : R)
    (x : core.result.Result threshold_schnorr.avss.ProcessedMessage fastcrypto.error.FastCryptoError)
    (h : threshold_schnorr.avss.Receiver.process_message rngInst r m g = ok (x, g'))
    (hx : ¬ IsErr x) :
    threshold_schnorr.avss.Receiver.check_message r m = ok (core.result.Result.Ok ()) := by
  have hnc := (process_message_err rngInst r m g g' x h).not.mp hx
  unfold threshold_schnorr.avss.Receiver.process_message at h
  obtain ⟨y, hy, -⟩ := bind_eq_ok h
  unfold threshold_schnorr.avss.Receiver.verify_message at hy
  obtain ⟨c, hc, -⟩ := bind_eq_ok hy
  cases c with
  | Ok u => exact hc
  | Err e => exact absurd ⟨_, hc, e, rfl⟩ hnc

theorem recover_complete {R : Type} (hpclone : PolyCloneIsId)
    (rngInst : fastcrypto.traits.AllowedRng R) (r : threshold_schnorr.avss.Receiver)
    (hinterp : InterpolationComplete r)
    (m : threshold_schnorr.avss.Message) (g g' : R)
    (x : core.result.Result threshold_schnorr.avss.ProcessedMessage fastcrypto.error.FastCryptoError)
    (hpm : threshold_schnorr.avss.Receiver.process_message rngInst r m g = ok (x, g'))
    (hx : ¬ IsErr x)
    (vs : alloc.vec.Vec threshold_schnorr.avss.VerifiedComplaintResponse)
    (hv : ∀ v ∈ vs.val, ∃ j c, threshold_schnorr.avss.Receiver.verify_complaint_response r m j c =
      ok (core.result.Result.Ok v))
    (hnd : (vs.val.map (·.responder_id)).Nodup)
    (W : Std.U16 → Std.U16)
    (hW : ∀ v ∈ vs.val, weightOf r.nodes v.responder_id = ok (core.result.Result.Ok (W v.responder_id)))
    (hsum : (vs.val.map (fun v => (W v.responder_id).val)).sum ≤ U16.max)
    (ht : r.params.t.val ≤ (vs.val.map (fun v => (W v.responder_id).val)).sum)
    (ids) (hids : nodes.Nodes.share_ids_of
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize r.nodes r.id
      = ok (core.result.Result.Ok ids)) :
    threshold_schnorr.avss.Receiver.recover r m vs ⦃ res => ∃ o, res = core.result.Result.Ok o ⦄ := by
  have hcheck := process_message_check rngInst r m g g' x hpm hx
  unfold threshold_schnorr.avss.Receiver.recover
  rw [recover_loop3_eq, recover_loop4_eq, recover_loop5_eq]
  split
  on_goal 2 =>
    rename_i c hc
    obtain ⟨pp, hpp, hne⟩ := check_message_commitment r m c hcheck hc
    simp only [hpp, hne, bind_ok, Bool.false_eq_true, ↓reduceIte]
  all_goals
    simp only [SharedAVec.Insts.CoreIterTraitsCollectIntoIteratorSharedATIter.into_iter, bind_ok]
    apply WP.spec_bind (recover_loop0_spec _ (alloc.vec.Vec.new _) (by simp))
    intro resp hresp
    have hresp' : resp.val = vs.val.map (·.responder_id) := by simpa using hresp
    apply WP.spec_bind (all_distinct_spec _ (by rw [vec_deref_val, hresp']; exact hnd))
    rintro b rfl
    simp only [↓reduceIte]
    apply WP.spec_bind (recover_loop1_spec r.nodes W _ 0#u16 false
      (by intro j hj; simp only [vec_deref_val, hresp', List.drop_zero, List.mem_map] at hj; obtain ⟨v, hv, rfl⟩ := hj; exact hW v hv)
      (by simpa [vec_deref_val, hresp', Function.comp_def] using hsum))
    rintro ⟨tot, unk⟩ ⟨htot, hunk⟩
    simp only at htot hunk
    subst hunk
    simp only [vec_deref_val, hresp', Function.comp_def, List.drop_zero, List.map_map] at htot
    have hnlt : ¬ tot < r.params.t := by scalar_tac
    simp only [Std.uncurry_apply_pair, Bool.false_eq_true, ↓reduceIte, hnlt]
    apply WP.spec_bind (Pₘ := fun it => vs = it) (by
      unfold alloc.vec.IntoIteratorVec.into_iter; exact (WP.spec_ok _).mpr rfl)
    rintro _ rfl
    apply WP.spec_bind (recover_loop2_spec vs (alloc.vec.Vec.new _) (by simp))
    intro vsh hvsh
    have hvsh' : (alloc.vec.Vec.deref vsh).val = vs.val.map (·.shares) := by simpa using hvsh
    obtain ⟨sh, hrec, hver⟩ := hinterp m vs.val W ids _ hcheck hv hnd hW (by simpa [htot] using ht)
      hids hvsh'
    have hmi : threshold_schnorr.avss.Receiver.my_indices r = ok ids := by
      simp [threshold_schnorr.avss.Receiver.my_indices, hids, core.result.Result.unwrap]
    simp [hmi, hrec, core.result.Result.Insts.CoreOpsTry.branch, hver, hpclone m.feldman_commitment]

end AvssProofs
