-- THIS FILE IS AI-ONLY
import avss.Generated.Funs
import avss.Result
import avss.ResponseVerifies

/-!
`handle_accepts` for the code Aeneas generated: if `Rᵢ.process_message(m)` returns
`Ok(Complaint(c))` and `Rⱼ.process_message(m)` returns `Ok(Valid(o))`, then
`Rⱼ.handle_complaint(m, i, c, o)` returns `Ok`, for receivers configured alike and a party `i`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- `Poly::clone` returns an equal value. -/
def PolyCloneIsId : Prop :=
  ∀ p, polynomial.Poly.Insts.CoreCloneClone.clone
    fastcrypto.groups.secp256k1.ProjectivePoint.Insts.CoreCloneClone p = ok p

/-- `Poly::eq` of a polynomial with itself returns `true`. -/
def PolyEqRefl : Prop :=
  ∀ p, (polynomial.Poly.Insts.CoreCmpPartialEqPoly
    fastcrypto.groups.secp256k1.ProjectivePoint.Insts.CoreCmpPartialEqProjectivePoint).eq p p
    = ok true

/-- The completeness of the recovery proof: for receivers configured alike, a complaint that
`Rᵢ.create_complaint` makes about a message whose shares `Rᵢ.verify_message` rejected is accepted
by `Rⱼ.check_recovery_proof`. -/
def RecoveryComplete : Prop :=
  ∀ {R : Type} (rngInst : fastcrypto.traits.AllowedRng R) (r_i r_j : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message) (g g' : R) (c : threshold_schnorr.avss.Complaint) ids,
    r_i.nodes = r_j.nodes → r_i.params = r_j.params → r_i.sid = r_j.sid →
    r_i.commitment = r_j.commitment →
    threshold_schnorr.avss.Receiver.verify_message r_i m = ok (core.result.Result.Ok none) →
    threshold_schnorr.avss.Receiver.create_complaint rngInst r_i m g = ok (c, g') →
    nodes.Nodes.share_ids_of
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize r_j.nodes r_i.id
      = ok (core.result.Result.Ok ids) →
    threshold_schnorr.avss.Receiver.check_recovery_proof r_j m r_i.id c (alloc.vec.Vec.deref ids)
      = ok (core.result.Result.Ok ())

/-- `process_message` returns a complaint only after `verify_message` returned `Ok(None)`, and the
complaint is the one `create_complaint` made. -/
theorem process_complaint {R : Type} (rngInst : fastcrypto.traits.AllowedRng R)
    (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message) (g g' : R)
    (c : threshold_schnorr.avss.Complaint)
    (h : threshold_schnorr.avss.Receiver.process_message rngInst r m g
      = ok (core.result.Result.Ok (threshold_schnorr.avss.ProcessedMessage.Complaint c), g')) :
    threshold_schnorr.avss.Receiver.verify_message r m = ok (core.result.Result.Ok none) ∧
      threshold_schnorr.avss.Receiver.create_complaint rngInst r m g = ok (c, g') := by
  unfold threshold_schnorr.avss.Receiver.process_message at h
  ok_inv at h
  simp only [threshold_schnorr.avss.ProcessedMessage.Complaint.injEq] at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨‹_›, ‹_›⟩

/-- `process_message` returns `Valid(o)` only after `verify_message` returned `Ok(Some(o))`. -/
theorem process_valid_output {R : Type} (rngInst : fastcrypto.traits.AllowedRng R)
    (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message) (g g' : R)
    (o : threshold_schnorr.avss.AvssOutput)
    (h : threshold_schnorr.avss.Receiver.process_message rngInst r m g
      = ok (core.result.Result.Ok (threshold_schnorr.avss.ProcessedMessage.Valid o), g')) :
    threshold_schnorr.avss.Receiver.verify_message r m = ok (core.result.Result.Ok (some o)) := by
  unfold threshold_schnorr.avss.Receiver.process_message at h
  ok_inv at h
  simp only [threshold_schnorr.avss.ProcessedMessage.Valid.injEq] at h
  obtain ⟨rfl, -⟩ := h
  exact ‹_›

/-- With `Poly::clone` the identity, `verify_message` returns an output for the message itself. -/
theorem verify_message_commitment (hpclone : PolyCloneIsId) (r : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message) (o : threshold_schnorr.avss.AvssOutput)
    (h : threshold_schnorr.avss.Receiver.verify_message r m = ok (core.result.Result.Ok (some o))) :
    o.feldman_commitment = m.feldman_commitment := by
  unfold threshold_schnorr.avss.Receiver.verify_message at h
  ok_inv at h
  all_goals
    subst h
    have hc := ‹polynomial.Poly.Insts.CoreCloneClone.clone _ _ = ok _›
    rw [hpclone, Result.ok_injective.eq_iff] at hc
    exact hc.symm

theorem handle_accepts {R : Type} (hclone : CloneIsId) (hpclone : PolyCloneIsId)
    (hpeq : PolyEqRefl) (hrec : RecoveryComplete) (rngInst : fastcrypto.traits.AllowedRng R)
    (r_i r_j : threshold_schnorr.avss.Receiver) (hn : r_i.nodes = r_j.nodes)
    (hp : r_i.params = r_j.params) (hs : r_i.sid = r_j.sid) (hc : r_i.commitment = r_j.commitment)
    (ids) (hids : nodes.Nodes.share_ids_of
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize r_j.nodes r_i.id
      = ok (core.result.Result.Ok ids))
    (m : threshold_schnorr.avss.Message) (c : threshold_schnorr.avss.Complaint)
    (o : threshold_schnorr.avss.AvssOutput) (g_i g_i' g_j g_j' : R)
    (h_i : threshold_schnorr.avss.Receiver.process_message rngInst r_i m g_i
      = ok (core.result.Result.Ok (threshold_schnorr.avss.ProcessedMessage.Complaint c), g_i'))
    (h_j : threshold_schnorr.avss.Receiver.process_message rngInst r_j m g_j
      = ok (core.result.Result.Ok (threshold_schnorr.avss.ProcessedMessage.Valid o), g_j')) :
    ∃ resp, threshold_schnorr.avss.Receiver.handle_complaint r_j m r_i.id c o
      = ok (core.result.Result.Ok resp) := by
  obtain ⟨hv_i, hc_i⟩ := process_complaint rngInst r_i m g_i g_i' c h_i
  have hcomm := verify_message_commitment hpclone r_j m o (process_valid_output rngInst r_j m g_j g_j' o h_j)
  have hcheck := hrec rngInst r_i r_j m g_i g_i' c ids hn hp hs hc hv_i hc_i hids
  have hpeq' := hpeq m.feldman_commitment
  have hclone' := hclone o.my_shares
  unfold threshold_schnorr.avss.Receiver.handle_complaint
  simp [core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default, hcomm, hpeq', hids,
    hcheck, hclone', core.result.Result.Insts.CoreOpsTry.branch]

end AvssProofs
