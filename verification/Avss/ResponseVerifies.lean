import Avss.Generated.Funs
import Avss.Result
import Avss.RecoverSound
import Avss.ProcessValid

/-!
`response_verifies` for the code Aeneas generated: if `Rⱼ.process_message(m)` returns
`Ok(Valid(o))` and `Rⱼ.handle_complaint(m, i, c, o)` returns `Ok(r)`, then
`Rᵢ.verify_complaint_response(m, j, r)` returns `Ok`, for receivers with the same `nodes`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- `SharesForNode::clone` returns an equal value. Its derived code calls the `Clone` impls of
types that Aeneas keeps opaque, so this is assumed where needed. -/
def CloneIsId : Prop :=
  ∀ s, threshold_schnorr.avss.SharesForNode.Insts.CoreCloneClone.clone s = ok s

/-- If `handle_complaint` returns `Ok(r)`, then `r.shares` are `my_output.my_shares`. -/
theorem handle_complaint_shares (hclone : CloneIsId) (r : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message) (i : Std.U16) (c : threshold_schnorr.avss.Complaint)
    (o : threshold_schnorr.avss.AvssOutput) (resp : threshold_schnorr.avss.ComplaintResponse)
    (h : threshold_schnorr.avss.Receiver.handle_complaint r m i c o
      = ok (core.result.Result.Ok resp)) :
    resp.shares = o.my_shares := by
  unfold threshold_schnorr.avss.Receiver.handle_complaint at h
  ok_inv at h
  all_goals
    subst h
    have hc := ‹threshold_schnorr.avss.SharesForNode.Insts.CoreCloneClone.clone _ = ok _›
    rw [hclone, Result.ok_injective.eq_iff] at hc
    exact hc.symm

theorem response_verifies {R : Type} (hclone : CloneIsId) (rngInst : fastcrypto.traits.AllowedRng R)
    (r_i r_j : threshold_schnorr.avss.Receiver) (hnodes : r_i.nodes = r_j.nodes)
    (m : threshold_schnorr.avss.Message) (c : threshold_schnorr.avss.Complaint)
    (o : threshold_schnorr.avss.AvssOutput) (resp : threshold_schnorr.avss.ComplaintResponse)
    (rng rng' : R)
    (hp : threshold_schnorr.avss.Receiver.process_message rngInst r_j m rng
      = ok (core.result.Result.Ok (threshold_schnorr.avss.ProcessedMessage.Valid o), rng'))
    (hh : threshold_schnorr.avss.Receiver.handle_complaint r_j m r_i.id c o
      = ok (core.result.Result.Ok resp)) :
    ∃ v, threshold_schnorr.avss.Receiver.verify_complaint_response r_i m r_j.id resp
      = ok (core.result.Result.Ok v) := by
  obtain ⟨ids, hids, hv⟩ := process_valid rngInst r_j m rng rng' o hp
  have hs := handle_complaint_shares hclone r_j m r_i.id c o resp hh
  unfold threshold_schnorr.avss.Receiver.verify_complaint_response
  rw [hnodes, hids, hs]
  simp [core.result.Result.Insts.CoreOpsTry.branch, hv]

end AvssProofs
