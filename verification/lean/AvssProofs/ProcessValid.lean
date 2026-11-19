import Avss.Funs
import AvssProofs.Result
import AvssProofs.RecoverSound

/-!
`process_valid` for the code Aeneas generated from `Receiver::process_message`: if it returns
`Ok(Valid(o))`, then `o.my_shares` pass `SharesForNode::verify` for this receiver's share ids.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- `is_err` returns `false` only for `Ok`. -/
theorem is_err_false {E : Type _} {w : core.result.Result Unit E} {b : Bool}
    (h : core.result.Result.is_err w = ok b) (hb : ¬ b = true) : w = core.result.Result.Ok () := by
  cases w with
  | Ok _ => rfl
  | Err _ => simp [core.result.Result.is_err] at h; simp [← h] at hb

/-- If `verify_message` returns `Ok(Some(o))`, then `o.my_shares` are valid for this receiver. -/
theorem verify_message_valid (r : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message) (o : threshold_schnorr.avss.AvssOutput)
    (h : threshold_schnorr.avss.Receiver.verify_message r m = ok (core.result.Result.Ok (some o))) :
    ValidShares r.nodes m r.id o.my_shares := by
  unfold threshold_schnorr.avss.Receiver.verify_message at h
  ok_inv at h
  all_goals
    subst h
    refine ⟨_, ‹nodes.Nodes.share_ids_of _ _ r.nodes r.id = ok (core.result.Result.Ok _)›, ?_⟩
    have hw := is_err_false ‹core.result.Result.is_err _ = ok _› ‹¬ _ = true›
    subst hw
    exact ‹threshold_schnorr.avss.SharesForNode.verify _ m _ r.id = _›

theorem process_valid {R : Type} (rngInst : fastcrypto.traits.AllowedRng R)
    (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message) (rng rng' : R)
    (o : threshold_schnorr.avss.AvssOutput)
    (h : threshold_schnorr.avss.Receiver.process_message rngInst r m rng
      = ok (core.result.Result.Ok (threshold_schnorr.avss.ProcessedMessage.Valid o), rng')) :
    ValidShares r.nodes m r.id o.my_shares := by
  unfold threshold_schnorr.avss.Receiver.process_message at h
  ok_inv at h
  all_goals
    simp only [threshold_schnorr.avss.ProcessedMessage.Valid.injEq] at h
    obtain ⟨rfl, -⟩ := h
    exact verify_message_valid r m _ ‹_›

end AvssProofs
