import Avss.Generated.Funs
import Avss.Result

/-!
`recover_sound` for the code Aeneas generated from `Receiver::recover`: if it returns `Ok(o)`,
then `o.my_shares` pass `SharesForNode::verify` for this receiver's share ids.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- `ns.share_ids_of(i)` returns `Ok(ids)` and `shares.verify(m, ids, i)` returns `Ok`:
`ValidOutput` in the Lean specs. -/
def ValidShares (ns : nodes.Nodes fastcrypto.groups.ristretto255.RistrettoPoint
      fastcrypto.groups.ristretto255.RistrettoScalar)
    (m : threshold_schnorr.avss.Message) (i : Std.U16)
    (shares : threshold_schnorr.avss.SharesForNode) : Prop :=
  ∃ ids, nodes.Nodes.share_ids_of
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize ns i
      = ok (core.result.Result.Ok ids)
    ∧ threshold_schnorr.avss.SharesForNode.verify shares m (alloc.vec.Vec.deref ids) i
      = ok (core.result.Result.Ok ())

/-- `my_indices` returns `ids` only when `share_ids_of(id)` returns `Ok(ids)`. -/
theorem my_indices_ok {r : threshold_schnorr.avss.Receiver} {ids}
    (h : threshold_schnorr.avss.Receiver.my_indices r = ok ids) :
    nodes.Nodes.share_ids_of
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize r.nodes r.id
      = ok (core.result.Result.Ok ids) := by
  unfold threshold_schnorr.avss.Receiver.my_indices at h
  obtain ⟨e, he, h⟩ := bind_eq_ok h
  rw [he, unwrap_eq_ok h]

theorem recover_sound (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message)
    (vs : alloc.vec.Vec threshold_schnorr.avss.VerifiedComplaintResponse)
    (o : threshold_schnorr.avss.AvssOutput)
    (h : threshold_schnorr.avss.Receiver.recover r m vs = ok (core.result.Result.Ok o)) :
    ValidShares r.nodes m r.id o.my_shares := by
  unfold threshold_schnorr.avss.Receiver.recover at h
  ok_inv at h
  all_goals
    subst h
    exact ⟨_, my_indices_ok ‹_›, ‹threshold_schnorr.avss.SharesForNode.verify _ m _ r.id = _›⟩

end AvssProofs
