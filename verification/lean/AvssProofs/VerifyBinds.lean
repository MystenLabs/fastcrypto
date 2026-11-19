import Avss.Funs

/-!
`verify_binds` for the code Aeneas generated from `Receiver::verify_complaint_response`:
if it returns `Ok(v)`, then `v.responder_id` is the given `responder_id`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

theorem verify_binds (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message)
    (j : Std.U16) (resp : threshold_schnorr.avss.ComplaintResponse)
    (v : threshold_schnorr.avss.VerifiedComplaintResponse)
    (h : threshold_schnorr.avss.Receiver.verify_complaint_response r m j resp
      = ok (core.result.Result.Ok v)) :
    v.responder_id = j := by
  unfold threshold_schnorr.avss.Receiver.verify_complaint_response at h
  generalize nodes.Nodes.share_ids_of
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElementRistrettoScalar
      fastcrypto.groups.ristretto255.RistrettoPoint.Insts.Serde_coreSerSerialize r.nodes j = a at h
  cases a with
  | ret ids =>
    cases ids with
    | Ok ids =>
      simp only [bind_ok, core.result.Result.Insts.CoreOpsTry.branch] at h
      generalize threshold_schnorr.avss.SharesForNode.verify resp.shares m
        (alloc.vec.Vec.deref ids) j = b at h
      cases b with
      | ret x =>
        cases x with
        | Ok _ =>
          simp only [bind_ok, Result.ok_injective.eq_iff, core.result.Result.Ok.injEq] at h
          rw [← h]
        | Err e =>
          have := congrArg Result.match h
          simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at this
      | vis i k =>
        have := congrArg Result.match h
        simp at this
      | div =>
        have := congrArg Result.match h
        simp at this
    | Err e =>
      have := congrArg Result.match h
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at this
  | vis i k =>
    have := congrArg Result.match h
    simp at this
  | div =>
    have := congrArg Result.match h
    simp at this


end AvssProofs
