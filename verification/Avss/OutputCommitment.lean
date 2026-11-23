import Avss.Generated.Funs
import Avss.Result
import Avss.HandleAccepts

/-!
The outputs of `Receiver::recover` carry the message's Feldman commitment.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- With `Poly::clone` the identity, `Rᵢ.recover(m, vs) = Ok(o)` ⇒
`o.feldman_commitment = m.feldman_commitment`. -/
theorem recover_commitment (hpclone : PolyCloneIsId) (r : threshold_schnorr.avss.Receiver)
    (m : threshold_schnorr.avss.Message)
    (vs : alloc.vec.Vec threshold_schnorr.avss.VerifiedComplaintResponse)
    (o : threshold_schnorr.avss.AvssOutput)
    (h : threshold_schnorr.avss.Receiver.recover r m vs = ok (core.result.Result.Ok o)) :
    o.feldman_commitment = m.feldman_commitment := by
  unfold threshold_schnorr.avss.Receiver.recover at h
  ok_inv at h
  all_goals
    subst h
    have hc := ‹polynomial.Poly.Insts.CoreCloneClone.clone _ _ = ok _›
    rw [hpclone, Result.ok_injective.eq_iff] at hc
    exact hc.symm

end AvssProofs
