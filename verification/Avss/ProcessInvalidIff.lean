import Avss.Generated.Funs
import Avss.Result

/-!
`process_invalid_iff` for the code Aeneas generated from `Receiver::process_message`: two
receivers configured alike (same `nodes`, `params`, `sid` and `commitment`) either both return an
error for a message or neither does, when both return.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs

/-- `x` is an `Err`. -/
def IsErr {T E : Type _} (x : core.result.Result T E) : Prop := ∃ e, x = .Err e

/-- Receivers configured alike get the same result from `check_message`: it reads only `nodes`,
`params`, `sid` and `commitment`. -/
theorem check_message_congr (r₁ r₂ : threshold_schnorr.avss.Receiver) (hn : r₁.nodes = r₂.nodes)
    (hp : r₁.params = r₂.params) (hs : r₁.sid = r₂.sid) (hc : r₁.commitment = r₂.commitment)
    (m : threshold_schnorr.avss.Message) :
    threshold_schnorr.avss.Receiver.check_message r₁ m =
      threshold_schnorr.avss.Receiver.check_message r₂ m := by
  unfold threshold_schnorr.avss.Receiver.check_message threshold_schnorr.avss.Receiver.random_oracle
  rw [hn, hp, hs, hc]

/-- `verify_message` returns an error exactly when `check_message` does, when it returns. -/
theorem verify_message_err (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message)
    (y : core.result.Result (Option threshold_schnorr.avss.AvssOutput)
      fastcrypto.error.FastCryptoError)
    (h : threshold_schnorr.avss.Receiver.verify_message r m = ok y) :
    IsErr y ↔ ∃ c, threshold_schnorr.avss.Receiver.check_message r m = ok c ∧ IsErr c := by
  unfold threshold_schnorr.avss.Receiver.verify_message at h
  ok_inv at h
  all_goals
    subst h
    simp_all [IsErr]

/-- `process_message` returns an error exactly when `check_message` does, when it returns. -/
theorem process_message_err {R : Type} (rngInst : fastcrypto.traits.AllowedRng R)
    (r : threshold_schnorr.avss.Receiver) (m : threshold_schnorr.avss.Message) (g g' : R)
    (x : core.result.Result threshold_schnorr.avss.ProcessedMessage fastcrypto.error.FastCryptoError)
    (h : threshold_schnorr.avss.Receiver.process_message rngInst r m g = ok (x, g')) :
    IsErr x ↔ ∃ c, threshold_schnorr.avss.Receiver.check_message r m = ok c ∧ IsErr c := by
  unfold threshold_schnorr.avss.Receiver.process_message at h
  ok_inv at h
  all_goals
    rw [← verify_message_err r m _ ‹_›]
    obtain ⟨rfl, -⟩ := h
    simp [IsErr]

theorem process_invalid_iff {R : Type} (rngInst : fastcrypto.traits.AllowedRng R)
    (r₁ r₂ : threshold_schnorr.avss.Receiver) (hn : r₁.nodes = r₂.nodes)
    (hp : r₁.params = r₂.params) (hs : r₁.sid = r₂.sid) (hc : r₁.commitment = r₂.commitment)
    (m : threshold_schnorr.avss.Message) (g₁ g₂ g₁' g₂' : R)
    (x₁ x₂ : core.result.Result threshold_schnorr.avss.ProcessedMessage
      fastcrypto.error.FastCryptoError)
    (h₁ : threshold_schnorr.avss.Receiver.process_message rngInst r₁ m g₁ = ok (x₁, g₁'))
    (h₂ : threshold_schnorr.avss.Receiver.process_message rngInst r₂ m g₂ = ok (x₂, g₂')) :
    IsErr x₁ ↔ IsErr x₂ := by
  rw [process_message_err rngInst r₁ m g₁ g₁' x₁ h₁, process_message_err rngInst r₂ m g₂ g₂' x₂ h₂,
    check_message_congr r₁ r₂ hn hp hs hc m]

end AvssProofs
