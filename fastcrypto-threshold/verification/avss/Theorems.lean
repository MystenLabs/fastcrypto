-- THIS FILE IS AI-ONLY
import avss.Protocol.LinkCommitment
import avss.Protocol.Agreement
import avss.Protocol.HonestDealer

/-!
The theorems about `fastcrypto_threshold::threshold_schnorr::avss`, for the generated code, under
the hypotheses of the link to the code (`Assumptions`). They follow from the protocol-level
theorems of the same names in `avss.Protocol` and `Link.contracts`.

For a message `m` certified by `signers` (`Certificate`), in an execution in which the corrupt
parties have weight at most `f`:
* `every_honest_party_gets_valid_shares`: every honest party eventually holds an output whose
  shares pass `SharesForNode::verify`, directly or through complaints and `recover`.
* `honest_outputs_agree`: all honest outputs fit one polynomial of degree `< t`, in their shares
  and their Feldman commitments.
* `honest_dealer_no_complaints`: if every receiver finds `m` valid, every honest party gets valid
  shares from `process_message` and never complains.
-/

open Aeneas Aeneas.Std Result
open fastcrypto_threshold

namespace AvssProofs.Link

/-- `CommitmentOpening` implies `CommitmentBinding`. -/
theorem CommitmentOpening.binding {Z : Scalars} (h : CommitmentOpening Z) : CommitmentBinding := by
  intro c d hd
  obtain ⟨p, e, he, hed, -, hiff, -⟩ := h c d hd
  exact ⟨p, e, he, hed, fun k v hv => (hiff k v).mp hv⟩

open scoped ENNReal in
/-- The hypotheses of `contracts`, together. -/
structure Assumptions (C : Receivers) (Z : Scalars) (D : Dealers Z) : Prop where
  clone : CloneIsId
  polyClone : PolyCloneIsId
  polyEq : PolyEqRefl
  recovery : RecoveryComplete
  interpolation : ∀ j, InterpolationComplete (C.recv j)
  nonZero : NonZeroModel Z
  shareIds : ∀ j : Party C.ns, ∃ ids, shareIdsOf C.ns j.val = ok (core.result.Result.Ok ids)
  weightsFit : ∀ A : Finset (Party C.ns), (setup C).weightOf A ≤ U16.max
  processReturns : ∀ (j : Party C.ns) m, ∃ y,
    threshold_schnorr.avss.Receiver.process_message C.rngInst (C.recv j.val) m (C.rng j.val) =
      ok y
  createValid : CreateValid C Z D
  createSecret : CreateSecret C Z D
  opening : CommitmentOpening Z
  genInjective : Function.Injective Z.gen
  sharesCoverT : SharesCoverT C Z D
  evalDetermined : EvalDetermined C Z D

variable {C : Receivers} {Z : Scalars} {D : Dealers Z}

theorem Assumptions.contracts (h : Assumptions C Z D) :
    Protocol.Avss.Contracts (setup C) (api C Z D) :=
  AvssProofs.Link.contracts C Z D h.clone h.polyClone h.polyEq h.recovery
    h.interpolation h.opening.binding h.nonZero h.shareIds h.weightsFit h.processReturns
    h.createValid h.createSecret
    (output_commitment C Z D h.polyClone h.opening h.genInjective h.nonZero h.sharesCoverT
      h.evalDetermined)

/-! The protocol theorems that follow from `Contracts`, for the generated code. -/

open Protocol.Avss in
/-- **Liveness of AVSS.** For a certified message, every honest party eventually holds an output
whose shares pass `SharesForNode::verify(m, share_ids_of(i), i)`. -/
theorem every_honest_party_gets_valid_shares (h : Assumptions C Z D)
    (hS : (setup C).Valid) {corrupt : Finset (Party C.ns)} (hcorrupt : (setup C).Tolerates corrupt)
    {m : threshold_schnorr.avss.Message} {signers : Finset (Party C.ns)}
    (hcert : Certificate (setup C) (api C Z D) corrupt m signers)
    {σ : ℕ → State (api C Z D)}
    (hrun : Run (api C Z D) m corrupt signers σ) (i : Party C.ns) (hi : i ∉ corrupt) :
    ∃ n o, (σ n).output i = some o ∧ (api C Z D).ValidOutput m i o :=
  Protocol.Avss.every_honest_party_gets_valid_shares hS h.contracts hcorrupt hcert hrun i hi

open Protocol.Avss in
/-- **Agreement.** All outputs honest parties hold for a certified message fit one polynomial of
degree `< t`, in their shares and their Feldman commitments. -/
theorem honest_outputs_agree (h : Assumptions C Z D) (hS : (setup C).Valid)
    {corrupt : Finset (Party C.ns)} (hcorrupt : (setup C).Tolerates corrupt)
    {m : threshold_schnorr.avss.Message} {signers : Finset (Party C.ns)}
    (hcert : Certificate (setup C) (api C Z D) corrupt m signers)
    {σ : ℕ → State (api C Z D)}
    (hrun : BasicRun (api C Z D) m corrupt σ) (i₀ : Party C.ns) :
    ∃ p, (api C Z D).Sh.degreeBound p < (setup C).t ∧
      ∀ i n o, i ∉ corrupt → (σ n).output i = some o →
        (api C Z D).shareList ((api C Z D).shares o) =
          ((api C Z D).shareIds i).map ((api C Z D).Sh.eval p) ∧
        ∀ k, (api C Z D).committed o k = ((api C Z D).Sh.eval p k).value :=
  Protocol.Avss.honest_outputs_agree hS h.contracts hcorrupt hcert hrun i₀

open Protocol.Avss in
/-- **Honest dealer: no complaints.** If every receiver finds `m` valid, every honest party
eventually holds an output from `process_message` whose shares verify, and never complains. -/
theorem honest_dealer_no_complaints (h : Assumptions C Z D)
    {m : threshold_schnorr.avss.Message} (hm : (api C Z D).AllValid m)
    {corrupt : Finset (Party C.ns)} {σ : ℕ → State (api C Z D)}
    (hrun : BasicRun (api C Z D) m corrupt σ) (i : Party C.ns)
    (hi : i ∉ corrupt) :
    (∃ n o, (σ n).output i = some o ∧ (api C Z D).ValidOutput m i o) ∧
      ∀ n c, (σ n).processed i ≠ some (.complaint c) :=
  Protocol.Avss.honest_dealer_no_complaints h.contracts hm hrun i hi

end AvssProofs.Link
