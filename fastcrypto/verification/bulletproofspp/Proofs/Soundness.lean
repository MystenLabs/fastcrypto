-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Correctness
import bulletproofspp.Proofs.Model.CircuitSoundness

/-!
# Special soundness of `range_proof.rs`

A tree of accepting runs of `RangeProof::verify_batch` on fixed commitments, forked at the
challenges of §5.3 of the paper, extracts a Pedersen opening of every commitment to a value in
`range`, or a nontrivial linear relation among the generators.
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

set_option linter.unusedSectionVars false

namespace RangeProof

open BpppTranscript Circuit

/-- An accepting `verify_batch` runs `circuit::verify` on the generators and parameters for the
batch size, from the transcript `transcript` sets up. -/
lemma verify_batch_run (rp : RangeProof F E) (oracle : List (Entry F E) → F)
    (generators : ℕ → Result (Generators E)) (commitments : List (PedersenCommitment E))
    (range : Range) (dst : List ℕ) (gens : Generators E) (params : CircuitParams)
    (hgens : generators params.nm = .ok gens)
    (hparams : CircuitParams.new range commitments.length = .ok params)
    (h : rp.verify_batch oracle generators commitments range dst = .ok ()) :
    ∃ t', (Circuit.verify gens params rp.proof commitments).run
      (transcript oracle dst range.bits commitments.length) = .ok ((), t') := by
  have hc : commitments ≠ [] := by
    rintro rfl; simp [verify_batch] at h; cases h
  simp only [verify_batch, hc, if_false, setup, hparams, hgens, bind, Except.bind, pure, Except.pure, StateT.run'] at h
  rcases hr : Circuit.verify gens params rp.proof commitments
    (transcript oracle dst range.bits commitments.length) with e | ⟨⟨⟩, t'⟩
  · rw [hr] at h; cases h
  · exact ⟨t', hr⟩

/-- What a run at a leaf must be: an accepting run of `verify_batch` whose proof has the given
messages, whose transcript derives the given challenges, and whose norm-linear part is the path
`p` of the leaf's tree of rounds. -/
def BatchRun (generators : ℕ → Result (Generators E))
    (commitments : List (PedersenCommitment E)) (range : Range) (dst : List ℕ) (cS cO cL cR : E)
    (alpha rho lambda beta : F) (τ : Fˣ)
    (p : List (E × E) × List F × Spec.NormLinear.Witness F) : Prop :=
  ∃ (rp : RangeProof F E) (oracle : List (Entry F E) → F),
    let t := transcript oracle dst range.bits commitments.length
    rp.proof.c_s = cS ∧ rp.proof.c_o = cO ∧ rp.proof.c_l = cL ∧ rp.proof.c_r = cR ∧
    oracle (alphaLog t commitments rp.proof) = alpha ∧ oracle (rhoLog t commitments rp.proof) = rho ∧
    oracle (lamLog t commitments rp.proof) = lambda ∧
    oracle (betaLog t commitments rp.proof) = beta ∧ oracle (tauLog t commitments rp.proof) = τ ∧
    p.1 = rp.proof.nl_proof.rounds ∧
    p.2.1 = NormLinear.gammasOf ((afterTau t commitments rp.proof).extend
      [.message "dom-sep" ("norm_linear".toList.map Char.toNat)]) rp.proof.nl_proof.rounds ∧
    p.2.2 = ⟨fun k => [rp.proof.nl_proof.l_final].getD k 0,
      fun k => rp.proof.nl_proof.n_final.getD k 0⟩ ∧
    rp.verify_batch oracle generators commitments range dst = .ok ()

lemma leafRun_of_batchRun (generators : ℕ → Result (Generators E))
    (commitments : List (PedersenCommitment E)) (range : Range) (dst : List ℕ) (gens : Generators E)
    (params : CircuitParams) (hgens : generators params.nm = .ok gens)
    (hparams : CircuitParams.new range commitments.length = .ok params) (cS cO cL cR : E)
    (alpha rho lambda beta : F) (τ : Fˣ) (p : List (E × E) × List F × Spec.NormLinear.Witness F)
    (h : BatchRun generators commitments range dst cS cO cL cR alpha rho lambda beta τ p) :
    LeafRun gens params commitments cS cO cL cR alpha rho lambda beta τ p := by
  obtain ⟨rp, oracle, e1, e2, e3, e4, ha, hr, hl, hb, ht, h1, h2, h3, hv⟩ := h
  obtain ⟨t', hrun⟩ := verify_batch_run rp oracle generators commitments range dst gens params hgens
    hparams hv
  exact ⟨rp.proof, _, t', e1, e2, e3, e4, ha, hr, hl, hb, ht, h1, h2, h3, hrun⟩

end RangeProof

end Bppp
