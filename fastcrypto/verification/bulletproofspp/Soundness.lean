-- THIS FILE IS AI-ONLY
import bulletproofspp.Correctness
import bulletproofspp.Proofs.CircuitSoundness

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
    (alpha rho lambda beta delta : F) (τ : Fˣ)
    (p : List (E × E) × List F × Spec.NormLinear.Witness F) : Prop :=
  ∃ (rp : RangeProof F E) (oracle : List (Entry F E) → F),
    let t := transcript oracle dst range.bits commitments.length
    rp.proof.c_s = cS ∧ rp.proof.c_o = cO ∧ rp.proof.c_l = cL ∧ rp.proof.c_r = cR ∧
    oracle (alphaLog t commitments rp.proof) = alpha ∧ oracle (rhoLog t commitments rp.proof) = rho ∧
    oracle (lamLog t commitments rp.proof) = lambda ∧
    oracle (betaLog t commitments rp.proof) = beta ∧
    oracle (deltaLog t commitments rp.proof) = delta ∧ oracle (tauLog t commitments rp.proof) = τ ∧
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
    (alpha rho lambda beta delta : F) (τ : Fˣ) (p : List (E × E) × List F × Spec.NormLinear.Witness F)
    (h : BatchRun generators commitments range dst cS cO cL cR alpha rho lambda beta delta τ p) :
    LeafRun gens params commitments cS cO cL cR alpha rho lambda beta delta τ p := by
  obtain ⟨rp, oracle, e1, e2, e3, e4, ha, hr, hl, hb, hd, ht, h1, h2, h3, hv⟩ := h
  obtain ⟨t', hrun⟩ := verify_batch_run rp oracle generators commitments range dst gens params hgens
    hparams hv
  exact ⟨rp.proof, _, t', e1, e2, e3, e4, ha, hr, hl, hb, hd, ht, h1, h2, h3, hrun⟩

/-- **Special soundness of `verify_batch`.** Take a tree of accepting runs of `verify_batch` on
fixed `commitments`, `range` and `dst`, each with its own transcript hash, forked as in
`Circuit.verify_extract`. If `Generators::new` returns `H_LEN` and `nm` generators with
`g = pedersen::H` and `h_vec[0] = pedersen::G`, every commitment is a Pedersen commitment to a
value in `range`, or the generators satisfy a nontrivial linear relation. -/
theorem verify_extract (generators : ℕ → Result (Generators E))
    (commitments : List (PedersenCommitment E)) (range : Range) (dst : List ℕ)
    (gens : Generators E) (params : CircuitParams)
    (hgens : generators params.nm = .ok gens)
    (hparams : CircuitParams.new range commitments.length = .ok params) (hv : params.Valid)
    (hh : gens.h_vec.length = H_LEN) (hg : gens.g_vec.length = params.nm) (G H : E)
    (hgH : gens.g = H) (hhG : gens.h_vec.getD 0 0 = G) (hc : commitments ≠ [])
    (h2 : (2 : F) ≠ 0) (hchar : ∀ m : ℕ, 0 < m → m ≤ (params.toSpec hv).Nd → (m : F) ≠ 0)
    (cO cL : E) (cR : Fin ((params.toSpec hv).Nd + 16) → E)
    (cS : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 →
      Fin (params.m * (params.nm + 8) + 1) → E)
    (α : Fin ((params.toSpec hv).Nd + 16) → F)
    (rho δ : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → F)
    (β : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 → F)
    (lam : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 →
      Fin (params.m * (params.nm + 8) + 1) → F)
    (τ : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 →
      Fin (params.m * (params.nm + 8) + 1) → Fin 13 → F)
    (hα : Function.Injective α) (hμ : ∀ a, Function.Injective fun r => rho a r * rho a r)
    (hβ : ∀ a r, Function.Injective (β a r)) (hlam : ∀ a r b, Function.Injective (lam a r b))
    (hτ : ∀ a r b l, Function.Injective (τ a r b l))
    (hpole : ∀ a, ∀ j : ℕ, j < 16 → α a + j ≠ 0) (hρ0 : ∀ a r, rho a r ≠ 0)
    (hδ0 : ∀ a r, δ a r ≠ 0) (hτ0 : ∀ a r b l t, τ a r b l t ≠ 0)
    (trees : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 →
      Fin (params.m * (params.nm + 8) + 1) → Fin 13 → Spec.NormLinear.Tree F E) (d : ℕ)
    (hd : ∀ a r b l t, (trees a r b l t).Depth d) (hdist : ∀ a r b l t, (trees a r b l t).Distinct)
    (hL : 2 ^ d ∣ params.nm)
    (hruns : ∀ a r b l t, ∀ p ∈ (trees a r b l t).paths,
      BatchRun generators commitments range dst (cS a r b l) cO cL (cR a) (α a) (rho a r)
        (lam a r b l) (β a r b) (δ a r) (Units.mk0 (τ a r b l t) (hτ0 a r b l t)) p) :
    (∃ (v : ℕ → ℕ) (s : ℕ → F), ∀ i < commitments.length, range.is_in_range (v i) ∧
      commitments.getD i ⟨0⟩ = PedersenCommitment.new G H (v i : F) (s i)) ∨
    Spec.Relation F (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0)
      (fun k => gens.g_vec.getD k 0) := by
  have hm : commitments.length ≠ 0 := by simpa using hc
  obtain ⟨params', hpn, -, -, hpm, h16⟩ := params_new range commitments.length hm
  obtain rfl : params = params' := by rw [hparams] at hpn; exact Except.ok.inj hpn
  rcases Circuit.verify_extract gens params hv hh hg h2 hchar (by omega) commitments hpm.symm cO cL
    cR cS α rho δ β lam τ hα hμ hβ hlam hτ hpole hρ0 hδ0 hτ0 trees d hd hdist hL
    (fun a r b l t p hp => leafRun_of_batchRun generators commitments range dst gens params hgens
      hparams _ _ _ _ _ _ _ _ _ _ p (hruns a r b l t p hp)) with ⟨v, s, hvs⟩ | hrel
  · left
    refine ⟨v, s, fun i hi => ?_⟩
    obtain ⟨hlt, hpt⟩ := hvs i (by omega)
    refine ⟨?_, ?_⟩
    · simp only [Range.is_in_range, decide_eq_true_eq]
      rw [h16] at hlt
      omega
    · rw [show commitments.getD i ⟨0⟩ = ⟨(commitments.getD i ⟨0⟩).point⟩ from rfl, hpt, hgH, hhG,
        PedersenCommitment.new]
  · exact Or.inr hrel

end RangeProof

end Bppp
