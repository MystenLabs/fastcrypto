import bulletproofspp.Proofs.RustTheorems

/-!
The theorems about `fastcrypto::bulletproofspp`. This file, `Assumptions.lean` and the model in
`Model/`, which the theorems are stated with, are the claim of the proofs, so a reviewer reads them
in full. The files in `Proofs/` are lemmas, which Lean checks.

* Theorems about the model (`Bppp.RangeProof`): completeness, special soundness, zero-knowledge,
  and the hygiene of the Fiat–Shamir transcript.
* Theorems about the Rust code (`BpppProofs.RangeProof`): the translated prover outputs the
  model's proof for some draws of its random number generator, the translated verifier accepts
  exactly when the model's does, so honest proofs of the translated prover are accepted by the
  translated verifier, and the prover has the model's distribution and is zero-knowledge.
-/

/-! ## Theorems about the model -/

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

set_option linter.unusedSectionVars false

open Finset

namespace RangeProof

/-- **Completeness.** For values in `range`, generators for the batch's `nm` of the right shape
whose `G` and `H_0` are the Pedersen bases, and a transcript hash that never outputs `-j` for
`j < 16`, `verify_batch` accepts the proof of `prove_batch` for the Pedersen commitments to the
values. -/
theorem completeness (oracle : List (Entry F E) → F) (generators : ℕ → Result (Generators E))
    (G H : E) (values : List ℕ) (blindings : List F) (range : Range) (dst : List ℕ)
    (rng : Circuit.Randomness F) (gens : Generators E) (params : CircuitParams)
    (hvals : values ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values, range.is_in_range v)
    (hparams : CircuitParams.new range values.length = .ok params)
    (hgens : generators params.nm = .ok gens) (hh : gens.h_vec.length = H_LEN)
    (hg : gens.g_vec.length = params.nm) (hgH : gens.g = H)
    (hhG : gens.h_vec.getD 0 0 = G) (horacle : ∀ log, ∀ j : ℕ, j < 16 → oracle log + j ≠ 0) :
    ∃ proof, prove_batch oracle generators G H values blindings range dst rng = .ok proof ∧
      proof.verify_batch oracle generators (commitments G H values blindings) range dst = .ok () := by
  have hm : values.length ≠ 0 := by simpa using hvals
  obtain ⟨params', hpn, hv, hpr, hpm, h16⟩ := params_new range values.length hm
  obtain rfl : params = params' := by rw [hparams] at hpn; exact Except.ok.inj hpn
  have hd : ∀ v ∈ values, v < 16 ^ params.d := fun v hv' => by
    have := hrange v hv'
    simp only [Range.is_in_range, decide_eq_true_eq] at this
    rw [h16]; have := Nat.one_le_two_pow (n := range.bits); omega
  obtain ⟨proof, t', hprove, hverify⟩ := Circuit.completeness params hv rng values blindings G H
    gens (transcript oracle dst range.bits values.length) hh hg hgH hhG hpm.symm
    (by rw [hb, hpm]) (by rw [hpr]; exact hrange) hd (fun log j hj => horacle log j hj)
  refine ⟨⟨proof⟩, ?_, ?_⟩
  · have hc : ¬(values = [] ∨ values.length ≠ blindings.length ∨
        values.any (fun v => !range.is_in_range v)) := by
      simp [hvals, hb]; intro v hv'; simpa using hrange v hv'
    have hp : Circuit.prove G H gens params rng values blindings
        (transcript oracle dst range.bits values.length) =
          .ok ((proof, commitments G H values blindings), t') := hprove
    simp only [prove_batch, hc, if_false, setup, hparams, hgens, bind, Except.bind, pure,
      Except.pure, StateT.run', hp]
    rfl
  · have hlen : (commitments G H values blindings : List (PedersenCommitment E)).length =
        values.length := by simp [commitments, length_to_scalars, hb]
    have hc : ¬(commitments G H values blindings : List (PedersenCommitment E)) = [] := by
      intro h0; rw [h0] at hlen; exact hm hlen.symm
    have hv' : Circuit.verify gens params proof (commitments G H values blindings)
        (transcript oracle dst range.bits values.length) = .ok ((), t') := hverify
    simp only [verify_batch, hc, if_false, setup, hlen, hparams, hgens, bind, Except.bind, pure,
      Except.pure, StateT.run', hv']
    rfl

section

open BpppTranscript Circuit

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
    (rho : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → F)
    (β : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 → F)
    (lam : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 →
      Fin (params.m * (params.nm + 8) + 1) → F)
    (τ : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 →
      Fin (params.m * (params.nm + 8) + 1) → Fin 13 → F)
    (hα : Function.Injective α) (hμ : ∀ a, Function.Injective fun r => rho a r * rho a r)
    (hβ : ∀ a r, Function.Injective (β a r)) (hlam : ∀ a r b, Function.Injective (lam a r b))
    (hτ : ∀ a r b l, Function.Injective (τ a r b l))
    (hpole : ∀ a, ∀ j : ℕ, j < 16 → α a + j ≠ 0) (hρ0 : ∀ a r, rho a r ≠ 0)
    (hτ0 : ∀ a r b l t, τ a r b l t ≠ 0)
    (trees : Fin ((params.toSpec hv).Nd + 16) → Fin (params.nm + 1) → Fin 2 →
      Fin (params.m * (params.nm + 8) + 1) → Fin 13 → Spec.NormLinear.Tree F E) (d : ℕ)
    (hd : ∀ a r b l t, (trees a r b l t).Depth d) (hdist : ∀ a r b l t, (trees a r b l t).Distinct)
    (hL : 2 ^ d ∣ params.nm)
    (hruns : ∀ a r b l t, ∀ p ∈ (trees a r b l t).paths,
      BatchRun generators commitments range dst (cS a r b l) cO cL (cR a) (α a) (rho a r)
        (lam a r b l) (β a r b) (Units.mk0 (τ a r b l t) (hτ0 a r b l t)) p) :
    (∃ (v : ℕ → ℕ) (s : ℕ → F), ∀ i < commitments.length, range.is_in_range (v i) ∧
      commitments.getD i ⟨0⟩ = PedersenCommitment.new G H (v i : F) (s i)) ∨
    Spec.Relation F (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0)
      (fun k => gens.g_vec.getD k 0) := by
  have hm : commitments.length ≠ 0 := by simpa using hc
  obtain ⟨params', hpn, -, -, hpm, h16⟩ := params_new range commitments.length hm
  obtain rfl : params = params' := by rw [hparams] at hpn; exact Except.ok.inj hpn
  rcases Circuit.verify_extract gens params hv hh hg h2 hchar (by omega) commitments hpm.symm cO cL
    cR cS α rho β lam τ hα hμ hβ hlam hτ hpole hρ0 hτ0 trees d hd hdist hL
    (fun a r b l t p hp => leafRun_of_batchRun generators commitments range dst gens params hgens
      hparams _ _ _ _ _ _ _ _ _ p (hruns a r b l t p hp)) with ⟨v, s, hvs⟩ | hrel
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

end

section

open BpppTranscript Circuit

/-- **The verifier hashes only the challenge logs.** Two transcript hashes that agree on
`challengeLogs` of the statement and the proof give the same `verify_batch` result, accepting or
rejecting. -/
theorem verify_batch_local (rp : RangeProof F E) (o o' : List (Entry F E) → F)
    (generators : ℕ → Result (Generators E)) (commitments : List (PedersenCommitment E))
    (range : Range) (dst : List ℕ)
    (h : ∀ q ∈ challengeLogs (transcript o dst range.bits commitments.length) commitments rp.proof,
      o' q = o q) :
    rp.verify_batch o' generators commitments range dst =
      rp.verify_batch o generators commitments range dst := by
  simp only [verify_batch]
  split_ifs
  · rfl
  simp only [setup]
  rcases CircuitParams.new range commitments.length with e | params
  · rfl
  simp only [bind, Except.bind]
  rcases generators params.nm with e | gens
  · rfl
  simp only [pure, Except.pure, StateT.run']
  have key := (Circuit.readsOnly_verify gens params rp.proof commitments
    (transcript o dst range.bits commitments.length)).swap o' h
  rw [show transcript o' dst range.bits commitments.length =
    (transcript o dst range.bits commitments.length).withOracle o' from rfl]
  have key' : Circuit.verify gens params rp.proof commitments
      ((transcript o dst range.bits commitments.length).withOracle o') =
      swapRes o' (Circuit.verify gens params rp.proof commitments
        (transcript o dst range.bits commitments.length)) := key
  rw [key']
  rcases Circuit.verify gens params rp.proof commitments
    (transcript o dst range.bits commitments.length) with e | ⟨⟨⟩, t'⟩ <;> rfl

end

section

open BpppTranscript Circuit

/-- **The challenge logs decode uniquely.** If two challenge logs, of any statements and proofs,
absorb the same labels and bytes, they are the same log of the same statement. Points are under
any injective encoding, untagged as in Rust, and `n_bits` and `m` fit a `u64`. -/
theorem challenge_decodes {encP : E → List ℕ} {encS : F → List ℕ} (hP : Function.Injective encP)
    {o o' : List (Entry F E) → F} {dst dst' : List ℕ} {bits bits' : ℕ}
    {vcs vcs' : List (PedersenCommitment E)} {proof proof' : CircuitProof F E}
    (hb : bits < 2 ^ 64) (hb' : bits' < 2 ^ 64) (hm : vcs.length < 2 ^ 64)
    (hm' : vcs'.length < 2 ^ 64) {q q' : List (Entry F E)}
    (hq : q ∈ challengeLogs (transcript o dst bits vcs.length) vcs proof)
    (hq' : q' ∈ challengeLogs (transcript o' dst' bits' vcs'.length) vcs' proof')
    (h : q.map (Entry.bytes encP encS) = q'.map (Entry.bytes encP encS)) :
    dst = dst' ∧ bits = bits' ∧ vcs = vcs' ∧ q = q' := by
  obtain ⟨⟨r, rfl⟩, hl⟩ := challengeLogs_shape o dst bits vcs proof q hq
  obtain ⟨⟨r', rfl⟩, hl'⟩ := challengeLogs_shape o' dst' bits' vcs' proof' q' hq'
  have e := map_bytes_inj hP hl hl' h
  exact ⟨(stmt_eq hb hb' hm hm' e).1, (stmt_eq hb hb' hm hm' e).2.1, (stmt_eq hb hb' hm hm' e).2.2, e⟩

end

section

open BpppTranscript Circuit

/-- **No two challenges share a log.** Within a run, every challenge is drawn at a different log,
so no two challenges are forced to be equal. -/
theorem challengeLogs_nodup (t : BpppTranscript F E) (vcs : List (PedersenCommitment E))
    (proof : CircuitProof F E) : (challengeLogs t vcs proof).Nodup := by
  refine List.Pairwise.imp (R := fun a b : List (Entry F E) => a.length < b.length)
    (fun h e => by rw [e] at h; exact lt_irrefl _ h) ?_
  simp only [challengeLogs, nlLogs, List.pairwise_append, List.pairwise_cons, List.pairwise_map,
    List.mem_cons, List.mem_map, List.mem_range, List.not_mem_nil, List.Pairwise.nil, or_false,
    forall_eq_or_imp, forall_eq, forall_exists_index, and_imp, forall_apply_eq_imp_iff₂]
  simp only [alphaLog, rhoLog, lamLog, betaLog, tauLog, List.length_append,
    List.length_cons, List.length_nil, length_roundEntries, List.length_take]
  and_intros
  all_goals first
    | omega
    | (intro i hi; omega)
    | exact List.pairwise_lt_range.imp_of_mem fun {i j} _ hj h => by
        simp only [List.mem_range] at hj; omega
    | (intro _ h; exact h.elim)
    | trivial

end

section ZK

open BpppTranscript Circuit OracleComp ChallengeVerifyProtocol

variable [Fintype F] [SampleableType F]

/-- **Honest-verifier zero-knowledge of `range_proof`** (Theorem 1 of the paper), as VCVio's
`ChallengeVerifyProtocol.HVZK`. For batches of `m ≥ 1` values, with generators of the right shape
(`g = pedersen::H`, `h_vec[0] = pedersen::G`) in the span of `g` with `h_vec[j] = h_j g` and
`h_0 ≠ 0`, the transcripts of `prove_batch` against an honest verifier, whose challenges are
uniform, are within total variation distance `21 / |F|` of `simTranscript`, which sees only the
commitments, `range`, `dst` and the generators. -/
theorem zero_knowledge (generators : ℕ → Result (Generators E)) (G H : E) (range : Range)
    (dst : List ℕ) (gens : Generators E) (params : CircuitParams) (hv : params.Valid) (m : ℕ)
    (hm : m ≠ 0) (hgens : generators params.nm = .ok gens)
    (hparams : CircuitParams.new range m = .ok params) (hh : gens.h_vec.length = H_LEN)
    (hg : gens.g_vec.length = params.nm) (hgH : gens.g = H) (hhG : gens.h_vec.getD 0 0 = G)
    (h gg : ℕ → F) (hH : ∀ j, gens.h_vec.getD j 0 = h j • gens.g)
    (hG : ∀ k, gens.g_vec.getD k 0 = gg k • gens.g) (hh0 : h 0 ≠ 0) :
    ChallengeVerifyProtocol.HVZK (Chal := Chal F (rounds params))
      (protocol generators G H range dst params hv m)
      (simTranscript gens range dst params hv) (21 / Fintype.card F) := by
  classical
  intro V w hw
  letI : MeasurableSpace (Unit × Chal F (rounds params) × Result (RangeProof F E)) := ⊤
  obtain ⟨values, blindings⟩ := w
  simp only [decide_eq_true_eq] at hw
  obtain ⟨hlen, hb, hrange, rfl⟩ := hw
  subst hlen
  have hvals : values ≠ [] := fun h0 => hm (by simp [h0])
  simp only [realTranscript, protocol, simTranscript, pure_bind]
  refine (OracleComp.measureETVDist_bind_left_le_prEvent_of_evalDistEq _ _ _
    (Bad h ((params.toSpec hv).g 1)) fun c hc => ?_).trans (pr_bad_le h _ _)
  simp only [Bad, not_or, not_exists] at hc
  obtain ⟨hα, hρ, ⟨hβ0, hD⟩, hτ⟩ := hc
  have key := zero_knowledge_at (chalOracle c) generators G H values blindings range dst gens
    params hgens hparams hv hh hg hgH hhG hvals hb hrange h gg hH hG c.1 c.2.1 c.2.2.1 c.2.2.2.1
    (unitOr c.2.2.2.2.1) rfl rfl rfl rfl (by simp [unitOr, hτ]; rfl)
    (fun j hj => hα ⟨j, hj⟩) hρ hβ0 hh0 (sub_ne_zero.2 hD)
  simpa only [bind_pure_comp, Functor.map_map] using key.map (fun π => ((), c, π))

end ZK

end RangeProof

end Bppp

/-! ## Theorems about the Rust code -/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

/-- `RangeProof::prove_batch` outputs the proof of the model's `RangeProof.prove_batch` for the
draws `rngD` of its random number generator, or fails exactly when it does. -/
theorem RangeProof.prove_batch_refines {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (values : Slice U64) (blindings : Slice pedersen.Blinding)
    (range : pedersen.Range) (dst : Slice U8) (rng : R) (params : Bppp.CircuitParams)
    (hparams : Bppp.CircuitParams.new (toRange range) values.val.length = .ok params)
    (hsize : 256 * values.length + 256 ≤ Usize.max) :
    bulletproofspp.range_proof.RangeProof.prove_batch inst values blindings range dst rng ⦃ r =>
      match Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
          (blindings.val.map φ) (toRange range) (dst.val.map (·.val))
          (rngD φ hm.rand inst rng params.nm) with
      | .ok rp => ∃ rp', r.1 = .Ok rp' ∧ toRP φ ψ rp' = rp
      | .error _ => ∃ e, r.1 = .Err e ⦄ :=
  prove_batch_refines_spec hm inst values blindings range dst rng params hparams hsize

/-- `RangeProof::verify_batch` accepts exactly when the model's `RangeProof.verify_batch` does. -/
theorem RangeProof.verify_batch_refines
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H)
    (rp : bulletproofspp.range_proof.RangeProof) (commitments : Slice pedersen.PedersenCommitment)
    (range : pedersen.Range) (dst : Slice U8)
    (hsize : 256 * commitments.length + 256 ≤ Usize.max) :
    bulletproofspp.range_proof.RangeProof.verify_batch rp commitments range dst ⦃ r =>
      r = .Ok () ↔ (toRP φ ψ rp).verify_batch oracle (genM ψ) (commitments.val.map (toPC ψ))
          (toRange range) (dst.val.map (·.val)) = .ok () ⦄ := by
  apply WP.spec_mono (verify_batch_spec hm.scalar hm.point hm.transcript hm.transcript_init
    hm.gens rp commitments range dst hsize)
  intro r hr
  split at hr
  · rename_i h; exact ⟨fun _ => h, fun _ => hr⟩
  · rename_i e h
    obtain ⟨e', rfl⟩ := hr
    simp [h]

/-- **Completeness of the Rust code.** For values in `range` and blindings of the same length,
`RangeProof::prove_batch` returns a proof, for every state of the random number generator, and
`RangeProof::verify_batch` accepts it for the Pedersen commitments to the values. This needs a
transcript hash that never outputs `-j` for `j < 16`. -/
theorem RangeProof.completeness_rust
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (values : Slice U64) (blindings : Slice pedersen.Blinding)
    (range : pedersen.Range) (dst : Slice U8) (rng : R)
    (commitments : Slice pedersen.PedersenCommitment)
    (hvals : values.val ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values.val, (toRange range).is_in_range v.val)
    (hcs : commitments.val.map (toPC ψ) =
      Bppp.RangeProof.commitments G H (values.val.map (·.val)) (blindings.val.map φ))
    (hsize : 256 * values.length + 256 ≤ Usize.max)
    (horacle : ∀ log, ∀ j : ℕ, j < 16 → oracle log + j ≠ 0) :
    bulletproofspp.range_proof.RangeProof.prove_batch inst values blindings range dst rng ⦃ r =>
      ∃ rp, r.1 = .Ok rp ∧
        bulletproofspp.range_proof.RangeProof.verify_batch rp commitments range dst ⦃ v =>
          v = .Ok () ⦄ ⦄ := by
  have evl : values.length = values.val.length := rfl
  have ebl : blindings.length = blindings.val.length := rfl
  have hm0 : (values.val.map (·.val)).length ≠ 0 := by simpa using hvals
  obtain ⟨params, g, hpn, -, -, -, -, hgens, hh, hgl, hgH, hhG⟩ :=
    gens_for hm.gens range _ hm0 (by rw [List.length_map, ← evl]; exact hsize)
  apply WP.spec_mono (RangeProof.prove_batch_refines hm inst values blindings range dst rng params
    (by simpa using hpn) hsize)
  intro r hr
  obtain ⟨proof, hprove, hverify⟩ := Bppp.RangeProof.completeness oracle (genM ψ) G H
    (values.val.map (·.val)) (blindings.val.map φ) (toRange range) (dst.val.map (·.val))
    (rngD φ hm.rand inst rng params.nm) (toGens ψ g) params (by simpa using hvals)
    (by simp only [List.length_map]; exact hb) (by simpa using hrange) hpn hgens
    (by simpa [toGens, Bppp.H_LEN] using hh) (by simpa [toGens] using hgl)
    (by simpa [toGens] using hgH) (by simpa [toGens] using hhG) horacle
  rw [hprove] at hr
  obtain ⟨rp, h1, h2⟩ := hr
  refine ⟨rp, h1, ?_⟩
  have hcl : commitments.length = values.length := by
    have := congrArg List.length hcs
    simp only [List.length_map, Bppp.RangeProof.commitments, List.length_zip, Bppp.to_scalars] at this
    show commitments.val.length = _
    rw [this, evl, ← ebl, hb, evl, min_self]
  apply WP.spec_mono (RangeProof.verify_batch_refines hm rp commitments range dst (by omega))
  intro v hv
  rw [h2, hcs] at hv
  exact hv.mpr hverify

/-! ## Zero-knowledge -/

section ZK

variable [Fintype F] [SampleableType F]

/-- **The prover's distribution.** With valid inputs and an ideal random number generator,
`RangeProof::prove_batch` has the distribution, under the models, of the model's `prove_batch`
with uniform masks and blindings, for any transcript hash. -/
theorem RangeProof.prove_batch_distribution
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (D : ProbComp R) (hD : IdealRng φ hm.rand inst D)
    (values : Slice U64) (blindings : Slice pedersen.Blinding) (range : pedersen.Range)
    (dst : Slice U8) (params : Bppp.CircuitParams) (hv : params.Valid)
    (hparams : Bppp.CircuitParams.new (toRange range) values.val.length = .ok params)
    (hvals : values.val ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values.val, (toRange range).is_in_range v.val)
    (hsize : 256 * values.length + 256 ≤ Usize.max) :
    (fun rng => toRes φ ψ (rustProve inst values blindings range dst rng)) <$> D =ᵈ
      (fun x => Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
        (blindings.val.map φ) (toRange range) (dst.val.map (·.val))
        (Bppp.Circuit.rngOf params hv x)) <$>
        ($ᵗ (Bppp.Spec.Masks F (params.toSpec hv) × (Fin 15 → F))) := by
  have evl : values.length = values.val.length := rfl
  have hm0 : (values.val.map (·.val)).length ≠ 0 := by simpa using hvals
  obtain ⟨params', g, hpn, -, -, -, -, hgens, -⟩ :=
    gens_for hm.gens range _ hm0 (by rw [List.length_map, ← evl]; exact hsize)
  rw [List.length_map, hparams] at hpn
  cases hpn
  set model := fun x : Bppp.Spec.Masks F (params.toSpec hv) × (Fin 15 → F) =>
    Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
      (blindings.val.map φ) (toRange range) (dst.val.map (·.val)) (Bppp.Circuit.rngOf params hv x)
  set xO : (Fin (15 + params.nm + 1) → F) → Bppp.Spec.Masks F (params.toSpec hv) × (Fin 15 → F) :=
    fun f => xOf params.nm f
  have hxO : Function.Bijective xO := xOf_bijective params.nm
  have hfun : (fun rng => toRes φ ψ (rustProve inst values blindings range dst rng)) =
      (model ∘ xO) ∘ (fun rng => fun i : Fin (15 + params.nm + 1) =>
        φ (rdraw hm.rand inst i rng)) := by
    funext rng
    rw [rust_prove_eq hm inst values blindings range dst params _ hvals hb hrange hparams hgens
      hsize rng, rngD_eq]
    rfl
  rw [hfun, LawfulFunctor.comp_map]
  refine ((hD _).map _).trans ?_
  rw [LawfulFunctor.comp_map]
  exact (SampleableType.map_uniformSample_evalDistEq_of_bijective hxO).map _

/-- **Zero-knowledge of the Rust prover**, per challenge. If the transcript hash returns the
challenges `c` of an honest verifier, then with valid inputs and an ideal random number generator
the output of `RangeProof::prove_batch`, under the models, has the distribution of the response
at `c` of `protocol`, the model's protocol whose transcripts `RangeProof.zero_knowledge`
simulates. -/
theorem RangeProof.zero_knowledge_rust
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E} {G H : E}
    (params : Bppp.CircuitParams) (hv : params.Valid)
    (c : Bppp.RangeProof.Chal F (Bppp.RangeProof.rounds params))
    (hm : Models φ ψ τ (fun l => Bppp.RangeProof.chalOracle c (Bppp.BpppTranscript.chalLabels l))
      G H) {R : Type}
    (inst : traits.AllowedRng R) (D : ProbComp R) (hD : IdealRng φ hm.rand inst D)
    (values : Slice U64) (blindings : Slice pedersen.Blinding) (range : pedersen.Range)
    (dst : Slice U8) (V : List (Bppp.PedersenCommitment E))
    (hparams : Bppp.CircuitParams.new (toRange range) values.val.length = .ok params)
    (hvals : values.val ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values.val, (toRange range).is_in_range v.val)
    (hsize : 256 * values.length + 256 ≤ Usize.max) :
    (fun rng => toRes φ ψ (rustProve inst values blindings range dst rng)) <$> D =ᵈ
      (Bppp.RangeProof.protocol (genM ψ) G H (toRange range) (dst.val.map (·.val)) params hv
        values.val.length).respond V (values.val.map (·.val), blindings.val.map φ) () c :=
  RangeProof.prove_batch_distribution hm inst D hD values blindings range dst params hv hparams
    hvals hb hrange hsize

end ZK

end BpppProofs

#print axioms Bppp.RangeProof.completeness
#print axioms Bppp.RangeProof.verify_extract
#print axioms Bppp.RangeProof.verify_batch_local
#print axioms Bppp.RangeProof.challenge_decodes
#print axioms Bppp.RangeProof.challengeLogs_nodup
#print axioms Bppp.RangeProof.zero_knowledge
#print axioms BpppProofs.RangeProof.prove_batch_refines
#print axioms BpppProofs.RangeProof.verify_batch_refines
#print axioms BpppProofs.RangeProof.completeness_rust
#print axioms BpppProofs.RangeProof.prove_batch_distribution
#print axioms BpppProofs.RangeProof.zero_knowledge_rust
