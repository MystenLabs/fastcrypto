-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Circuit
import bulletproofspp.Proofs.NormLinearSoundness
import bulletproofspp.Spec.CircuitExtract

/-!
# Special soundness of `circuit.rs`

An accepting run of `circuit::verify` is an accepting run of `norm_linear::verify` on the
combined commitment `C(τ)` of `Spec` (`verify_run`, `vInst_eq`). So a tree of accepting runs,
forked at the challenges of §5.3, is one `Spec.circuit_extract` extracts from (`verify_extract`).
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

set_option linter.unusedSectionVars false

namespace Circuit

open BpppTranscript NormLinear

/-! ## The challenges `verify` derives -/

section Logs

variable (t : BpppTranscript F E) (vcs : List (PedersenCommitment E)) (proof : CircuitProof F E)

/-- The entries `verify` absorbs before `α`. -/
def preAlpha : List (Entry F E) :=
  [.message "dom-sep" ("bppp_circuit".toList.map Char.toNat)] ++
    vcs.map (fun c => .point "V" c.point) ++ [.point "C_L" proof.c_l, .point "C_O" proof.c_o]

/-- The log at which `verify` draws each challenge, `α`, `ρ`, `λ`, `β`, `τ`. -/
def alphaLog : List (Entry F E) := t.log ++ preAlpha vcs proof ++ [.challenge "alpha"]
def rhoLog : List (Entry F E) := alphaLog t vcs proof ++ [.point "C_R" proof.c_r, .challenge "rho"]
def lamLog : List (Entry F E) := rhoLog t vcs proof ++ [.challenge "lambda"]
def betaLog : List (Entry F E) := lamLog t vcs proof ++ [.challenge "beta"]
def tauLog : List (Entry F E) := betaLog t vcs proof ++ [.point "C_S" proof.c_s, .challenge "tau"]

/-- The transcript after `τ`, which `norm_linear::verify` continues. -/
def afterTau : BpppTranscript F E := { t with log := tauLog t vcs proof }

end Logs

/-! ## An accepting run -/

variable (gens : Generators E) (params : CircuitParams)

/-- The inputs `norm_linear::verify` gets from `circuit::verify`. -/
noncomputable def cTau (C : Constraints F) (beta : F) (τ : Fˣ) : List F :=
  (List.range H_LEN).map fun k => evalAt τ ((Circuit.c C beta).toPolys k)
noncomputable def pnTau (C : Constraints F) (τ : Fˣ) : List F :=
  (List.range params.nm).map fun k => evalAt τ ((C.p_n).toPolys k)
noncomputable def psTau (C : Constraints F) (rho : F) (τ : Fˣ) : F :=
  weighted_norm (pnTau params C τ) (rho * rho) + 2 * (C.lambda_al + C.mu_am) * ((τ : F) * τ * τ)
def extraOf (C : Constraints F) (τ : Fˣ) (vcs : List (PedersenCommitment E))
    (cS cO cL cR : E) : List (F × E) :=
  [((τ : F)⁻¹, cS), (1, cO), ((τ : F), cL), ((τ : F) * τ, cR)] ++
    vcs.zipIdx.map fun (v_i, i) => (2 * ((τ : F) * τ * τ) * C.lambdas.getD i 0, v_i.point)

/-- An accepting run of `verify` checks the shape of the inputs and is an accepting run of
`norm_linear::verify` after `τ`, on the verifier's decomposed `C(τ)`. -/
lemma verify_run (hv : params.Valid) (proof : CircuitProof F E)
    (vcs : List (PedersenCommitment E)) (t t' : BpppTranscript F E)
    (alpha rho lambda beta : F) (τ : Fˣ) (C : Constraints F)
    (hα : t.oracle (alphaLog t vcs proof) = alpha) (hρ : t.oracle (rhoLog t vcs proof) = rho)
    (hlam : t.oracle (lamLog t vcs proof) = lambda) (hβ : t.oracle (betaLog t vcs proof) = beta)
    (hτ : t.oracle (tauLog t vcs proof) = τ) (hCnew : Constraints.new params alpha (rho * rho) lambda = .ok C)
    (hC : Constraints.Correct params alpha (rho * rho) lambda C hv)
    (hrun : (verify gens params proof vcs).run t = .ok ((), t')) :
    vcs.length = params.m ∧ gens.g_vec.length = params.nm ∧
      (NormLinear.verify gens (cTau C beta τ) (psTau params C rho τ) (pnTau params C τ)
        (extraOf C τ vcs proof.c_s proof.c_o proof.c_l proof.c_r) rho proof.nl_proof).run (afterTau t vcs proof) =
        .ok ((), t') := by
  have hshape : vcs.length = params.m ∧ gens.g_vec.length = params.nm := by
    by_contra hne
    have hc : vcs.length ≠ params.m ∨ gens.g_vec.length ≠ params.nm := by tauto
    simp only [verify, if_pos hc] at hrun
    cases hrun
  refine ⟨hshape.1, hshape.2, ?_⟩
  have hver : ¬(vcs.length ≠ params.m ∨ gens.g_vec.length ≠ params.nm) := by simp [hshape]
  have e3 : (τ : F) ^ (3 : ℤ) = τ * τ * τ := by
    rw [show (3 : ℤ) = ((3 : ℕ) : ℤ) by norm_num, zpow_natCast]; ring
  obtain ⟨hcu, -⟩ := c_spec params hv alpha rho lambda beta C hC
  have hpnu := uniform_p_n params hv alpha rho lambda C hC
  simp only [alphaLog, rhoLog, lamLog, betaLog, tauLog, preAlpha, List.append_assoc,
    List.cons_append, List.nil_append] at hα hρ hlam hβ hτ
  simp only [verify, hver, if_false, StateT.run_bind, pure_bind, run_domain_sep,
    ok_bind, run_append_commits, run_append_point, run_challenge_scalar, extend_extend,
    extend_oracle, extend_log, List.append_assoc, List.cons_append, List.nil_append] at hrun
  rw [hα, hρ, hlam, hβ] at hrun
  rw [hτ, hCnew] at hrun
  simp only [run_liftM_ok, ok_bind, Laurent.eval_eq hpnu τ, Laurent.eval_eq hcu τ,
    Laurent.eval_monomial_one, C_S_POWER, C_O_POWER, C_L_POWER, C_R_POWER, V_HAT_POWER, zpow_neg_one,
    zpow_zero, zpow_one, zpow_two, e3, mul_one] at hrun
  convert hrun using 2
  · rfl
  · simp [afterTau, tauLog, betaLog, lamLog, rhoLog, alphaLog, preAlpha, extend]

/-! ## The instance of `norm_linear::verify` is `C(τ)` -/

/-- The norm-linear relation depends on an instance only through its entries up to its lengths. -/
lemma rel_congr {g : E} {x y : Spec.NormLinear.Instance F E} (hC : x.C = y.C)
    (hL : x.Lℓ = y.Lℓ) (hn : x.Ln = y.Ln) (hμ : x.μ = y.μ) (hc : ∀ k < x.Lℓ, x.c k = y.c k)
    (hH : ∀ k < x.Lℓ, x.H k = y.H k) (hG : ∀ k < x.Ln, x.G k = y.G k)
    {w : Spec.NormLinear.Witness F} (h : Spec.NormLinear.Rel g x w) : Spec.NormLinear.Rel g y w := by
  simp only [Spec.NormLinear.Rel, Spec.NormLinear.ip, Spec.NormLinear.wip,
    Spec.NormLinear.msm] at h ⊢
  have e1 : ∑ k ∈ range x.Lℓ, x.c k * w.ℓ k = ∑ k ∈ range x.Lℓ, y.c k * w.ℓ k :=
    sum_congr rfl fun k hk => by rw [hc k (mem_range.1 hk)]
  have e2 : ∑ k ∈ range x.Lℓ, w.ℓ k • x.H k = ∑ k ∈ range x.Lℓ, w.ℓ k • y.H k :=
    sum_congr rfl fun k hk => by rw [hH k (mem_range.1 hk)]
  have e3 : ∑ k ∈ range x.Ln, w.n k • x.G k = ∑ k ∈ range x.Ln, w.n k • y.G k :=
    sum_congr rfl fun k hk => by rw [hG k (mem_range.1 hk)]
  rw [← hC, h, e1, e2, e3, hL, hn, hμ]

lemma relation_congr {g : E} {x y : Spec.NormLinear.Instance F E} (hL : x.Lℓ = y.Lℓ)
    (hn : x.Ln = y.Ln) (hH : ∀ k < x.Lℓ, x.H k = y.H k) (hG : ∀ k < x.Ln, x.G k = y.G k)
    (h : Spec.NormLinear.Relation g x) : Spec.NormLinear.Relation g y := by
  obtain ⟨s, hh, n, hne, he⟩ := h
  refine ⟨s, hh, n, by rwa [← hL, ← hn], ?_⟩
  simp only [Spec.NormLinear.pt, Spec.NormLinear.msm] at he ⊢
  have e2 : ∑ k ∈ range x.Lℓ, hh k • x.H k = ∑ k ∈ range x.Lℓ, hh k • y.H k :=
    sum_congr rfl fun k hk => by rw [hH k (mem_range.1 hk)]
  have e3 : ∑ k ∈ range x.Ln, n k • x.G k = ∑ k ∈ range x.Ln, n k • y.G k :=
    sum_congr rfl fun k hk => by rw [hG k (mem_range.1 hk)]
  rw [← he, e2, e3, hL, hn]

/-- The commitment `norm_linear::verify` checks is `C(τ)` (25) of the proof's messages. -/
lemma combined_eq (hv : params.Valid) (hg : gens.g_vec.length = params.nm)
    (alpha rho lambda beta : F) (τ : Fˣ) (C : Constraints F)
    (hC : Constraints.Correct params alpha (rho * rho) lambda C hv)
    (vcs : List (PedersenCommitment E)) (hvcs : vcs.length = params.m) (cS cO cL cR : E) :
    psTau params C rho τ • gens.g + (List.zipWith (· • ·) (pnTau params C τ)
      gens.g_vec).sum + ((extraOf C τ vcs cS cO cL cR).map fun (s, p) => s • p).sum =
    Spec.combined (params.toSpec hv) gens.g (fun k => gens.g_vec.getD k 0)
      (specCh alpha rho lambda beta) τ cS cO cL cR
      (Spec.vHat (params.toSpec hv) (specCh alpha rho lambda beta)
        fun i => (vcs.getD i ⟨0⟩).point) := by
  have hiw : ∀ i < params.m, C.lambdas.getD i 0 = lambda ^ i :=
    getD_lambdas params hv alpha rho lambda C hC
  have hextra : ((extraOf C τ vcs cS cO cL cR).map fun (s, p) => s • p).sum =
      (τ : F)⁻¹ • cS + (1 : F) • cO + (τ : F) • cL + ((τ : F) * τ) • cR +
        ∑ i ∈ range params.m, (2 * ((τ : F) * τ * τ) * lambda ^ i) • (vcs.getD i ⟨0⟩).point := by
    simp only [extraOf, List.map_append, List.sum_append, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil, add_zero]
    have hz := sum_zipIdx_map vcs ⟨0⟩
      (fun i => 2 * ((τ : F) * τ * τ) * C.lambdas.getD i 0) (fun v => v.point)
    simp only at hz
    rw [hz, hvcs, sum_congr rfl fun i hi => by rw [hiw i (mem_range.1 hi)]]
    abel
  rw [← combined_assembly, hextra, psTau, pnTau, ps_eq params hv alpha rho lambda beta C hC τ,
    pn_msm_eq params hv gens hg alpha rho lambda beta C hC τ]
  rfl

/-! ## One leaf -/

/-- What a run at a leaf must be: an accepting run of `verify` whose proof has the given
messages, whose transcript derives the given challenges, and whose norm-linear part is the path
`p` of the leaf's tree of rounds. -/
def LeafRun (vcs : List (PedersenCommitment E)) (cS cO cL cR : E) (alpha rho lambda beta : F)
    (τ : Fˣ) (p : List (E × E) × List F × Spec.NormLinear.Witness F) : Prop :=
  ∃ (proof : CircuitProof F E) (t t' : BpppTranscript F E),
    proof.c_s = cS ∧ proof.c_o = cO ∧ proof.c_l = cL ∧ proof.c_r = cR ∧
    t.oracle (alphaLog t vcs proof) = alpha ∧ t.oracle (rhoLog t vcs proof) = rho ∧
    t.oracle (lamLog t vcs proof) = lambda ∧ t.oracle (betaLog t vcs proof) = beta ∧
    t.oracle (tauLog t vcs proof) = τ ∧
    p.1 = proof.nl_proof.rounds ∧
    p.2.1 = NormLinear.gammasOf ((afterTau t vcs proof).extend
      [.message "dom-sep" ("norm_linear".toList.map Char.toNat)]) proof.nl_proof.rounds ∧
    p.2.2 = ⟨fun k => [proof.nl_proof.l_final].getD k 0, fun k => proof.nl_proof.n_final.getD k 0⟩ ∧
    (verify gens params proof vcs).run t = .ok ((), t')

/-- A tree of accepting runs at one `τ`, forked at the norm-linear challenges, opens `C(τ)` to a
norm-linear witness, or the generators satisfy a nontrivial relation. -/
lemma leaf_extract (hv : params.Valid) (hh : gens.h_vec.length = H_LEN)
    (hg : gens.g_vec.length = params.nm) (vcs : List (PedersenCommitment E))
    (hvcs : vcs.length = params.m) (cS cO cL cR : E) (alpha rho lambda beta : F) (τ : Fˣ)
    (halpha : ∀ j : ℕ, j < 16 → alpha + j ≠ 0) (hρ : rho ≠ 0)
    (tree : Spec.NormLinear.Tree F E) (d : ℕ) (hd : tree.Depth d) (hdist : tree.Distinct)
    (hL : 2 ^ d ∣ gens.g_vec.length)
    (hruns : ∀ p ∈ tree.paths,
      LeafRun gens params vcs cS cO cL cR alpha rho lambda beta τ p) :
    (∃ w, Spec.NormLinear.Rel gens.g (Spec.tauInst (params.toSpec hv)
      (specCh alpha rho lambda beta) gens.g (fun k => gens.h_vec.getD k 0)
      (fun k => gens.g_vec.getD k 0) cS cO cL cR
      (Spec.vHat (params.toSpec hv) (specCh alpha rho lambda beta)
        fun i => (vcs.getD i ⟨0⟩).point) rho τ) w) ∨
    Spec.Relation F (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0)
      (fun k => gens.g_vec.getD k 0) := by
  obtain ⟨C, hCnew, hC⟩ := Constraints.new_correct params alpha (rho * rho) lambda hv
    (mul_ne_zero hρ hρ) halpha
  have hext := NormLinear.verify_extract gens (cTau C beta τ) (psTau params C rho τ)
    (pnTau params C τ) (extraOf C τ vcs cS cO cL cR) rho tree d hd hdist hL
    (by rw [hh]; decide) hρ fun p hp => by
      obtain ⟨proof, t, t', e1, e2, e3, e4, ha, hr, hl, hb, ht, h1, h2, h3, hrun⟩ :=
        hruns p hp
      obtain ⟨-, -, hnl⟩ := verify_run gens params hv proof vcs t t' alpha rho lambda beta
        τ C ha hr hl hb ht hCnew hC hrun
      rw [e1, e2, e3, e4] at hnl
      exact ⟨proof.nl_proof, afterTau t vcs proof, t', h1, h2, h3, hnl⟩
  obtain ⟨-, hcp⟩ := c_spec params hv alpha rho lambda beta C hC
  have hLℓ : (cTau C beta τ).length = 8 := by simp [cTau, H_LEN]
  have hLn : (contract' (Weights.new : Weights F).w gens.g_vec).length = params.nm := by
    simp [LazyBases.new_w, contract'_one, hg]
  rcases hext with ⟨w, hw⟩ | hrel
  · left
    refine ⟨w, rel_congr (h := hw) ?_ ?_ ?_ ?_ ?_ ?_ ?_⟩
    · exact combined_eq gens params hv hg alpha rho lambda beta τ C hC vcs hvcs cS cO cL cR
    · exact hLℓ
    · exact hLn
    · rfl
    · intro k hk
      have hk : k < H_LEN := by simpa [NormLinear.vInst, hLℓ, H_LEN] using hk
      exact (getD_map_range _ hk).trans (by rw [hcp k hk]; rfl)
    · intro k _; simp [NormLinear.vInst, Spec.tauInst, LazyBases.new_w, contract'_one]
    · intro k _; simp [NormLinear.vInst, Spec.tauInst, LazyBases.new_w, contract'_one]
  · right
    refine Spec.relation_of_tau (params.toSpec hv) gens.g _ _ (ch := specCh alpha rho lambda beta)
      (cS := cS) (cO := cO) (cL := cL) (cR := cR) (rho := rho) (τ := τ)
      (V := Spec.vHat (params.toSpec hv) (specCh alpha rho lambda beta)
        fun i => (vcs.getD i ⟨0⟩).point) (relation_congr (h := hrel) hLℓ hLn ?_ ?_)
    · intro k _; simp [NormLinear.vInst, Spec.tauInst, LazyBases.new_w, contract'_one]
    · intro k _; simp [NormLinear.vInst, Spec.tauInst, LazyBases.new_w, contract'_one]

/-! ## Special soundness -/

/-- **Special soundness of `circuit::verify`.** Take a tree of accepting runs of `verify` on
inputs `vcs`. It forks `α` (`N_d + 16` values), `ρ` (`nm + 1` values with distinct squares), `β`
(2), `λ` (`M(nm+8)+1`) and `τ` (13), then the norm-linear challenges at every `τ` (4 per round).
Every fork has distinct values in the good set, and each run's transcript derives the challenges
of its path. `C_O`, `C_L` are fixed, `C_R` depends on `α` and `C_S` on the path down to `λ`.
Then every input is `v_i g + s_i H_0` with `v_i < 16^D`, or the generators satisfy a nontrivial
linear relation. It assumes `2 ≠ 0`, that no `m = 1, ..., N_d` is zero in the field, and a
nonempty batch. -/
lemma verify_extract (hv : params.Valid) (hh : gens.h_vec.length = H_LEN)
    (hg : gens.g_vec.length = params.nm) (h2 : (2 : F) ≠ 0)
    (hchar : ∀ m : ℕ, 0 < m → m ≤ (params.toSpec hv).Nd → (m : F) ≠ 0) (hM : 0 < params.m)
    (vcs : List (PedersenCommitment E)) (hvcs : vcs.length = params.m) (cO cL : E)
    (cR : Fin ((params.toSpec hv).Nd + 16) → E)
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
      LeafRun gens params vcs (cS a r b l) cO cL (cR a) (α a) (rho a r) (lam a r b l) (β a r b)
        (Units.mk0 (τ a r b l t) (hτ0 a r b l t)) p) :
    (∃ (v : ℕ → ℕ) (s : ℕ → F), ∀ i < params.m, v i < 16 ^ params.d ∧
      (vcs.getD i ⟨0⟩).point = (v i : F) • gens.g + s i • gens.h_vec.getD 0 0) ∨
    Spec.Relation F (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0)
      (fun k => gens.g_vec.getD k 0) := by
  by_cases hrel : Spec.Relation F (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0)
    (fun k => gens.g_vec.getD k 0)
  · exact Or.inr hrel
  have leaf := fun a r b l t => (leaf_extract gens params hv hh hg vcs hvcs (cS a r b l) cO cL
    (cR a) (α a) (rho a r) (lam a r b l) (β a r b) (Units.mk0 (τ a r b l t) (hτ0 a r b l t))
    (hpole a) (hρ0 a r) (trees a r b l t) d (hd a r b l t) (hdist a r b l t)
    (by rw [hg]; exact hL) (hruns a r b l t)).resolve_right hrel
  choose w hw using leaf
  exact Spec.circuit_extract (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0)
    (fun k => gens.g_vec.getD k 0) h2 hchar hM (fun i => (vcs.getD i ⟨0⟩).point) cO cL cR cS α
    (fun a r => rho a r * rho a r) (fun _ _ => 1) rho β lam
    (fun a r b l t => Units.mk0 (τ a r b l t) (hτ0 a r b l t)) hα hμ hβ hlam
    (fun a r b l x y e => hτ a r b l (congrArg Units.val e)) hpole
    (fun a r => mul_ne_zero (hρ0 a r) (hρ0 a r)) (fun _ _ => one_ne_zero) w hw

end Circuit

end Bppp
