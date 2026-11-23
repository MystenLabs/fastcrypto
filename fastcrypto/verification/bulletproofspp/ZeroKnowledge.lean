-- THIS FILE IS AI-ONLY
import bulletproofspp.Correctness
import bulletproofspp.Proofs.ZeroKnowledge
import bulletproofspp.Spec.ZeroKnowledge
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.EvalDist.Sum
import VCVio.EvalDist.ProbabilityBounds

/-!
# Zero-knowledge of `range_proof.rs`

Against an honest verifier, `RangeProof::prove_batch` under uniform randomness has the
distribution of a simulator that sees only the commitments, `range`, `dst`, the generators and the
challenges. It is stated with VCVio's `ChallengeVerifyProtocol.HVZK`: the honest verifier draws
every challenge uniformly, and the real and simulated transcripts are within total variation
distance `22 / |F|`, the probability that a challenge hits one of the inversions or condition (32).
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

set_option linter.unusedSectionVars false

namespace RangeProof

open BpppTranscript Circuit

/-- `prove_batch`'s result from the result of `circuit::prove`. -/
def batchOf (r : Except Error ((CircuitProof F E × List (PedersenCommitment E)) ×
    BpppTranscript F E)) : Result (RangeProof F E) :=
  match r with
  | .ok ((proof, _), _) => .ok ⟨proof⟩
  | .error _ => .error .GeneralOpaqueError

/-- **The simulator** of `prove_batch`: `Spec.simView` on the commitments, then `finish`. -/
noncomputable def simBatch (o' : List String → F) (gens : Generators E) (params : CircuitParams)
    (hv : params.Valid) (commitments : List (PedersenCommitment E)) (range : Range)
    (dst : List ℕ) (alpha rho lambda beta delta : F) (τ : Fˣ)
    (y : ((Fin params.nm → F) × F) × (Fin 10 → F)) : Result (RangeProof F E) :=
  batchOf (finish gens (params.toSpec hv) (specCh alpha rho lambda beta delta) rho τ
    (transcript (fun l => o' (chalLabels l)) dst range.bits commitments.length) commitments
    (Spec.simView (params.toSpec hv) (specCh alpha rho lambda beta delta) τ gens.g
      (fun k => gens.h_vec.getD k 0) (fun k => gens.g_vec.getD k 0)
      (fun i => (commitments.getD i ⟨0⟩).point) y))

/-- `prove_batch` for fixed challenges. Take a transcript hash whose challenges
depend only on which challenges came before (an honest verifier's), with challenges `α` not in
`{0, -1, ..., -15}` and `ρ, β, δ, τ ≠ 0`. Take values in `range`, generators of the right shape
with `g = pedersen::H` and `h_vec[0] = pedersen::G`, all in the span of `g`, with
`h_vec[j] = h_j g`, `h_0 ≠ 0` and `β² ≠ h_0 (h_1 + λ^{g_1})`. Then `prove_batch`, with its masks
and blindings uniform, has the distribution of `simBatch`, which sees only the commitments, `range`,
`dst`, the generators and the challenges. -/
lemma zero_knowledge_at [Fintype F] [SampleableType F] (o' : List String → F)
    (generators : ℕ → Result (Generators E)) (G H : E) (values : List ℕ)
    (blindings : List F) (range : Range) (dst : List ℕ) (gens : Generators E)
    (params : CircuitParams) (hgens : generators params.nm = .ok gens)
    (hparams : CircuitParams.new range values.length = .ok params) (hv : params.Valid)
    (hh : gens.h_vec.length = H_LEN) (hg : gens.g_vec.length = params.nm) (hgH : gens.g = H)
    (hhG : gens.h_vec.getD 0 0 = G) (hvals : values ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values, range.is_in_range v) (h gg : ℕ → F)
    (hH : ∀ j, gens.h_vec.getD j 0 = h j • gens.g) (hG : ∀ k, gens.g_vec.getD k 0 = gg k • gens.g)
    (alpha rho lambda beta delta : F) (τ : Fˣ)
    (hα : o' ["alpha"] = alpha) (hρ : o' ["alpha", "rho"] = rho)
    (hlam : o' ["alpha", "rho", "lambda"] = lambda)
    (hβ : o' ["alpha", "rho", "lambda", "beta"] = beta)
    (hδ : o' ["alpha", "rho", "lambda", "beta", "delta"] = delta)
    (hτ : o' ["alpha", "rho", "lambda", "beta", "delta", "tau"] = τ)
    (halpha : ∀ j : ℕ, j < 16 → alpha + j ≠ 0) (hrho0 : rho ≠ 0) (hbeta0 : beta ≠ 0)
    (hdelta0 : delta ≠ 0) (hh0 : h 0 ≠ 0)
    (hD : beta ^ 2 - h 0 * (h 1 + lambda ^ (params.toSpec hv).g 1) ≠ 0) :
    (fun x => prove_batch (fun l => o' (chalLabels l)) generators G H values blindings range dst
        (rngOf params hv x)) <$> ($ᵗ (Spec.Masks F (params.toSpec hv) × (Fin 15 → F))) =ᵈ
      simBatch o' gens params hv (commitments G H values blindings) range dst alpha rho lambda
        beta delta τ <$> ($ᵗ (((Fin params.nm → F) × F) × (Fin 10 → F))) := by
  have hm : values.length ≠ 0 := by simpa using hvals
  obtain ⟨params', hpn, -, hpr, hpm, h16⟩ := params_new range values.length hm
  obtain rfl : params = params' := by rw [hparams] at hpn; exact Except.ok.inj hpn
  have hd : ∀ v ∈ values, v < 16 ^ params.d := fun v hv' => by
    have := hrange v hv'
    simp only [Range.is_in_range, decide_eq_true_eq] at this
    rw [h16]; have := Nat.one_le_two_pow (n := range.bits); omega
  set P := params.toSpec hv
  set ch := specCh alpha rho lambda beta delta
  set t := transcript (fun l => o' (chalLabels l)) dst range.bits values.length (F := F) (E := E)
  set Hf : ℕ → E := fun k => gens.h_vec.getD k 0
  set Gf : ℕ → E := fun k => gens.g_vec.getD k 0
  set d : ℕ → ℕ → ℕ := fun i t => values.getD i 0 / 16 ^ t % 16
  set sb : ℕ → F := fun i => blindings.getD i 0
  have hvcs : commitments (F := F) G H (blindings := blindings) values =
      (List.zip (to_scalars values : List F) blindings).map fun (v, s) =>
        PedersenCommitment.new G H v s := rfl
  have ht : chalLabels t.log = [] := by simp [t, transcript, BpppTranscript.new]
  -- Each run of `prove_batch` is `finish` of the honest view.
  have hrun : ∀ x, prove_batch (fun l => o' (chalLabels l)) generators G H values blindings range
      dst (rngOf params hv x) = batchOf (finish gens P ch rho τ t (commitments G H values blindings)
        (Spec.realView P ch d sb τ gens.g Hf Gf x)) := fun x => by
    have hc : ¬(values = [] ∨ values.length ≠ blindings.length ∨
        values.any (fun v => !range.is_in_range v)) := by
      simp [hvals, hb]; intro v hv'; simpa using hrange v hv'
    have hp := prove_view params hv (rngOf params hv x) values blindings G H gens t o'
      (fun _ => rfl) ht hh hg hpm.symm (by rw [hb, hpm]) (by rw [hpr]; exact hrange) hd
      alpha rho lambda beta delta τ hα hρ hlam hβ hδ hτ halpha hrho0 hbeta0 hdelta0
    rw [specHonest_rngOf params hv values blindings x] at hp
    simp only [prove_batch, hc, if_false, setup, hparams, hgens, bind, Except.bind, pure, Except.pure, StateT.run']
    have hp' : (Circuit.prove G H gens params (rngOf params hv x) values blindings).run t =
        finish gens P ch rho τ t (commitments G H values blindings)
          (Spec.realView P ch d sb τ gens.g Hf Gf x) := hp
    rw [show (Circuit.prove G H gens params (rngOf params hv x) values blindings) t =
      (Circuit.prove G H gens params (rngOf params hv x) values blindings).run t from rfl, hp']
    generalize finish gens P ch rho τ t (commitments G H values blindings) (Spec.realView P ch d sb τ gens.g Hf Gf x) = r
    rcases r with e | ⟨⟨proof, _⟩, _⟩ <;> rfl
  -- The inputs, as the simulator sees them.
  have hV : ∀ y, Spec.simView P ch τ gens.g Hf Gf
      (Spec.Honest.inputs (P := P) gens.g Hf (Spec.zkHonest P d sb 0 0)) y =
      Spec.simView P ch τ gens.g Hf Gf (fun i => ((commitments G H values blindings).getD i ⟨0⟩).point) y := fun y => by
    have hvh : Spec.vHat P ch (Spec.Honest.inputs (P := P) gens.g Hf (Spec.zkHonest P d sb 0 0)) =
        Spec.vHat P ch (fun i => ((commitments G H values blindings).getD i ⟨0⟩).point) := by
      simp only [Spec.vHat]
      congr 1
      refine sum_congr rfl fun i hi => ?_
      have hi : i < values.length := by rw [← hpm]; simpa [P] using hi
      have hvl : (commitments (F := F) G H values blindings).length = values.length := by
        simp [hvcs, length_to_scalars, hb]
      rw [← getElem_eq_getD' _ (by rw [hvl]; exact hi)]
      simp only [hvcs, List.getElem_map, List.getElem_zip]
      simp only [PedersenCommitment.new, Spec.Honest.inputs, Spec.zkHonest, hgH]
      rw [show Hf 0 = G from hhG, getElem_eq_getD' _ _ 0, getD_to_scalars,
        value_eq params hv (rngOf params hv 0) values blindings hd i hi,
        getElem_eq_getD' _ _ 0]
      rfl
    simp only [Spec.simView, hvh]
  have hzk := Spec.zero_knowledge P ch d sb τ h gg gens.g Hf Gf hH hG halpha
    (mul_ne_zero hrho0 hrho0) hbeta0 hdelta0 hh0 hD
    (fun i _ t _ => Nat.mod_lt _ (by norm_num))
  rw [show (fun x => prove_batch (fun l => o' (chalLabels l)) generators G H values blindings
      range dst (rngOf params hv x)) = (fun v => batchOf (finish gens P ch rho τ t (commitments G H values blindings) v)) ∘
      Spec.realView P ch d sb τ gens.g Hf Gf from funext hrun, LawfulFunctor.comp_map]
  refine (hzk.map _).trans ?_
  rw [Functor.map_map]
  have key : ∀ {α β : Type} (f g : α → β) (x : ProbComp α), f = g → f <$> x =ᵈ g <$> x := by
    rintro _ _ f g x rfl; rfl
  refine key _ _ _ (funext fun y => ?_)
  have hvl : (commitments (F := F) G H values blindings).length = values.length := by
    simp [hvcs, length_to_scalars, hb]
  simp only [Function.comp, simBatch, hV, hvl]
  rfl

/-! ## As a VCVio protocol -/

open OracleComp ChallengeVerifyProtocol

/-- The challenges `(α, ρ, λ, β, δ, τ, γ_1, ..., γ_r)` of a run, drawn up front by the honest
verifier: they do not depend on the prover's messages. -/
abbrev Chal (F : Type) (r : ℕ) := F × F × F × F × F × F × (Fin r → F)

/-- The number of norm-linear rounds for `params`. -/
def rounds (params : CircuitParams) : ℕ := (NormLinear.proof_shape H_LEN params.nm).1

/-- The transcript hash of the honest verifier with challenges `c`: the `k`-th challenge drawn is
the `k`-th entry of `c`, whatever was absorbed. -/
def chalOracle {r : ℕ} (c : Chal F r) (labels : List String) : F :=
  match labels.length with
  | 1 => c.1
  | 2 => c.2.1
  | 3 => c.2.2.1
  | 4 => c.2.2.2.1
  | 5 => c.2.2.2.2.1
  | 6 => c.2.2.2.2.2.1
  | n + 7 => if h : n < r then c.2.2.2.2.2.2 ⟨n, h⟩ else 0
  | _ => 0

/-- `τ` as a unit, `1` if it is zero. -/
noncomputable def unitOr (x : F) : Fˣ := if h : x = 0 then 1 else Units.mk0 x h

variable [Fintype F] [SampleableType F]

/-- `range_proof` as a VCVio protocol for batches of `m` values: the statement is the
commitments, the witness the values and blindings, there is no first message, the challenges are
`Chal`, and the response is the output of `prove_batch` under uniform masks and blindings. -/
noncomputable def protocol (generators : ℕ → Result (Generators E)) (G H : E)
    (range : Range) (dst : List ℕ) (params : CircuitParams) (hv : params.Valid) (m : ℕ) :
    ChallengeVerifyProtocol (List (PedersenCommitment E)) (List ℕ × List F) Unit Unit
      (Chal F (rounds params)) (Result (RangeProof F E))
      (fun V w => by classical exact decide (w.1.length = m ∧ w.2.length = m ∧
        (∀ v ∈ w.1, range.is_in_range v) ∧ V = commitments G H w.1 w.2)) where
  commit _ _ := pure ((), ())
  respond _ w _ c :=
    (fun x => prove_batch (fun l => chalOracle c (chalLabels l)) generators G H w.1 w.2 range dst
      (rngOf params hv x)) <$> ($ᵗ (Spec.Masks F (params.toSpec hv) × (Fin 15 → F)))
  verify V _ c resp :=
    match resp with
    | .ok rp =>
      match rp.verify_batch (fun l => chalOracle c (chalLabels l)) generators V range dst with
      | .ok () => true
      | .error _ => false
    | .error _ => false

/-- The simulated transcript: uniform challenges, then `simBatch`. -/
noncomputable def simTranscript (gens : Generators E) (range : Range) (dst : List ℕ)
    (params : CircuitParams) (hv : params.Valid) (V : List (PedersenCommitment E)) :
    ProbComp (Unit × Chal F (rounds params) × Result (RangeProof F E)) := do
  let c ← $ᵗ (Chal F (rounds params))
  let y ← $ᵗ (((Fin params.nm → F) × F) × (Fin 10 → F))
  return ((), c, simBatch (chalOracle c) gens params hv V range dst c.1 c.2.1 c.2.2.1 c.2.2.2.1
    c.2.2.2.2.1 (unitOr c.2.2.2.2.2.1) y)

/-- The challenges for which the simulation can differ: an inversion of `prove_batch` fails, or
condition (32) of the paper fails. -/
def Bad (h : ℕ → F) (g1 : ℕ) {r : ℕ} (c : Chal F r) : Prop :=
  (∃ j : Fin 16, c.1 + (j : ℕ) = 0) ∨ c.2.1 = 0 ∨
    (c.2.2.2.1 = 0 ∨ c.2.2.2.1 ^ 2 = h 0 * (h 1 + c.2.2.1 ^ g1)) ∨
    c.2.2.2.2.1 = 0 ∨ c.2.2.2.2.2.1 = 0

omit [DecidableEq F] in
lemma pr_eq_le (a : F) :
    Pr{let x ← $ᵗ F}[x = a] ≤ 1 / Fintype.card F := by
  classical
  rw [SampleableType.prEvent_uniformSample]
  gcongr
  rw [Finset.filter_eq' univ a]; simp

omit [DecidableEq F] in
lemma pr_sq_le (k : F) :
    Pr{let x ← $ᵗ F}[x = 0 ∨ x ^ 2 = k] ≤ 3 / Fintype.card F := by
  classical
  rw [SampleableType.prEvent_uniformSample]
  gcongr
  have hp : (Polynomial.X ^ 2 - Polynomial.C k : Polynomial F) ≠ 0 :=
    Polynomial.X_pow_sub_C_ne_zero (by norm_num) k
  have hsub : (univ.filter fun x : F => x = 0 ∨ x ^ 2 = k) ⊆
      insert 0 (Polynomial.X ^ 2 - Polynomial.C k).roots.toFinset := by
    intro x hx
    simp only [mem_filter, mem_univ, true_and] at hx
    rcases hx with rfl | hx
    · exact mem_insert_self _ _
    · refine mem_insert_of_mem (Multiset.mem_toFinset.2 ((Polynomial.mem_roots hp).2 ?_))
      simp [hx]
  have hdeg : (Polynomial.X ^ 2 - Polynomial.C k : Polynomial F).roots.toFinset.card ≤ 2 :=
    (Multiset.toFinset_card_le _).trans ((Polynomial.card_roots' _).trans
      (Polynomial.natDegree_X_pow_sub_C (n := 2) (a := k)).le)
  exact_mod_cast (card_le_card hsub).trans ((card_insert_le _ _).trans (by omega))

omit [DecidableEq F] in
lemma pr_fst_le {A B : Type} [SampleableType A] [SampleableType B] (p : A → Prop)
    {ε : ENNReal} (h : Pr{let a ← $ᵗ A}[p a] ≤ ε) :
    Pr{let z ← $ᵗ (A × B)}[p z.1] ≤ ε :=
  SampleableType.prEvent_uniformSample_prod_le_of_forall_snd (fun z => p z.1) fun _ => h

omit [DecidableEq F] in
lemma pr_snd_le {A B : Type} [SampleableType A] [SampleableType B] (p : B → Prop)
    {ε : ENNReal} (h : Pr{let b ← $ᵗ B}[p b] ≤ ε) :
    Pr{let z ← $ᵗ (A × B)}[p z.2] ≤ ε :=
  SampleableType.prEvent_uniformSample_prod_le_of_forall_fst (fun z => p z.2) fun _ => h

omit [DecidableEq F] in
/-- **The bad challenges are rare**: at most `22 / |F|`. -/
lemma pr_bad_le (h : ℕ → F) (g1 r : ℕ) :
    Pr{let c ← $ᵗ (Chal F r)}[Bad h g1 c] ≤ 22 / Fintype.card F := by
  set q : ENNReal := (Fintype.card F : ENNReal)
  -- `α + j = 0` for one of 16 values of `j`.
  have hA : Pr{let c ← $ᵗ (Chal F r)}[∃ j : Fin 16, c.1 + (j : ℕ) = 0] ≤ 16 / q := by
    refine pr_fst_le (fun a : F => ∃ j : Fin 16, a + (j : ℕ) = 0) ?_
    refine (prEvent_exists_le_card_mul _ (fun (j : Fin 16) (a : F) => a + (j : ℕ) = 0)
      (ε := 1 / q) fun j => ?_).trans_eq ?_
    · have : (fun a : F => a + (j : ℕ) = 0) = fun a => a = -((j : ℕ) : F) := by
        funext a; exact propext add_eq_zero_iff_eq_neg
      rw [this]; exact pr_eq_le (-((j : ℕ) : F))
    · simp [q, div_eq_mul_inv]
  -- `ρ = 0`.
  have hB : Pr{let c ← $ᵗ (Chal F r)}[c.2.1 = 0] ≤ 1 / q :=
    pr_snd_le (fun b : F × F × F × F × F × (Fin r → F) => b.1 = 0)
      (pr_fst_le (fun a : F => a = 0) (pr_eq_le 0))
  -- `β = 0` or condition (32) fails, for each `λ`.
  have hC : Pr{let c ← $ᵗ (Chal F r)}[c.2.2.2.1 = 0 ∨
      c.2.2.2.1 ^ 2 = h 0 * (h 1 + c.2.2.1 ^ g1)] ≤ 3 / q :=
    pr_snd_le (fun b : F × F × F × F × F × (Fin r → F) =>
        b.2.2.1 = 0 ∨ b.2.2.1 ^ 2 = h 0 * (h 1 + b.2.1 ^ g1))
      (pr_snd_le (fun b : F × F × F × F × (Fin r → F) =>
          b.2.1 = 0 ∨ b.2.1 ^ 2 = h 0 * (h 1 + b.1 ^ g1))
        (SampleableType.prEvent_uniformSample_prod_le_of_forall_fst
          (fun b : F × F × F × F × (Fin r → F) =>
            b.2.1 = 0 ∨ b.2.1 ^ 2 = h 0 * (h 1 + b.1 ^ g1))
          fun l => pr_fst_le (fun a : F => a = 0 ∨ a ^ 2 = h 0 * (h 1 + l ^ g1))
            (pr_sq_le _)))
  -- `δ = 0`.
  have hD : Pr{let c ← $ᵗ (Chal F r)}[c.2.2.2.2.1 = 0] ≤ 1 / q :=
    pr_snd_le (fun b : F × F × F × F × F × (Fin r → F) => b.2.2.2.1 = 0)
      (pr_snd_le (fun b : F × F × F × F × (Fin r → F) => b.2.2.1 = 0)
        (pr_snd_le (fun b : F × F × F × (Fin r → F) => b.2.1 = 0)
          (pr_snd_le (fun b : F × F × (Fin r → F) => b.1 = 0)
            (pr_fst_le (fun a : F => a = 0) (pr_eq_le 0)))))
  -- `τ = 0`.
  have hE : Pr{let c ← $ᵗ (Chal F r)}[c.2.2.2.2.2.1 = 0] ≤ 1 / q :=
    pr_snd_le (fun b : F × F × F × F × F × (Fin r → F) => b.2.2.2.2.1 = 0)
      (pr_snd_le (fun b : F × F × F × F × (Fin r → F) => b.2.2.2.1 = 0)
        (pr_snd_le (fun b : F × F × F × (Fin r → F) => b.2.2.1 = 0)
          (pr_snd_le (fun b : F × F × (Fin r → F) => b.2.1 = 0)
            (pr_snd_le (fun b : F × (Fin r → F) => b.1 = 0)
              (pr_fst_le (fun a : F => a = 0) (pr_eq_le 0))))))
  calc Pr{let c ← $ᵗ (Chal F r)}[Bad h g1 c]
      ≤ 16 / q + (1 / q + (3 / q + (1 / q + 1 / q))) := by
        refine (prEvent_or_le _ _ _).trans (add_le_add hA ?_)
        refine (prEvent_or_le _ _ _).trans (add_le_add hB ?_)
        refine (prEvent_or_le _ _ _).trans (add_le_add hC ?_)
        exact (prEvent_or_le _ _ _).trans (add_le_add hD hE)
    _ = 22 / q := by
        simp only [← ENNReal.add_div]; norm_num

/-- **Honest-verifier zero-knowledge of `range_proof`** (Theorem 1 of the paper), as VCVio's
`ChallengeVerifyProtocol.HVZK`. For batches of `m ≥ 1` values, with generators of the right shape
(`g = pedersen::H`, `h_vec[0] = pedersen::G`) in the span of `g` with `h_vec[j] = h_j g` and
`h_0 ≠ 0`, the transcripts of `prove_batch` against an honest verifier, whose challenges are
uniform, are within total variation distance `22 / |F|` of `simTranscript`, which sees only the
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
      (simTranscript gens range dst params hv) (22 / Fintype.card F) := by
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
  obtain ⟨hα, hρ, ⟨hβ0, hD⟩, hδ, hτ⟩ := hc
  have key := zero_knowledge_at (chalOracle c) generators G H values blindings range dst gens
    params hgens hparams hv hh hg hgH hhG hvals hb hrange h gg hH hG c.1 c.2.1 c.2.2.1 c.2.2.2.1
    c.2.2.2.2.1 (unitOr c.2.2.2.2.2.1) rfl rfl rfl rfl rfl (by simp [unitOr, hτ]; rfl)
    (fun j hj => hα ⟨j, hj⟩) hρ hβ0 hδ hh0 (sub_ne_zero.2 hD)
  simpa only [bind_pure_comp, Functor.map_map] using key.map (fun π => ((), c, π))

end RangeProof

end Bppp
