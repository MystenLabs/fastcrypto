-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Circuit
import bulletproofspp.Spec.ZeroKnowledge

/-!
# Zero-knowledge of `circuit.rs`

Against an honest verifier, whose challenges depend only on which challenges came before,
`circuit::prove` outputs a fixed function `finish` of the view of `Spec.zero_knowledge`: the
commitments, and the norm-linear prover run on the opening of `C(τ)` (`prove_view`).
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

set_option linter.unusedSectionVars false

namespace BpppTranscript

/-- The labels of the challenges in a log. -/
def chalLabels : List (Entry F E) → List String :=
  List.filterMap fun e => match e with
    | .challenge l => some l
    | _ => none

end BpppTranscript

namespace Circuit

open BpppTranscript NormLinear

/-- What `prove` absorbs after the inputs' transcript. -/
def prefixLog (vcs : List (PedersenCommitment E)) (cL cO cR cS : E) : List (Entry F E) :=
  [.message "dom-sep" ("bppp_circuit".toList.map Char.toNat)] ++
    vcs.map (fun c => .point "V" c.point) ++
    [.point "C_L" cL, .point "C_O" cO, .challenge "alpha", .point "C_R" cR, .challenge "rho",
      .challenge "lambda", .challenge "beta", .point "C_S" cS,
      .challenge "tau"]

/-- The rest of `prove` from the view: the messages, and the norm-linear prover on the opening. -/
noncomputable def finish (gens : Generators E) (P : Spec.Params) (ch : Spec.Challenges F)
    (rho : F) (τ : Fˣ) (t : BpppTranscript F E) (vcs : List (PedersenCommitment E))
    (v : Spec.View F E P) :
    Except Error ((CircuitProof F E × List (PedersenCommitment E)) × BpppTranscript F E) :=
  (do
    let nl ← NormLinear.prove gens ((List.range H_LEN).map fun j => evalAt τ (Spec.c P ch j)) rho
      ⟨0, List.ofFn v.2.2.2.2.1, List.ofFn v.2.2.2.2.2⟩
    pure ((⟨v.2.1, v.1, v.2.2.1, v.2.2.2.1, nl⟩ : CircuitProof F E), vcs)).run
    (t.extend (prefixLog vcs v.2.1 v.1 v.2.2.1 v.2.2.2.1))

lemma chalLabels_append (a b : List (Entry F E)) :
    chalLabels (a ++ b) = chalLabels a ++ chalLabels b := List.filterMap_append

@[simp] lemma chalLabels_nil : chalLabels ([] : List (Entry F E)) = [] := rfl
@[simp] lemma chalLabels_challenge (l : String) (r : List (Entry F E)) :
    chalLabels (.challenge l :: r) = l :: chalLabels r := rfl
@[simp] lemma chalLabels_point (l : String) (p : E) (r : List (Entry F E)) :
    chalLabels (.point l p :: r) = chalLabels r := rfl
@[simp] lemma chalLabels_message (l : String) (m : List ℕ) (r : List (Entry F E)) :
    chalLabels (.message l m :: r) = chalLabels r := rfl

@[simp] lemma chalLabels_points (vcs : List (PedersenCommitment E)) (l : String) :
    chalLabels (vcs.map fun c => (.point l c.point : Entry F E)) = [] := by
  induction vcs with
  | nil => rfl
  | cons v vcs ih => simp [chalLabels] at ih ⊢

/-- Openings that agree on `r_{S,0..7}` give the same view. -/
lemma view_congr (P : Spec.Params) (ch : Spec.Challenges F) (g : E) (H G : ℕ → E) (τ : Fˣ)
    (h : Spec.Honest F) {r r' : ℕ → F} (hr : ∀ j ≤ 7, r j = r' j) :
    let w := h.opening P ch r
    let w' := h.opening P ch r'
    Spec.cS P g H G w = Spec.cS P g H G w' ∧
      ∀ j, evalAt τ (Spec.ℓ ch w j) = evalAt τ (Spec.ℓ ch w' j) := by
  intro w w'
  have hlin : Spec.lin w.rS w.ℓS = Spec.lin w'.rS w'.ℓS := funext fun j => by
    simp only [Spec.lin, w, w', Spec.Honest.opening]
    split_ifs with hj
    · exact hr _ (by omega)
    · rfl
  refine ⟨?_, fun j => ?_⟩
  · simp only [Spec.cS]
    rw [hlin, show w.rS 0 = w'.rS 0 from hr 0 (by norm_num)]
    rfl
  · by_cases hj : j < 7
    · simp only [Spec.ℓ, w, w', Spec.Honest.opening, if_pos hj, hr (j + 1) (by omega)]
    · simp only [Spec.ℓ, w, w', Spec.Honest.opening, if_neg hj]

variable (params : CircuitParams) (hv : params.Valid) (rng : Randomness F) (values : List ℕ)
  (blindings : List F)

set_option maxHeartbeats 1000000 in
/-- **`prove` against an honest verifier.** If the transcript's challenges depend only on the
challenges before them, `prove` outputs `finish` of the view of the honest opening. -/
lemma prove_view (Gp Hp : E) (gens : Generators E) (t : BpppTranscript F E)
    (o' : List String → F) (ho : ∀ l, t.oracle l = o' (chalLabels l)) (ht : chalLabels t.log = [])
    (hh : gens.h_vec.length = H_LEN) (hg : gens.g_vec.length = params.nm)
    (hlen : values.length = params.m) (hb : blindings.length = params.m)
    (hrange : ∀ v ∈ values, params.range.is_in_range v) (hd : ∀ v ∈ values, v < 16 ^ params.d)
    (alpha rho lambda beta : F) (τ : Fˣ)
    (hα : o' ["alpha"] = alpha) (hρ : o' ["alpha", "rho"] = rho)
    (hlam : o' ["alpha", "rho", "lambda"] = lambda) (hβ : o' ["alpha", "rho", "lambda", "beta"] = beta)
    (hτ : o' ["alpha", "rho", "lambda", "beta", "tau"] = τ)
    (halpha : ∀ j : ℕ, j < 16 → alpha + j ≠ 0) (hrho0 : rho ≠ 0) (hbeta0 : beta ≠ 0) :
    (prove Gp Hp gens params rng values blindings).run t =
      finish gens (params.toSpec hv) (specCh alpha rho lambda beta) rho τ t
        ((List.zip (to_scalars values : List F) blindings).map fun (v, s) =>
          PedersenCommitment.new Gp Hp v s)
        (let w := (specHonest rng values blindings).opening (params.toSpec hv)
          (specCh alpha rho lambda beta)
          ((specHonest rng values blindings).rS (params.toSpec hv) (specCh alpha rho lambda beta))
        (Spec.cO (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0) (fun k => gens.g_vec.getD k 0) w,
          Spec.cL (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0) (fun k => gens.g_vec.getD k 0) w,
          Spec.cR (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0) (fun k => gens.g_vec.getD k 0) w,
          Spec.cS (params.toSpec hv) gens.g (fun k => gens.h_vec.getD k 0) (fun k => gens.g_vec.getD k 0) w,
          fun j => evalAt τ (Spec.ℓ (specCh alpha rho lambda beta) w j),
          fun k => evalAt τ (Spec.n (params.toSpec hv) (specCh alpha rho lambda beta) w k))) := by
  have key : ∀ l, t.oracle (t.log ++ l) = o' (chalLabels l) := fun l => by
    rw [ho, chalLabels_append, ht, List.nil_append]
  have hprove : ¬(values.length ≠ params.m ∨ blindings.length ≠ params.m ∨
      gens.g_vec.length ≠ params.nm ∨ values.any (fun v => !params.range.is_in_range v)) := by
    simp [hlen, hb, hg]
    intro v hv; simpa using hrange v hv
  simp only [prove, hprove, if_false, prove_witness, StateT.run_bind]
  rw [input_commitments_eq]
  set vcs := (List.zip (to_scalars values : List F) blindings).map fun (v, s) =>
    PedersenCommitment.new Gp Hp v s with hvcs
  set W : Witness F := Witness.new params rng values blindings with hW
  have hrl : W.r_l.length = H_LEN := length_blinding_vector _ _
  have hro : W.r_o.length = H_LEN := length_blinding_vector _ _
  have hrr : W.r_r.length = H_LEN := length_blinding_vector _ _
  have hnl : W.n_l.length = params.nm := length_pad_to _ _
  have hno : W.n_o.length = params.nm := length_pad_to _ _
  have hns : W.n_s.length = params.nm := by simp [W, Witness.new]
  obtain ⟨c_l, hcl⟩ : ∃ c_l, gens.commit (message_opening W.r_l W.n_l) = .ok c_l :=
    ⟨_, gens_commit_eq gens _ (by rw [message_opening_l, length_h_coordinates hrl, hh]) (by rw [message_opening_n, hnl, hg])⟩
  obtain ⟨c_o, hco⟩ : ∃ c_o, gens.commit (message_opening W.r_o W.n_o) = .ok c_o :=
    ⟨_, gens_commit_eq gens _ (by rw [message_opening_l, length_h_coordinates hro, hh]) (by rw [message_opening_n, hno, hg])⟩
  simp only [StateT.run_pure, pure_bind, run_liftM_ok, ok_bind,
    run_domain_sep, run_append_commits, hcl, hco, run_append_point, run_challenge_scalar,
    extend_extend, extend_oracle, extend_log, List.append_assoc, key, chalLabels_append,
    chalLabels_points]
  simp only [chalLabels_nil, chalLabels_challenge, chalLabels_point, chalLabels_message,
    List.nil_append, List.cons_append, hα]
  obtain ⟨n_r, hnr_eq, hnr_len, hnr⟩ := reciprocals_eq params hv rng values blindings hlen alpha
    halpha 0 0 0 0
  rw [← hW] at hnr_eq
  obtain ⟨c_r, hcr⟩ : ∃ c_r, gens.commit (message_opening W.r_r n_r) = .ok c_r :=
    ⟨_, gens_commit_eq gens _ (by rw [message_opening_l, length_h_coordinates hrr, hh]) (by rw [message_opening_n, hnr_len, hg])⟩
  simp only [hnr_eq, hcr, run_liftM_ok, ok_bind, extend_oracle, extend_log, extend_extend,
    List.append_assoc, key, chalLabels_append, chalLabels_points, chalLabels_nil,
    chalLabels_challenge, chalLabels_point, chalLabels_message, List.nil_append,
    List.cons_append, hρ, hlam, hβ]
  obtain ⟨C, hCnew, hC⟩ := Constraints.new_correct params alpha (rho * rho) lambda hv
    (mul_ne_zero hrho0 hrho0) halpha
  simp only [hCnew, run_liftM_ok, ok_bind]
  have hrest := rest_eq params hv rng values blindings alpha rho lambda beta C hC n_r hlen hb hd
    hnr_len (fun k => hnr k)
  obtain ⟨g_s, h_s, hsolve, hhs_len, hhs7, hrS⟩ := solve_r_s_eq params hv rng values blindings alpha
    rho lambda beta C hC _ hbeta0 hrest
  obtain ⟨hOs, ⟨hOlu, hOl⟩, ⟨hOnu, hOn⟩⟩ := opening_without_r_s_spec params hv rng values blindings
    alpha rho lambda C hC n_r hnr_len
  have hfbar := f_eq_f3 params (w := C.norm_weights) (c_spec params hv alpha rho lambda beta C hC).1
    (l_base params hv rng values blindings alpha rho lambda beta C hC 0 n_r hb).1
    (n_spec params hv rng values blindings alpha rho lambda beta C hC 0 n_r hlen hnr_len
      (fun k => hnr k)).1 (by simp [hC.norm_weights]) hOs hOlu hOl hOnu hOn
  rw [← solve_r_s_congr C hfbar] at hsolve
  rw [← hW] at hsolve hOs hOlu hOl hOnu hOn
  obtain ⟨c_s, hcs⟩ : ∃ c_s, gens.commit ⟨g_s, h_s, W.n_s⟩ = .ok c_s :=
    ⟨_, gens_commit_eq gens _ (by rw [hhs_len, hh]) (by rw [hns, hg])⟩
  have hcommit : commit_c_s gens params C W n_r (Circuit.c C beta) beta =
      .ok (c_s, (opening_without_r_s params C W n_r).with_r_s g_s h_s) := by
    simp only [commit_c_s, show W.l_s = rng.l_s from rfl, hsolve, ok_bind, hcs]; rfl
  simp only [hcommit, run_liftM_ok, ok_bind, extend_oracle, extend_log, extend_extend,
    List.append_assoc, key, chalLabels_append, chalLabels_points, chalLabels_nil,
    chalLabels_challenge, chalLabels_point, chalLabels_message, List.nil_append,
    List.cons_append, hτ]
  obtain ⟨hcu, hcp⟩ := c_spec params hv alpha rho lambda beta C hC
  obtain ⟨hlu, hlp⟩ := l_base params hv rng values blindings alpha rho lambda beta C hC
    (rSOf g_s h_s) n_r hb
  obtain ⟨hnu, hnp⟩ := n_spec params hv rng values blindings alpha rho lambda beta C hC
    (rSOf g_s h_s) n_r hlen hnr_len (fun k => hnr k)
  rw [← hW] at hlu hlp hnu hnp
  set O := opening_without_r_s params C W n_r with hO
  have hlu' := Laurent.uniform_add hOlu (Laurent.uniform_monomial C_S_POWER hhs_len)
  obtain ⟨sig_tau, hsig⟩ := Laurent.eval_ok (O.sigma + Laurent.monomial C_S_POWER g_s) τ
  simp only [CombinedOpening.eval, CombinedOpening.with_r_s, Laurent.eval_eq hcu τ, hsig,
    Laurent.eval_eq hlu' τ, Laurent.eval_eq hOnu τ, run_liftM_ok, ok_bind, bind, Except.bind, pure,
    Except.pure]
  set w := specOpening params hv rng values blindings alpha rho lambda beta (rSOf g_s h_s)
    with hw
  set Hf : ℕ → E := fun k => gens.h_vec.getD k 0 with hHf
  set Gf : ℕ → E := fun k => gens.g_vec.getD k 0 with hGf
  have ecl : c_l = Spec.cL (params.toSpec hv) gens.g Hf Gf w := by
    have e := Except.ok.inj ((gens_commit_eq gens _ (by rw [message_opening_l, length_h_coordinates hrl, hh])
      (by rw [message_opening_n, hnl, hg])).symm.trans hcl)
    rw [message_opening_sigma, message_opening_l, message_opening_n] at e
    rw [← e, commit_spec params hv gens hh hg _ _ _ (length_h_coordinates hrl) hnl, headD_eq_getD]
    exact spec_commit_congr _ _ _ _ _ (fun s _ => getD_h_coordinates hrl s)
      (fun k _ => getD_n_l params hv rng values blindings hlen k)
  have eco : c_o = Spec.cO (params.toSpec hv) gens.g Hf Gf w := by
    have e := Except.ok.inj ((gens_commit_eq gens _ (by rw [message_opening_l, length_h_coordinates hro, hh])
      (by rw [message_opening_n, hno, hg])).symm.trans hco)
    rw [message_opening_sigma, message_opening_l, message_opening_n] at e
    rw [← e, commit_spec params hv gens hh hg _ _ _ (length_h_coordinates hro) hno, headD_eq_getD]
    exact spec_commit_congr _ _ _ _ _ (fun s _ => getD_h_coordinates hro s)
      (fun k _ => getD_n_o params hv rng values blindings hlen k)
  have ecr : c_r = Spec.cR (params.toSpec hv) gens.g Hf Gf w := by
    have e := Except.ok.inj ((gens_commit_eq gens _ (by rw [message_opening_l, length_h_coordinates hrr, hh])
      (by rw [message_opening_n, hnr_len, hg])).symm.trans hcr)
    rw [message_opening_sigma, message_opening_l, message_opening_n] at e
    rw [← e, commit_spec params hv gens hh hg _ _ _ (length_h_coordinates hrr) hnr_len,
      headD_eq_getD]
    exact spec_commit_congr _ _ _ _ _ (fun s _ => getD_h_coordinates hrr s) (fun k _ => hnr k)
  have ecs : c_s = Spec.cS (params.toSpec hv) gens.g Hf Gf w := by
    have e := Except.ok.inj ((gens_commit_eq gens ⟨g_s, h_s, W.n_s⟩ (by rw [hhs_len, hh])
      (by rw [hns, hg])).symm.trans hcs)
    rw [← e, commit_spec params hv gens hh hg _ _ _ hhs_len hns]
    refine spec_commit_congr _ _ _ _ _ (fun s hs => ?_) (fun k hk => ?_)
    · simp only [w, Spec.Honest.opening, Spec.lin, rSOf, specHonest]
      rcases (show s < 7 ∨ s = 7 by omega) with h7 | rfl
      · rw [if_pos h7, if_neg (by omega), Nat.add_sub_cancel]
      · rw [if_neg (by omega), hhs7]
    · simp only [w, Spec.Honest.opening, specHonest, W, Witness.new]
      exact getD_map_range _ (by simpa using hk)
  -- The opening at `τ`.
  obtain ⟨hcongS, hcongℓ⟩ := view_congr (params.toSpec hv) (specCh alpha rho lambda beta)
    gens.g Hf Gf τ (specHonest rng values blindings) hrS
  have hl : List.map (fun k => evalAt τ ((O.l + Laurent.monomial C_S_POWER h_s).toPolys k))
      (List.range H_LEN) =
      List.ofFn fun j : Fin 8 => evalAt τ (Spec.ℓ (specCh alpha rho lambda beta)
        ((specHonest rng values blindings).opening (params.toSpec hv)
          (specCh alpha rho lambda beta)
          ((specHonest rng values blindings).rS (params.toSpec hv)
            (specCh alpha rho lambda beta))) j) := by
    refine List.ext_getElem (by simp [H_LEN]) fun s h1 h2 => ?_
    simp only [List.getElem_map, List.getElem_range, List.getElem_ofFn]
    rw [Laurent.toPolys_add hOlu (Laurent.uniform_monomial _ hhs_len),
      Laurent.toPolys_monomial, hOl s, hlp s (by simpa using h1), ← hcongℓ s,
      show C_S_POWER = -1 from rfl]
    have key : (if s < 7 then rSOf g_s h_s (s + 1) else rng.l_s) = h_s.getD s 0 := by
      have hs : s < 8 := by simpa [H_LEN] using h1
      rcases (show s < 7 ∨ s = 7 by omega) with h7 | rfl
      · rw [if_pos h7]; simp only [rSOf, if_neg (by omega : s + 1 ≠ 0), Nat.add_sub_cancel]
      · rw [if_neg (by omega), hhs7]
    rw [key, sub_add_cancel]
  have hn : List.map (fun k => evalAt τ (O.n.toPolys k)) (List.range params.nm) =
      List.ofFn fun k : Fin (params.toSpec hv).nm => evalAt τ (Spec.n (params.toSpec hv)
        (specCh alpha rho lambda beta)
        ((specHonest rng values blindings).opening (params.toSpec hv)
          (specCh alpha rho lambda beta)
          ((specHonest rng values blindings).rS (params.toSpec hv)
            (specCh alpha rho lambda beta))) k) := by
    refine List.ext_getElem (by simp) fun k h1 h2 => ?_
    simp only [List.getElem_map, List.getElem_range, List.getElem_ofFn]
    rw [hOn k, hnp k (by simpa using h1)]
    rfl
  have hc : List.map (fun k => evalAt τ ((c C beta).toPolys k)) (List.range H_LEN) =
      (List.range H_LEN).map fun j => evalAt τ (Spec.c (params.toSpec hv)
        (specCh alpha rho lambda beta) j) :=
    List.map_congr_left fun j hj => by rw [hcp j (List.mem_range.1 hj)]
  rw [hl, hn, hc, ecl, eco, ecr, ecs, hcongS]
  rfl

/-- The draws of `Witness::new` from masks and free blindings; the zero-pattern slots and the
slots past `nm` are never read. -/
def rngOf (x : Spec.Masks F (params.toSpec hv) × (Fin 15 → F)) : Randomness F where
  r_o := Spec.blindO x.2
  r_l := Spec.blindL x.2
  r_r := Spec.blindR x.2
  n_s k := if h : k < params.nm then x.1.1 ⟨k, h⟩ else 0
  l_s := x.1.2

lemma blind_ge (b : Fin 15 → F) (j : ℕ) (hj : 8 ≤ j) :
    Spec.blindO b j = 0 ∧ Spec.blindL b j = 0 ∧ Spec.blindR b j = 0 := by
  obtain ⟨k, rfl⟩ : ∃ k, j = k + 8 := ⟨j - 8, by omega⟩
  exact ⟨rfl, rfl, rfl⟩

lemma specHonest_rngOf (x : Spec.Masks F (params.toSpec hv) × (Fin 15 → F)) :
    specHonest (rngOf params hv x) values blindings = Spec.zkHonest (params.toSpec hv)
      (fun i t => values.getD i 0 / 16 ^ t % 16) (fun i => blindings.getD i 0) x.1 x.2 := by
  have hb : ∀ (r : ℕ → F) (zeros : List ℕ), (∀ j ∈ zeros, r j = 0) → (∀ j, 8 ≤ j → r j = 0) →
      ∀ j, (masked r zeros).getD j 0 = r j := fun r zeros hz h8 j => by
    rw [getD_masked]
    split_ifs with hj
    · rfl
    · simp only [not_and_or, not_not] at hj
      rcases hj with hj | hj
      · exact (h8 j (by simp [H_LEN] at hj; omega)).symm
      · exact (hz j hj).symm
  simp only [specHonest, Spec.zkHonest, rngOf]
  congr 1
  · funext j; exact hb _ _ (by simp; exact ⟨rfl, rfl⟩) (fun j hj => (blind_ge _ j hj).1) j
  · funext j; exact hb _ _ (by simp; exact ⟨rfl, rfl, rfl⟩) (fun j hj => (blind_ge _ j hj).2.1) j
  · funext j; exact hb _ _ (by simp; exact ⟨rfl, rfl, rfl, rfl⟩) (fun j hj => (blind_ge _ j hj).2.2) j

end Circuit

end Bppp
