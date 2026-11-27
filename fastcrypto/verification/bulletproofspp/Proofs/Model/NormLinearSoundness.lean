-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Model.NormLinear
import bulletproofspp.Proofs.Spec.NormLinearSoundness

/-!
# Accepting runs of `norm_linear::verify`

An accepting run of `verify` is an accepting transcript of the interactive argument of `Spec`: the
opening it sends in the clear satisfies the relation (19) on the instance folded with its rounds
and the challenges the transcript derives (`verify_accepts`). So a tree of such runs, forked at the
challenges, is a tree that `Spec.NormLinear.extract` extracts from.
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

set_option linter.unusedSectionVars false

namespace NormLinear

open BpppTranscript

/-- The transcript entries of the rounds. -/
def roundEntries : List (E × E) → List (Entry F E)
  | [] => []
  | (X, R) :: rounds => [.point "X" X, .point "R" R, .challenge "gamma"] ++ roundEntries rounds

/-- The challenges `verify` derives for the rounds, from the transcript `t`. -/
def gammasOf (t : BpppTranscript F E) : List (E × E) → List F
  | [] => []
  | (X, R) :: rounds =>
    let t' := t.extend [.point "X" X, .point "R" R, .challenge "gamma"]
    t'.oracle t'.log :: gammasOf t' rounds

variable (gens : Generators E)

/-- The instance of `Spec` that a state `(c, rho, _, _, w_h, w_g)` of the round loop stands for,
with commitment `C`. -/
def vInst (C : E) (c : List F) (rho : F) (w_h w_g : Weights F) : Spec.NormLinear.Instance F E where
  C := C
  c k := c.getD k 0
  H k := (contract' w_h.w gens.h_vec).getD k 0
  G k := (contract' w_g.w gens.g_vec).getD k 0
  Lℓ := c.length
  Ln := (contract' w_g.w gens.g_vec).length
  ρ := rho
  μ := rho * rho

/-- One iteration of the round loop folds as `Spec.NormLinear.foldInst`. -/
lemma vInst_fold (C X R : E) (c : List F) (rho gamma : F) (w_h w_g : Weights F)
    (hwh : 0 < w_h.w.length) (hwg : 0 < w_g.w.length)
    (hc : c.length = (contract' w_h.w gens.h_vec).length) :
    vInst gens (C + gamma • X + (gamma ^ 2 - 1) • R)
        (vec_add (split_even_odd c).1 (vec_scalar_mul gamma (split_even_odd c).2)) (rho * rho)
        (w_h.tensor_pair one gamma) (w_g.tensor_pair rho gamma) =
      Spec.NormLinear.foldInst (vInst gens C c rho w_h w_g) X R gamma := by
  have e1 : vec_add (split_even_odd c).1 (vec_scalar_mul gamma (split_even_odd c).2) =
      vec_add (vec_scalar_mul 1 (split_even_odd c).1) (vec_scalar_mul gamma (split_even_odd c).2) := by
    rw [vec_scalar_mul_one]
  rw [e1]
  simp only [vInst, Spec.NormLinear.foldInst, Spec.NormLinear.Instance.mk.injEq, true_and,
    contract'_tensor_pair hwh, contract'_tensor_pair hwg, length_fold_vec, length_foldPts]
  refine ⟨funext fun j => ?_, funext fun j => ?_, funext fun j => ?_, rfl, by ring⟩
  · rw [getD_fold_vec, one_mul]
  · rw [getD_foldPts_pts _ _ hc.symm, one, one_smul]
  · rw [getD_foldPts_pts _ _ rfl]

/-- The round loop of `verify` draws `gammasOf` and follows `Spec.NormLinear.foldPath`. -/
lemma loop_spec : ∀ (rounds : List (E × E)) (C : E) (c : List F) (rho : F) (gs0 : List F)
    (w_h w_g : Weights F) (T : BpppTranscript F E), 0 < w_h.w.length → 0 < w_g.w.length →
    c.length = (contract' w_h.w gens.h_vec).length →
    ∃ cf rhof wh' wg', (rounds.foldlM verify_round (c, rho, rho * rho, gs0, w_h, w_g)).run T =
        .ok ((cf, rhof, rhof * rhof, gs0 ++ gammasOf T rounds, wh', wg'),
          T.extend (roundEntries rounds)) ∧
      0 < wh'.w.length ∧ 0 < wg'.w.length ∧ cf.length = (contract' wh'.w gens.h_vec).length ∧
      vInst gens (C + ((List.zip rounds (gammasOf T rounds)).map fun ((X, R), γ) =>
          γ • X + (γ ^ 2 - 1) • R).sum) cf rhof wh' wg' =
        Spec.NormLinear.foldPath (vInst gens C c rho w_h w_g) rounds (gammasOf T rounds)
  | [], C, c, rho, gs0, w_h, w_g, T, hwh, hwg, hc => ⟨c, rho, w_h, w_g, by
      simp [gammasOf, roundEntries]; rfl, hwh, hwg, hc,
      by simp [gammasOf, Spec.NormLinear.foldPath]⟩
  | (X, R) :: rounds, C, c, rho, gs0, w_h, w_g, T, hwh, hwg, hc => by
    set T1 := T.extend [.point "X" X, .point "R" R, .challenge "gamma"]
    set γ := T1.oracle T1.log
    have hc' : (vec_add (split_even_odd c).1 (vec_scalar_mul γ (split_even_odd c).2)).length =
        (contract' (w_h.tensor_pair one γ).w gens.h_vec).length := by
      rw [contract'_tensor_pair hwh, length_foldPts, ← hc]
      simp [length_vec_add, length_vec_scalar_mul, length_split_even_odd_fst, length_split_even_odd_snd, Spec.NormLinear.half]
    have hpos : ∀ (W : Weights F) (a b : F), 0 < W.w.length → 0 < (W.tensor_pair a b).w.length :=
      fun W a b h => by rw [length_tensor_pair]; omega
    obtain ⟨cf, rhof, wh', wg', hrun, hwh', hwg', hcf, hfold⟩ := loop_spec rounds
      (C + γ • X + (γ ^ 2 - 1) • R) _ (rho * rho) (gs0 ++ [γ]) _ _ T1 (hpos _ _ _ hwh)
      (hpos _ _ _ hwg) hc'
    refine ⟨cf, rhof, wh', wg', ?_, hwh', hwg', hcf, ?_⟩
    · rw [List.foldlM_cons, StateT.run_bind]
      simp only [verify_round, StateT.run_bind, run_append_point, ok_bind, run_challenge_scalar,
        extend_extend, extend_oracle, extend_log, StateT.run_pure, pure_bind]
      simp only [List.append_assoc, List.cons_append, List.nil_append] at hrun ⊢
      rw [show T.log ++ [Entry.point "X" X, Entry.point "R" R, Entry.challenge "gamma"] = T1.log
        from rfl]
      refine hrun.trans ?_
      simp [gammasOf, roundEntries, T1, γ]
    · rw [gammasOf, List.zip_cons_cons, List.map_cons, List.sum_cons]
      simp only []
      rw [← add_assoc, ← add_assoc, Spec.NormLinear.foldPath,
        ← vInst_fold gens C X R c rho γ w_h w_g hwh hwg hc]
      exact hfold

lemma headD_eq_getD' (v : List F) : v.getD 0 0 = v.headD 0 := by cases v <;> rfl

/-! ## Lengths -/

/-- Halving, as each round does to the lengths. -/
def halve (a : ℕ) : ℕ := (a + 1) / 2

/-- `proof_shape` halves the linear length down to at most one entry, and the norm length down to
the final length. -/
lemma proof_shape_spec : ∀ (l n : ℕ),
    halve^[(proof_shape l n).1] l ≤ 1 ∧ halve^[(proof_shape l n).1] n = (proof_shape l n).2 := by
  intro l n
  induction h : l + n using Nat.strong_induction_on generalizing l n with
  | _ N ih =>
    by_cases hb : is_base_case l n
    · rw [proof_shape, dif_pos hb]
      simp only [is_base_case, Bool.and_eq_true, decide_eq_true_eq] at hb
      exact ⟨by simpa using hb.1, rfl⟩
    · rw [proof_shape_step hb]
      rw [is_base_case_iff] at hb
      obtain ⟨h1, h2⟩ := ih _ (by omega) ((l + 1) / 2) ((n + 1) / 2) rfl
      exact ⟨by rw [Function.iterate_succ_apply]; exact h1,
        by rw [Function.iterate_succ_apply]; exact h2⟩

lemma halve_pos : ∀ (k a : ℕ), 0 < a → 0 < halve^[k] a
  | 0, _, h => h
  | k + 1, a, h => by rw [Function.iterate_succ_apply]; exact halve_pos k _ (by simp [halve]; omega)

lemma length_gammasOf : ∀ (T : BpppTranscript F E) (rounds : List (E × E)),
    (gammasOf T rounds).length = rounds.length
  | _, [] => rfl
  | T, (X, R) :: rounds => by simp [gammasOf, length_gammasOf _ rounds]

lemma foldPath_lengths : ∀ (x : Spec.NormLinear.Instance F E) (rounds : List (E × E))
    (γs : List F), γs.length = rounds.length →
    (Spec.NormLinear.foldPath x rounds γs).Lℓ = halve^[rounds.length] x.Lℓ ∧
      (Spec.NormLinear.foldPath x rounds γs).Ln = halve^[rounds.length] x.Ln
  | x, [], _, _ => by simp [Spec.NormLinear.foldPath]
  | x, (X, R) :: rounds, γ :: γs, h => by
    obtain ⟨h1, h2⟩ := foldPath_lengths (Spec.NormLinear.foldInst x X R γ) rounds γs
      (by simpa using h)
    simp only [Spec.NormLinear.foldPath, h1, h2, List.length_cons, Function.iterate_succ_apply]
    exact ⟨rfl, rfl⟩

/-! ## The final check -/

/-- The MSM of `verify`'s final check. -/
lemma final_msm (cf : List F) (l_f : F) (n_f : List F) (muf ps : F) (pn : List F)
    (extra : List (F × E)) (rounds : List (E × E)) (gs : List F) (wh wg : Weights F)
    (hwh : 0 < wh.w.length) (hwg : 0 < wg.w.length) (hch : (contract' wh.w gens.h_vec).length = 1)
    (hcg : (contract' wg.w gens.g_vec).length = n_f.length) (hpn : pn.length = gens.g_vec.length) :
    gens.msm (cf.headD 0 * l_f + weighted_norm n_f muf - ps)
        (List.take gens.h_vec.length (wh.scale l_f))
        (List.zipWith (fun w pn_i => w - pn_i) (List.take gens.g_vec.length (wg.tensor n_f)) pn)
        (List.map (fun x => x.1) (List.map (fun x => (-x.1, x.2)) extra ++
          List.flatMap (fun x => [(-x.2, x.1.1), (one - x.2 * x.2, x.1.2)]) (rounds.zip gs)))
        (List.map (fun x => x.2) (List.map (fun x => (-x.1, x.2)) extra ++
          List.flatMap (fun x => [(-x.2, x.1.1), (one - x.2 * x.2, x.1.2)]) (rounds.zip gs))) =
      .ok ((cf.headD 0 * l_f + weighted_norm n_f muf - ps) • gens.g +
        (l_f • (contract' wh.w gens.h_vec).getD 0 0 +
          (∑ k ∈ range n_f.length, n_f.getD k 0 • (contract' wg.w gens.g_vec).getD k 0 -
            (List.zipWith (· • ·) pn gens.g_vec).sum)) +
        (-(extra.map fun (s, p) => s • p).sum -
          ((List.zip rounds gs).map fun ((X, R), γ) => γ • X + (γ ^ 2 - 1) • R).sum)) := by
  have hHle : gens.h_vec.length ≤ (wh.scale l_f).length := by
    have := LazyBases.ceil_le hwh (c := 1) (by rw [← length_contract' hwh gens.h_vec, hch])
    simp only [Weights.scale, List.length_map]; omega
  have hGle : gens.g_vec.length ≤ (wg.tensor n_f).length := by
    have := LazyBases.ceil_le hwg (c := n_f.length) (by rw [← length_contract' hwg gens.g_vec, hcg])
    rw [length_tensor]; exact this
  have hl1 : (List.take gens.h_vec.length (wh.scale l_f)).length = gens.h_vec.length := by
    simp [List.length_take, hHle]
  have hn1' : (List.zipWith (fun w pn_i => w - pn_i)
      (List.take gens.g_vec.length (wg.tensor n_f)) pn).length = gens.g_vec.length := by
    simp [List.length_zipWith, List.length_take, hGle, hpn]
  simp only [Generators.msm, mixed_multi_scalar_mul]
  rw [if_neg (by simp [hl1, hn1'])]
  simp only [List.cons_append, List.zipWith_cons_cons, List.zipWith_append hl1, List.sum_cons,
    List.sum_append, zipWith_map_fst_snd]
  have hd := dynamic_sum extra rounds gs
  simp only at hd
  rw [hd, sum_zipWith_sub _ _ _ (by simp [List.length_take, hGle, hpn]) (by simp [hGle]),
    scale_eq_tensor, LazyBases.msm_tensor_cur _ hwh _ _ (by rw [hch]; simp),
    LazyBases.msm_tensor_cur _ hwg _ _ (by rw [hcg])]
  simp only [List.length_singleton, range_one, sum_singleton, List.getD_cons_zero]

/-- **An accepting run is an accepting transcript.** If `verify` accepts, the opening sent in
the clear satisfies the relation (19) on the instance of `Spec`, with commitment
`ps*G + <pn, G_vec> + sum extra`, folded with the proof's rounds and the challenges `gammasOf`
that the transcript derives. -/
lemma verify_accepts (t t' : BpppTranscript F E) (c : List F) (ps : F) (pn : List F)
    (extra : List (F × E)) (rho : F) (proof : NormLinearProof F E) (hH : 0 < gens.h_vec.length)
    (h : (verify gens c ps pn extra rho proof).run t = .ok ((), t')) :
    Spec.NormLinear.Rel gens.g (Spec.NormLinear.foldPath
        (vInst gens (ps • gens.g + (List.zipWith (· • ·) pn gens.g_vec).sum +
          (extra.map fun (s, p) => s • p).sum) c rho .new .new) proof.rounds
        (gammasOf (t.extend [.message "dom-sep" ("norm_linear".toList.map Char.toNat)])
          proof.rounds))
      ⟨fun k => [proof.l_final].getD k 0, fun k => proof.n_final.getD k 0⟩ := by
  by_cases hc1 : c.length ≠ gens.h_vec.length ∨ pn.length ≠ gens.g_vec.length
  · simp [verify, hc1, StateT.run, throw, throwThe, MonadExceptOf.throw, StateT.lift,
      bind, StateT.bind, Except.bind] at h
  by_cases hc2 : proof.rounds.length ≠ (proof_shape gens.h_vec.length gens.g_vec.length).1 ∨
      proof.n_final.length ≠ (proof_shape gens.h_vec.length gens.g_vec.length).2
  · simp [verify, hc1, hc2, StateT.run, throw, throwThe, MonadExceptOf.throw, StateT.lift,
      bind, StateT.bind, Except.bind, pure, StateT.pure, Except.pure] at h
  have hc1' := hc1; have hc2' := hc2
  push Not at hc1' hc2'
  obtain ⟨hcl, hpn⟩ := hc1'
  obtain ⟨hr, hnf⟩ := hc2'
  set T := t.extend [.message "dom-sep" ("norm_linear".toList.map Char.toNat)] with hT
  obtain ⟨cf, rhof, wh', wg', hrun, hwh', hwg', hcf, hfold⟩ := loop_spec gens proof.rounds
    (ps • gens.g + (List.zipWith (· • ·) pn gens.g_vec).sum + (extra.map fun (s, p) => s • p).sum)
    c rho [] .new .new T (by simp [LazyBases.new_w]) (by simp [LazyBases.new_w])
    (by rw [LazyBases.new_w, contract'_one, hcl])
  simp only [verify, hc1, hc2, if_false, StateT.run_bind, run_domain_sep, ok_bind,
    pure_bind] at h
  rw [← hT, hrun, ok_bind] at h
  simp only [run_append_scalars, ok_bind, List.nil_append] at h
  -- The final lengths.
  have hlen := foldPath_lengths (vInst gens (ps • gens.g + (List.zipWith (· • ·) pn gens.g_vec).sum +
    (extra.map fun (s, p) => s • p).sum) c rho .new .new) proof.rounds (gammasOf T proof.rounds)
    (length_gammasOf _ _)
  rw [← hfold] at hlen
  simp only [vInst, LazyBases.new_w, contract'_one, hcl, hr] at hlen
  obtain ⟨hs1, hs2⟩ := proof_shape_spec gens.h_vec.length gens.g_vec.length
  have hcf1 : cf.length = 1 := by
    have := halve_pos (proof_shape gens.h_vec.length gens.g_vec.length).1 _ hH
    rw [hlen.1]; omega
  have hcg : (contract' wg'.w gens.g_vec).length = proof.n_final.length := by
    rw [hlen.2, hs2, hnf]
  rw [final_msm gens cf proof.l_final proof.n_final (rhof * rhof) ps pn extra proof.rounds
    (gammasOf T proof.rounds) wh' wg' hwh' hwg' (by rw [← hcf, hcf1]) hcg hpn, run_liftM_ok,
    ok_bind] at h
  split_ifs at h with hz
  swap
  · simp [StateT.run, throw, throwThe, MonadExceptOf.throw, StateT.lift, bind,
      Except.bind] at h
  rw [← hfold]
  simp only [Spec.NormLinear.Rel, vInst, hcf1, hcg, Spec.NormLinear.ip, Spec.NormLinear.wip,
    Spec.NormLinear.msm, range_one, sum_singleton, List.getD_cons_zero]
  rw [weighted_norm_eq] at hz
  have hw : ∑ k ∈ range proof.n_final.length, (rhof * rhof) ^ (k + 1) *
      (proof.n_final.getD k 0 * proof.n_final.getD k 0) = ∑ k ∈ range proof.n_final.length,
      proof.n_final.getD k 0 * proof.n_final.getD k 0 * (rhof * rhof) ^ (k + 1) :=
    sum_congr rfl fun k _ => by ring
  rw [hw, headD_eq_getD' cf]
  linear_combination (norm := module) -hz

/-- **Special soundness of `norm_linear::verify`.** Take a tree of transcripts with four distinct
challenges per round, each of whose paths is an accepting run of `verify` on its own transcript,
with the path's challenges derived by that transcript. Then the commitment
`ps*G + <pn, G_vec> + sum extra` opens to a witness of the relation (19), or the generators satisfy
a nontrivial linear relation. -/
lemma verify_extract (c : List F) (ps : F) (pn : List F) (extra : List (F × E)) (rho : F)
    (tree : Spec.NormLinear.Tree F E) (d : ℕ) (hd : tree.Depth d) (hdist : tree.Distinct)
    (hL : 2 ^ d ∣ gens.g_vec.length) (hH : 0 < gens.h_vec.length) (hρ : rho ≠ 0)
    (hruns : ∀ p ∈ tree.paths, ∃ (proof : NormLinearProof F E) (t t' : BpppTranscript F E),
      p.1 = proof.rounds ∧
      p.2.1 = gammasOf (t.extend [.message "dom-sep" ("norm_linear".toList.map Char.toNat)])
        proof.rounds ∧
      p.2.2 = ⟨fun k => [proof.l_final].getD k 0, fun k => proof.n_final.getD k 0⟩ ∧
      (verify gens c ps pn extra rho proof).run t = .ok ((), t')) :
    let x := vInst gens (ps • gens.g + (List.zipWith (· • ·) pn gens.g_vec).sum +
      (extra.map fun (s, p) => s • p).sum) c rho .new .new
    (∃ w, Spec.NormLinear.Rel gens.g x w) ∨ Spec.NormLinear.Relation gens.g x := by
  intro x
  refine Spec.NormLinear.extract gens.g tree d x hd ?_ hρ (by simp [x, vInst, sq]) ?_
  · simpa [x, vInst, LazyBases.new_w, contract'_one] using hL
  · refine Spec.NormLinear.accepts_of_paths gens.g tree x hdist fun p hp => ?_
    obtain ⟨proof, t, t', h1, h2, h3, hv⟩ := hruns p hp
    rw [h1, h2, h3]
    exact verify_accepts gens t t' c ps pn extra rho proof hH hv

end NormLinear

end Bppp
