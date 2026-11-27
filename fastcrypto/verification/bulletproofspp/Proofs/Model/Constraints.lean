-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.Constraints
import bulletproofspp.Proofs.Model.Laurent
import bulletproofspp.Proofs.Spec.Protocol

/-!
# Lemmas about `constraints.rs`

`Constraints::new` computes the public data (23) of `Spec`.
-/

open Finset LaurentPolynomial

namespace Bppp

variable {F : Type} [Field F] [DecidableEq F]

set_option linter.unusedSectionVars false

/-- The dimensions `CircuitParams::new` produces. -/
structure CircuitParams.Valid (params : CircuitParams) : Prop where
  n_d : params.n_d = params.m * params.d
  le : params.n_d ≤ params.nm
  base : 16 ≤ params.nm

/-- The parameters of `Spec`. -/
def CircuitParams.toSpec (params : CircuitParams) (hv : params.Valid) : Spec.Params where
  M := params.m
  D := params.d
  nm := params.nm
  hnm := hv.n_d ▸ hv.le
  h15 := by have := hv.base; omega

@[simp] lemma CircuitParams.M_toSpec (params : CircuitParams) (hv : params.Valid) :
    (params.toSpec hv).M = params.m := rfl

@[simp] lemma CircuitParams.D_toSpec (params : CircuitParams) (hv : params.Valid) :
    (params.toSpec hv).D = params.d := rfl

@[simp] lemma CircuitParams.nm_toSpec (params : CircuitParams) (hv : params.Valid) :
    (params.toSpec hv).nm = params.nm := rfl

@[simp] lemma CircuitParams.Nd_toSpec (params : CircuitParams) (hv : params.Valid) :
    (params.toSpec hv).Nd = params.n_d := by
  simp [Spec.Params.Nd, toSpec, hv.n_d]

namespace Constraints

variable (params : CircuitParams) (alpha mu lambda : F)

/-- The challenges `Constraints::new` takes, with `β` and `δ` added. -/
def challenges (beta delta : F) : Spec.Challenges F := ⟨alpha, mu, lambda, beta, delta⟩

/-- What `Constraints::new` computes. -/
structure Correct (C : Constraints F) (hv : params.Valid) : Prop where
  norm_weights : C.norm_weights = (List.range params.nm).map fun k => mu ^ (k + 1)
  lambdas : C.lambdas = (List.range (params.m + 1)).map (lambda ^ ·)
  cn_l : C.cn_l = (List.range params.nm).map
    (Spec.cnL (params.toSpec hv) (challenges alpha mu lambda 0 0))
  cn_r : C.cn_r = (List.range params.nm).map
    (Spec.cnR (params.toSpec hv) (challenges alpha mu lambda 0 0))
  cn_o : C.cn_o = (List.range params.nm).map
    (Spec.cnO (params.toSpec hv) (challenges alpha mu lambda 0 0))
  cn_v : C.cn_v = (List.range params.nm).map
    (Spec.cnV (params.toSpec hv) (challenges alpha mu lambda 0 0))
  cl_v : C.cl_v = (List.range H_LEN).map
    (Spec.clV (params.toSpec hv) (challenges alpha mu lambda 0 0))
  lambda_al : C.lambda_al = Spec.lamAl (params.toSpec hv) (challenges alpha mu lambda 0 0)
  mu_am : C.mu_am = Spec.muAm (params.toSpec hv) (challenges alpha mu lambda 0 0)

lemma mod_succ_of_ne {j d : ℕ} (hd : 0 < d) (h : (j + 1) % d ≠ 0) :
    (j + 1) % d = j % d + 1 := by
  have hr := Nat.mod_lt j hd
  rcases (show d = 1 ∨ 2 ≤ d by omega) with rfl | hd2
  · exact absurd (Nat.mod_one _) h
  · rw [Nat.add_mod_eq_ite, Nat.mod_eq_of_lt (by omega : 1 < d)] at h ⊢
    split_ifs at h ⊢ <;> omega

/-- The main loop after `K` iterations. -/
lemma loop_spec (hv : params.Valid) (shape : List F) (K : ℕ) :
    let st := (List.range K).foldl
      (loop_step params alpha mu mu⁻¹ ((List.range (params.m + 1)).map (lambda ^ ·)) shape)
      ⟨[], [], [], [], 0, one, one, one⟩
    st.norm_weights = (List.range K).map (fun k => mu ^ (k + 1)) ∧
    st.cn_l = (List.range K).map (Spec.cnL (params.toSpec hv) (challenges alpha mu lambda 0 0)) ∧
    st.cn_r = (List.range K).map (Spec.cnR (params.toSpec hv) (challenges alpha mu lambda 0 0)) ∧
    st.cn_v = (List.range K).map (fun k => shape.getD k 0 * (mu ^ (k + 1))⁻¹) ∧
    st.mu_am = ∑ k ∈ range (min K params.n_d), mu ^ (k + 1) ∧
    st.mu_pow = mu ^ K ∧ st.mu_inv_pow = (mu ^ K)⁻¹ ∧
    (0 < K → K ≤ params.n_d → st.base_pow = 16 ^ ((K - 1) % params.d + 1)) := by
  intro st
  induction K with
  | zero => simp [st, one]
  | succ K ih =>
    obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8⟩ := ih
    have hst : st = loop_step params alpha mu mu⁻¹ ((List.range (params.m + 1)).map (lambda ^ ·))
        shape ((List.range K).foldl (loop_step params alpha mu mu⁻¹
          ((List.range (params.m + 1)).map (lambda ^ ·)) shape)
          ⟨[], [], [], [], 0, one, one, one⟩) K := by
      simp only [st, List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    generalize ((List.range K).foldl (loop_step params alpha mu mu⁻¹
      ((List.range (params.m + 1)).map (lambda ^ ·)) shape)
      ⟨[], [], [], [], 0, one, one, one⟩) = st' at h1 h2 h3 h4 h5 h6 h7 h8 hst
    rw [hst]
    have hlam : ∀ i ≤ params.m, ((List.range (params.m + 1)).map (lambda ^ ·)).getD i 0 =
        lambda ^ i := fun i hi => by
      rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range (by omega)]; rfl
    have hr : List.range (K + 1) = List.range K ++ [K] := List.range_succ
    have hnd : (params.toSpec hv).Nd = params.n_d := CircuitParams.Nd_toSpec params hv
    simp only [loop_step, hr, List.map_append, List.map_cons, List.map_nil, h1, h2, h3, h4, h6, h7]
    by_cases hK : K < params.n_d
    · have hd : 0 < params.d := by
        rcases Nat.eq_zero_or_pos params.d with h | h
        · rw [hv.n_d, h, mul_zero] at hK; omega
        · exact h
      have hbase : (if K % params.d = 0 then one else st'.base_pow) = (16 : F) ^ (K % params.d) := by
        split_ifs with hk
        · rw [hk, pow_zero]; rfl
        · rcases K with _ | K
          · simp at hk
          · rw [h8 (by omega) (by omega), Nat.add_sub_cancel, mod_succ_of_ne hd hk]
      have hdiv : K / params.d ≤ params.m := by
        have := hv.n_d; rw [Nat.div_le_iff_le_mul_add_pred hd]; nlinarith
      simp only [hK, if_true, hbase, hlam _ hdiv, hlam _ le_rfl]
      refine ⟨by simp [pow_succ], ?_, ?_, by simp [pow_succ, mul_comm], ?_,
        by simp [pow_succ], by simp [pow_succ, mul_comm], fun _ _ => ?_⟩
      · simp [Spec.cnL, hK, challenges, div_eq_mul_inv, pow_succ, mul_comm]
      · simp [Spec.cnR, hK, challenges, div_eq_mul_inv, pow_succ, mul_comm]
      · rw [h5, show min (K + 1) params.n_d = min K params.n_d + 1 by omega, sum_range_succ,
          show min K params.n_d = K by omega, pow_succ]
      · simp [BASE, pow_succ]
    · simp only [hK, if_false]
      refine ⟨by simp [pow_succ], ?_, ?_, by simp [pow_succ, mul_comm], ?_,
        by simp [pow_succ], by simp [pow_succ, mul_comm], fun _ h => absurd h (by omega)⟩
      · simp [Spec.cnL, hK]
      · simp [Spec.cnR, hK]
      · rw [h5, show min (K + 1) params.n_d = min K params.n_d by omega]

lemma getElem_eq_getD {α : Type*} (l : List α) {k : ℕ} (h : k < l.length) (d : α) :
    l[k] = l.getD k d := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h, Option.getD_some]

lemma getD_iterate_mul (a r : F) (n k : ℕ) (hk : k < n) :
    (List.iterate (· * r) a n).getD k 0 = a * r ^ k := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_iterate _ _ _ _ hk, Option.getD_some]
  induction k generalizing a with
  | zero => simp
  | succ k ih =>
    rw [Function.iterate_succ_apply, ih _ (by omega), pow_succ]; ring

/-- `Constraints::new` computes the public data (23), when no denominator vanishes. -/
lemma new_correct (hv : params.Valid) (hmu : mu ≠ 0) (halpha : ∀ j : ℕ, j < 16 → alpha + j ≠ 0) :
    ∃ C, Constraints.new params alpha mu lambda = .ok C ∧ Correct params alpha mu lambda C hv := by
  have hbase := hv.base
  have ha0 : alpha ≠ 0 := by simpa using halpha 0 (by norm_num)
  have hlam : ((List.range (params.m + 1)).map (lambda ^ ·)).getD params.m 0 = lambda ^ params.m := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range (by omega)]; rfl
  obtain ⟨h1, h2, h3, h4, h5, -, -, -⟩ := loop_spec params alpha mu lambda hv
    (List.iterate (· * lambda ^ params.m) (lambda * lambda ^ params.m) (params.nm + H_LEN - 1))
    params.nm
  set st := (List.range params.nm).foldl
    (loop_step params alpha mu mu⁻¹ ((List.range (params.m + 1)).map (lambda ^ ·))
      (List.iterate (· * lambda ^ params.m) (lambda * lambda ^ params.m) (params.nm + H_LEN - 1)))
    ⟨[], [], [], [], 0, one, one, one⟩ with hst
  have hbar : ∀ k < params.nm, st.norm_weights.getD k 0 = mu ^ (k + 1) := fun k hk => by
    rw [h1, List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hk]; rfl
  have hden : ∀ x ∈ (List.range (BASE - 1)).map (fun k =>
      alpha * (alpha + ((k + 1 : ℕ) : F)) * st.norm_weights.getD k 0), x ≠ 0 := by
    intro x hx
    simp only [List.mem_map, List.mem_range, BASE] at hx
    obtain ⟨k, hk, rfl⟩ := hx
    rw [hbar k (by omega)]
    exact mul_ne_zero (mul_ne_zero ha0 (halpha (k + 1) (by omega))) (pow_ne_zero _ hmu)
  have hinv : inverse mu = .ok mu⁻¹ := by simp [inverse, hmu]
  have hinva : inverse alpha = .ok alpha⁻¹ := by simp [inverse, ha0]
  set shape := List.iterate (· * lambda ^ params.m) (lambda * lambda ^ params.m)
    (params.nm + H_LEN - 1) with hshape
  set inverses := ((List.range (BASE - 1)).map fun k =>
    alpha * (alpha + ((k + 1 : ℕ) : F)) * st.norm_weights.getD k 0).map (·⁻¹)
  refine ⟨⟨st.norm_weights, st.cn_l, st.cn_r,
    pad_to ((List.range (BASE - 1)).map fun k =>
      ((k + 1 : ℕ) : F) * lambda ^ params.m * inverses.getD k 0) params.nm,
    st.cn_v, 0 :: (List.range' 1 (H_LEN - 1)).map fun p => shape.getD (params.nm + p - 1) 0,
    (params.n_d : F) * lambda ^ params.m * alpha⁻¹, st.mu_am,
    (List.range (params.m + 1)).map (lambda ^ ·)⟩, ?_, ?_⟩
  · unfold Constraints.new
    rw [hinv, power_vector_eq]
    simp only [bind, Except.bind, hlam]
    rw [batch_invert_eq]
    · simp only [hinva]; rfl
    · rw [← hst]; exact hden
  · refine ⟨h1, rfl, h2, h3, ?_, ?_, ?_, ?_, ?_⟩
    · -- `cn_o`
      apply List.ext_getElem (by simp [length_pad_to])
      intro k hk1 hk2
      simp only [List.length_map, List.length_range] at hk2
      rw [getElem_eq_getD _ _ (0 : F), getD_pad_to, if_pos hk2, List.getElem_map,
        List.getElem_range, Spec.cnO]
      simp only [challenges, CircuitParams.M_toSpec]
      by_cases hk : k ≤ 14
      · rw [if_pos hk, List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range
          (by simp [BASE]; omega), Option.map_some, Option.getD_some, List.getD_eq_getElem?_getD,
          List.getElem?_map, List.getElem?_map, List.getElem?_range (by simp [BASE]; omega)]
        simp only [Option.map_some, Option.getD_some, hbar k (by omega)]
        push_cast; field_simp
      · rw [if_neg hk, getD_eq_zero_of_le (by simp [BASE]; omega)]
    · -- `cn_v`
      rw [h4]
      apply List.ext_getElem (by simp)
      intro k hk1 hk2
      simp only [List.getElem_map, List.getElem_range, Spec.cnV, challenges, CircuitParams.M_toSpec]
      simp only [List.length_map, List.length_range] at hk2
      rw [getD_iterate_mul _ _ _ _ (by simp [H_LEN]; omega), div_eq_mul_inv, ← pow_mul,
        ← pow_succ']
      ring_nf
    · -- `cl_v`
      apply List.ext_getElem (by simp [H_LEN])
      intro s hs1 hs2
      have hs8 : s < 8 := by simpa [H_LEN] using hs2
      rw [List.getElem_map, List.getElem_range, Spec.clV]
      rcases s with _ | s
      · simp
      · simp only [List.getElem_cons_succ, List.getElem_map, List.getElem_range', challenges,
          Spec.Params.g, CircuitParams.M_toSpec, CircuitParams.nm_toSpec, Nat.add_one_ne_zero,
          if_false]
        rw [hshape, show params.nm + (1 + 1 * s) - 1 = params.nm + s by omega,
          getD_iterate_mul _ _ _ _ (by simp only [H_LEN]; omega)]
        ring
    · -- `lambda_al`
      simp [Spec.lamAl, challenges, div_eq_mul_inv]
    · -- `mu_am`
      rw [h5, Spec.muAm, CircuitParams.Nd_toSpec, min_eq_right hv.le]; rfl

end Constraints

end Bppp
