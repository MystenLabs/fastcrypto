-- THIS FILE IS AI-ONLY
import Mathlib.LinearAlgebra.Lagrange
import Mathlib.LinearAlgebra.Vandermonde
import Mathlib.Tactic
import bulletproofspp.Spec.Poly

/-!
# Interpolation

A polynomial of degree at most `d` that vanishes at `d + 1` distinct points is zero (Lemma 1 of
the paper), for `d = 2, 3`, and the inverse of the `3 × 3` system `(1, γ, γ² - 1)` that the
norm-linear extractor solves.
-/

open Polynomial Finset

namespace Bppp.Spec

variable {F : Type*} [Field F]

/-- A cubic with four distinct roots is zero. -/
lemma cubic_zero (t : Fin 4 → F) (ht : Function.Injective t) (a0 a1 a2 a3 : F)
    (h : ∀ k, a0 + a1 * t k + a2 * t k ^ 2 + a3 * t k ^ 3 = 0) :
    a0 = 0 ∧ a1 = 0 ∧ a2 = 0 ∧ a3 = 0 := by
  set p : F[X] := C a0 + C a1 * X + C a2 * X ^ 2 + C a3 * X ^ 3
  have hp : p = 0 := by
    refine eq_zero_of_degree_lt_of_eval_index_eq_zero univ (ht.injOn) ?_ ?_
    · rw [card_univ, Fintype.card_fin]
      refine lt_of_le_of_lt (degree_le_of_natDegree_le (p := p) (n := 3) ?_) (by decide)
      simp only [p]; compute_degree!
    · intro k _
      simp [p, h k]
  have c : ∀ i, p.coeff i = 0 := fun i => by rw [hp, coeff_zero]
  have c0 := c 0; have c1 := c 1; have c2 := c 2; have c3 := c 3
  simp [p, coeff_X, coeff_X_pow] at c0 c1 c2 c3
  exact ⟨c0, c1, c2, c3⟩

/-- A quadratic with three distinct roots is zero. -/
lemma quadratic_zero (t : Fin 3 → F) (ht : Function.Injective t) (a0 a1 a2 : F)
    (h : ∀ k, a0 + a1 * t k + a2 * t k ^ 2 = 0) : a0 = 0 ∧ a1 = 0 ∧ a2 = 0 := by
  set p : F[X] := C a0 + C a1 * X + C a2 * X ^ 2
  have hp : p = 0 := by
    refine eq_zero_of_degree_lt_of_eval_index_eq_zero univ (ht.injOn) ?_ ?_
    · rw [card_univ, Fintype.card_fin]
      refine lt_of_le_of_lt (degree_le_of_natDegree_le (p := p) (n := 2) ?_) (by decide)
      simp only [p]; compute_degree!
    · intro k _
      simp [p, h k]
  have c : ∀ i, p.coeff i = 0 := fun i => by rw [hp, coeff_zero]
  have c0 := c 0; have c1 := c 1; have c2 := c 2
  simp [p, coeff_X, coeff_X_pow] at c0 c1 c2
  exact ⟨c0, c1, c2⟩

/-! ## The `3 × 3` system -/

section System

variable (t0 t1 t2 : F)

/-- The weights that recover `C`, `X` and `R` from `C + γ_k X + (γ_k² - 1) R`, `k = 0, 1, 2`:
`b = 0, 1, 2` selects `C`, `X`, `R`. -/
noncomputable def lam (b : Fin 3) (m : Fin 3) : F :=
  let t := ![t0, t1, t2]
  let i := t (m + 1)
  let j := t (m + 2)
  let d := (t m - i) * (t m - j)
  match b with
  | 0 => (i * j + 1) / d
  | 1 => -(i + j) / d
  | 2 => 1 / d

variable {t0 t1 t2} (h01 : t0 ≠ t1) (h02 : t0 ≠ t2) (h12 : t1 ≠ t2)
include h01 h02 h12

/-- Recombining with the weights recovers each of `C`, `X`, `R`. -/
lemma lam_dual (b : Fin 3) :
    ∑ m, lam t0 t1 t2 b m = (if b = 0 then 1 else 0) ∧
    ∑ m, lam t0 t1 t2 b m * ![t0, t1, t2] m = (if b = 1 then 1 else 0) ∧
    ∑ m, lam t0 t1 t2 b m * (![t0, t1, t2] m ^ 2 - 1) = (if b = 2 then 1 else 0) := by
  have a := sub_ne_zero.2 h01; have b' := sub_ne_zero.2 h02; have c := sub_ne_zero.2 h12
  have a' := sub_ne_zero.2 h01.symm; have b'' := sub_ne_zero.2 h02.symm
  have c' := sub_ne_zero.2 h12.symm
  fin_cases b <;> simp [lam, Fin.sum_univ_three] <;> refine ⟨?_, ?_, ?_⟩ <;> field_simp <;> ring

/-- The weighted combination at `γ_k` is the indicator of `k`. -/
lemma lam_kron (k m : Fin 3) :
    lam t0 t1 t2 0 m + ![t0, t1, t2] k * lam t0 t1 t2 1 m +
      (![t0, t1, t2] k ^ 2 - 1) * lam t0 t1 t2 2 m = if k = m then 1 else 0 := by
  have a := sub_ne_zero.2 h01; have b' := sub_ne_zero.2 h02; have c := sub_ne_zero.2 h12
  have a' := sub_ne_zero.2 h01.symm; have b'' := sub_ne_zero.2 h02.symm
  have c' := sub_ne_zero.2 h12.symm
  fin_cases k <;> fin_cases m <;> simp [lam] <;> field_simp <;> ring

end System

/-! ## Lemma 1 for Laurent polynomials -/

/-- **Lemma 1.** A Laurent polynomial supported on the `n + 1` powers `T^a, ..., T^{a+n}` that
vanishes at `n + 1` distinct nonzero points is zero. -/
lemma laurent_zero {n : ℕ} {f : LaurentPolynomial F} {a : ℤ} (hf : Supp f a (a + n))
    (τ : Fin (n + 1) → Fˣ) (hτ : Function.Injective τ) (h : ∀ k, evalAt (τ k) f = 0) : f = 0 := by
  classical
  -- The coefficients, shifted to start at `T^0`, as a polynomial.
  set P : F[X] := ∑ i ∈ range (n + 1), C (coeff (a + i) f) * X ^ i
  have hfsum : f = ∑ i ∈ range (n + 1), mono (a + i) (coeff (a + i) f) := by
    refine ext_coeff fun p => ?_
    rw [map_sum]
    simp only [coeff_mono]
    by_cases hp : a ≤ p ∧ p ≤ a + n
    · rw [sum_eq_single_of_mem (p - a).toNat (mem_range.2 (by omega))]
      · rw [if_pos (by omega), show a + ((p - a).toNat : ℤ) = p by omega]
      · intro i _ hi; rw [if_neg (by omega)]
    · rw [sum_eq_zero fun i hi => if_neg (by simp only [mem_range] at hi; omega)]
      by_contra h0; exact hp (hf p h0)
  have hP : P = 0 := by
    have hinj : Function.Injective fun k => (τ k : F) := fun i j e => hτ (Units.ext e)
    refine eq_zero_of_degree_lt_of_eval_index_eq_zero univ (hinj.injOn) ?_ ?_
    · rw [card_univ, Fintype.card_fin]
      refine lt_of_le_of_lt (degree_sum_le _ _) ?_
      refine (Finset.sup_lt_iff (WithBot.bot_lt_coe _)).2 fun i hi => ?_
      refine lt_of_le_of_lt (degree_C_mul_X_pow_le _ _) ?_
      simp only [mem_range] at hi
      exact WithBot.coe_lt_coe.2 (by omega)
    · intro k _
      have hk := h k
      rw [hfsum, map_sum] at hk
      simp only [evalAt_mono] at hk
      have : eval (τ k : F) P = ((τ k : F) ^ a)⁻¹ *
          ∑ i ∈ range (n + 1), coeff (a + i) f * (τ k : F) ^ (a + (i : ℤ)) := by
        simp only [P, eval_finsetSum, eval_mul, eval_C, eval_pow, eval_X, mul_sum]
        refine sum_congr rfl fun i _ => ?_
        rw [zpow_add₀ (τ k).ne_zero, zpow_natCast]
        field_simp
      rw [this, hk, mul_zero]
  have hc : ∀ i < n + 1, coeff (a + i) f = 0 := fun i hi => by
    have := congrArg (fun q : Polynomial F => q.coeff i) hP
    simp only [P, finsetSum_coeff, coeff_C_mul_X_pow, Polynomial.coeff_zero] at this
    rwa [sum_eq_single_of_mem i (mem_range.2 hi) (fun j _ hj => if_neg (Ne.symm hj)),
      if_pos rfl] at this
  rw [hfsum]
  exact sum_eq_zero fun i hi => by rw [hc i (mem_range.1 hi), mono_zero]

/-! ## Lemma 2 -/

/-- **Lemma 2 (reciprocal vanishing).** If `Σ_{p ∈ U} e_p / (x + p)` vanishes at `|U|` distinct
points `x`, none a pole, then every `e_p` is zero. -/
lemma reciprocal_zero [DecidableEq F] (U : Finset F) (e : F → F) (x : Fin U.card → F)
    (hx : Function.Injective x) (hpole : ∀ k, ∀ p ∈ U, x k + p ≠ 0)
    (h : ∀ k, ∑ p ∈ U, e p / (x k + p) = 0) : ∀ p ∈ U, e p = 0 := by
  -- Clearing the denominators gives a polynomial of degree below `|U|`.
  set Q : F[X] := ∑ p ∈ U, C (e p) * ∏ q ∈ U.erase p, (X + C q)
  have hQ : Q = 0 := by
    refine eq_zero_of_degree_lt_of_eval_index_eq_zero univ (hx.injOn) ?_ ?_
    · rw [card_univ, Fintype.card_fin]
      refine lt_of_le_of_lt (degree_sum_le _ _) ((Finset.sup_lt_iff ?_).2 fun p hp => ?_)
      · exact WithBot.bot_lt_coe _
      refine lt_of_le_of_lt (degree_mul_le _ _) ?_
      refine lt_of_le_of_lt (add_le_add (degree_C_le) (degree_prod_le _ _)) ?_
      have hsum : ∑ q ∈ U.erase p, (X + C q : F[X]).degree ≤ ((U.erase p).card : WithBot ℕ) := by
        refine le_trans (sum_le_sum fun q _ => (degree_X_add_C q).le) ?_
        simp
      refine lt_of_le_of_lt (add_le_add le_rfl hsum) ?_
      rw [card_erase_of_mem hp, zero_add]
      have : 0 < U.card := card_pos.2 ⟨p, hp⟩
      exact_mod_cast (by omega : U.card - 1 < U.card)
    · intro k _
      have hk := h k
      have hprod : ∏ q ∈ U, (x k + q) ≠ 0 := prod_ne_zero_iff.2 fun q hq => hpole k q hq
      have : eval (x k) Q = (∏ q ∈ U, (x k + q)) * ∑ p ∈ U, e p / (x k + p) := by
        simp only [Q, eval_finsetSum, eval_mul, eval_C, eval_prod, eval_add, eval_X, mul_sum]
        refine sum_congr rfl fun p hp => ?_
        rw [← mul_prod_erase U _ hp]
        field_simp [hpole k p hp]
      rw [this, hk, mul_zero]
  intro p hp
  -- At `-p` only the term of `p` survives.
  have := congrArg (eval (-p)) hQ
  simp only [Q, eval_finsetSum, eval_mul, eval_C, eval_prod, eval_add, eval_X, eval_zero] at this
  rw [sum_eq_single_of_mem p hp] at this
  · have hne : ∏ q ∈ U.erase p, (-p + q) ≠ 0 := prod_ne_zero_iff.2 fun q hq => by
      have := ne_of_mem_erase hq; intro h0; apply this; linear_combination h0
    exact (mul_eq_zero.1 this).resolve_right hne
  · intro q hq hqp
    rw [prod_eq_zero (mem_erase.2 ⟨Ne.symm hqp, hp⟩) (by ring), mul_zero]

/-! ## Inverting a Vandermonde system -/

/-- The inverse of the Vandermonde matrix of distinct nodes `t`: weights `W` that recover the
coefficients of a polynomial of degree below `n` from its values at the nodes. -/
lemma vandermonde_inv {n : ℕ} (t : Fin n → F) (ht : Function.Injective t) :
    ∃ W : Fin n → Fin n → F,
      (∀ b j : Fin n, ∑ k, W b k * t k ^ (j : ℕ) = if b = j then 1 else 0) ∧
      (∀ k m : Fin n, ∑ b : Fin n, t k ^ (b : ℕ) * W b m = if k = m then 1 else 0) := by
  set M := Matrix.vandermonde t
  have hdet : IsUnit M.det := isUnit_iff_ne_zero.2 (Matrix.det_vandermonde_ne_zero_iff.2 ht)
  refine ⟨fun b k => M⁻¹ b k, fun b j => ?_, fun k m => ?_⟩
  · have := congrFun (congrFun (Matrix.nonsing_inv_mul M hdet) b) j
    rw [Matrix.mul_apply, Matrix.one_apply] at this
    simpa [M, Matrix.vandermonde_apply] using this
  · have := congrFun (congrFun (Matrix.mul_nonsing_inv M hdet) k) m
    rw [Matrix.mul_apply, Matrix.one_apply] at this
    simpa [M, Matrix.vandermonde_apply] using this

end Bppp.Spec
