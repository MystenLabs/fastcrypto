-- THIS FILE IS AI-ONLY
import bulletproofspp.Spec.CircuitSoundness

/-!
# The `λ`, `β`, `ρ` and `α` levels of the circuit extractor

For any opening, the `T³` coefficient of `f(T)`, the value row (29), is a polynomial in `λ` whose
coefficients are the rows (35): the degree-0 residue `E_0 + L_0`, the value links `L_i`, set
membership `S` and the shape rows. Forking `λ` forces every row to vanish, and forking `β`
removes the blinding bracket from the degree-0 residue, leaving (36). That is a polynomial in
`μ`, and forking `μ = ρ²` gives the first value link and the Hadamard rows. With those, set
membership is a sum of simple poles in `α` (37), and forking `α` puts every digit in the table.
-/

open Finset LaurentPolynomial

namespace Bppp.Spec

variable {F : Type*} [Field F] (P : Params) (ch : Challenges F)

/-- The value row (29) for any opening. -/
lemma coeff3_f (hδ : ch.δ ≠ 0) (w : Opening F) : coeff 3 (f P ch w) =
    2 * (lamAl P ch + muAm P ch) + w.vhat -
    2 * ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (ch.δ * w.nO k * w.nV k + w.nO k * cnO P ch k +
      cnV P ch k * w.nV k + w.nL k * w.nR k + w.nL k * cnL P ch k + cnR P ch k * w.nR k) -
    ch.β * (ch.δ * w.rO 4 + w.rL 3 + w.rR 2) - ∑ s ∈ range 8, clV P ch s * lin w.rV w.ℓV s := by
  have hcl : coeff 3 (∑ s ∈ range 8, c P ch s * ℓ ch w s) =
      ch.β * (ch.δ * w.rO 4 + w.rL 3 + w.rR 2) + ∑ s ∈ range 8, clV P ch s * lin w.rV w.ℓV s := by
    simp only [sum_range_succ, sum_range_zero, c, ℓ, e, lin]
    norm_num [add_mul, mul_add, mono_mul]
    ring
  simp only [f, σ, ps, map_sub, map_add, hcl, coeff3_normμ, n_eq, pn_eq, coeff3_sq, coeff_mono]
  norm_num
  rw [mul_sum]
  have hsum : ∀ k ∈ range P.nm, ch.μ ^ (k + 1) * (2 * (cnV P ch k * (ch.δ⁻¹ * cnO P ch k) +
      cnR P ch k * cnL P ch k)) - ch.μ ^ (k + 1) * (2 * ((ch.δ * w.nO k + cnV P ch k) *
        (w.nV k + ch.δ⁻¹ * cnO P ch k) + (w.nL k + cnR P ch k) * (w.nR k + cnL P ch k))) =
      -(2 * (ch.μ ^ (k + 1) * (ch.δ * w.nO k * w.nV k + w.nO k * cnO P ch k +
        cnV P ch k * w.nV k + w.nL k * w.nR k + w.nL k * cnL P ch k + cnR P ch k * w.nR k))) :=
    fun k _ => by field_simp; ring
  have key := sum_congr rfl hsum
  rw [sum_sub_distrib, sum_neg_distrib] at key
  linear_combination key

/-! ## The rows (35)

`w` supplies the openings of `C_O`, `C_L`, `C_R`, and `u`, `h`, `n` the coordinates of the inputs
`V_i` on `g`, `H` and `G`. None depends on `λ`. -/

section Rows

variable (w : Opening F) (u : ℕ → F) (h n : ℕ → ℕ → F)

/-- The part of the `λ⁰` coefficient outside the first value link. -/
noncomputable def rowE0 : F :=
  2 * muAm P ch - 2 * ∑ k ∈ range P.nm, ch.μ ^ (k + 1) *
    (w.nL k * w.nR k + if k < P.Nd then ch.α * w.nR k else 0) -
  ch.β * (ch.δ * w.rO 4 + w.rL 3 + w.rR 2)

/-- The value link of input `i`, scaled by `2`. -/
noncomputable def rowL (i : ℕ) : F :=
  2 * u i - 4 * ch.δ * ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w.nO k * n i k) -
    2 * ∑ t ∈ range P.D, 16 ^ t * w.nL (i * P.D + t)

/-- Set membership, scaled by `2`. -/
noncomputable def rowS : F :=
  2 * P.Nd / ch.α - 2 * ∑ k ∈ range P.nm,
    ((if k ≤ 14 then w.nO k * (((k : F) + 1) / (ch.α * (ch.α + ((k : F) + 1)))) else 0) +
      if k < P.Nd then w.nR k else 0)

/-- The shape row of coordinate `j` of input `i`: `G_j` for `j < nm`, else `H_{j-nm+1}`. -/
noncomputable def rowR (j i : ℕ) : F := if j < P.nm then -4 * n i j else -2 * h i (j - P.nm + 1)

end Rows

lemma pieceO (hμ : ch.μ ≠ 0) (w : Opening F) :
    ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w.nO k * cnO P ch k) = ch.lam ^ P.M * ∑ k ∈ range P.nm,
      (if k ≤ 14 then w.nO k * (((k : F) + 1) / (ch.α * (ch.α + ((k : F) + 1)))) else 0) := by
  rw [mul_sum]
  refine sum_congr rfl fun k _ => ?_
  have := pow_ne_zero (k + 1) hμ
  simp only [cnO]
  split_ifs
  · field_simp
  · simp

lemma pieceR (hμ : ch.μ ≠ 0) (w : Opening F) :
    ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (cnR P ch k * w.nR k) =
      ch.lam ^ P.M * ∑ k ∈ range P.nm, (if k < P.Nd then w.nR k else 0) +
        ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (if k < P.Nd then ch.α * w.nR k else 0) := by
  rw [mul_sum, ← sum_add_distrib]
  refine sum_congr rfl fun k _ => ?_
  have := pow_ne_zero (k + 1) hμ
  simp only [cnR]
  split_ifs
  · field_simp
  · simp

lemma pieceL (hμ : ch.μ ≠ 0) (w : Opening F) :
    ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w.nL k * cnL P ch k) =
      ∑ i ∈ range P.M, ch.lam ^ i * ∑ t ∈ range P.D, 16 ^ t * w.nL (i * P.D + t) := by
  rw [sum_range_of_le (m := P.Nd) P.hnm fun k hk => by simp [cnL]; omega]
  rw [sum_congr rfl fun k hk => show ch.μ ^ (k + 1) * (w.nL k * cnL P ch k) =
      ch.lam ^ (k / P.D) * (16 ^ (k % P.D) * w.nL (k / P.D * P.D + k % P.D)) by
    have hk := mem_range.mp hk
    have := pow_ne_zero (k + 1) hμ
    rw [Nat.div_add_mod']
    simp only [cnL, if_pos hk]
    field_simp]
  rw [show P.Nd = P.M * P.D from rfl, sum_range_mul_div_mod P.M P.D fun i t =>
    ch.lam ^ i * (16 ^ t * w.nL (i * P.D + t))]
  simp [mul_sum]

section Inputs

variable (w : Opening F) (u : ℕ → F) (h n : ℕ → ℕ → F)

lemma pieceV (hμ : ch.μ ≠ 0) (hn : ∀ k < P.nm, w.nV k = 2 * ∑ i ∈ range P.M, ch.lam ^ i * n i k) :
    ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (cnV P ch k * w.nV k) =
      ∑ j ∈ range P.nm, ∑ i ∈ range P.M, ch.lam ^ (P.M * (j + 1) + 1 + i) * (2 * n i j) := by
  refine sum_congr rfl fun k hk => ?_
  have := pow_ne_zero (k + 1) hμ
  rw [hn k (mem_range.mp hk)]
  simp only [mul_sum]
  refine sum_congr rfl fun i _ => ?_
  simp only [cnV, pow_add]
  field_simp

lemma pieceOV (hn : ∀ k < P.nm, w.nV k = 2 * ∑ i ∈ range P.M, ch.lam ^ i * n i k) :
    ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (ch.δ * w.nO k * w.nV k) = 2 * ch.δ *
      ∑ i ∈ range P.M, ch.lam ^ i * ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w.nO k * n i k) := by
  rw [sum_congr rfl fun k hk => by rw [hn k (mem_range.mp hk)]]
  simp only [mul_sum]
  rw [sum_comm]
  exact sum_congr rfl fun k _ => sum_congr rfl fun i _ => by ring

lemma pieceH (hl : ∀ s < 8, lin w.rV w.ℓV s = 2 * ∑ i ∈ range P.M, ch.lam ^ i * h i s) :
    ∑ s ∈ range 8, clV P ch s * lin w.rV w.ℓV s =
      ∑ s ∈ range 7, ∑ i ∈ range P.M,
        ch.lam ^ (P.M * (P.nm + s + 1) + 1 + i) * (2 * h i (s + 1)) := by
  rw [sum_range_succ']
  simp only [clV, if_pos, zero_mul, add_zero, Nat.succ_ne_zero, if_false]
  refine sum_congr rfl fun s hs => ?_
  rw [hl (s + 1) (by simp at hs; omega), mul_sum, mul_sum]
  refine sum_congr rfl fun i _ => ?_
  simp only [Params.g, pow_add]
  ring

lemma shape_sum : ∑ j ∈ range (P.nm + 7), ∑ i ∈ range P.M,
    ch.lam ^ (P.M * (j + 1) + 1 + i) * rowR P h n j i =
    -(2 * ∑ j ∈ range P.nm, ∑ i ∈ range P.M, ch.lam ^ (P.M * (j + 1) + 1 + i) * (2 * n i j)) -
      ∑ s ∈ range 7, ∑ i ∈ range P.M,
        ch.lam ^ (P.M * (P.nm + s + 1) + 1 + i) * (2 * h i (s + 1)) := by
  rw [sum_range_add, mul_sum, ← sum_neg_distrib, sub_eq_add_neg, ← sum_neg_distrib]
  congr 1
  · refine sum_congr rfl fun j hj => ?_
    rw [mul_sum, ← sum_neg_distrib]
    refine sum_congr rfl fun i _ => ?_
    simp only [rowR, if_pos (mem_range.mp hj)]; ring
  · refine sum_congr rfl fun s _ => ?_
    rw [← sum_neg_distrib]
    refine sum_congr rfl fun i _ => ?_
    simp only [rowR, show ¬ P.nm + s < P.nm by omega, if_false,
      show P.nm + s - P.nm + 1 = s + 1 by omega, show P.nm + s + 1 = P.nm + (s + 1) by omega]
    ring

/-- The value row as a polynomial in `λ` with the rows (35) as coefficients, when `V̂` opens to
the `λ`-combination of the input coordinates. -/
lemma coeff3_rows (hδ : ch.δ ≠ 0) (hμ : ch.μ ≠ 0)
    (hv : w.vhat = 2 * ∑ i ∈ range P.M, ch.lam ^ i * u i)
    (hl : ∀ s < 8, lin w.rV w.ℓV s = 2 * ∑ i ∈ range P.M, ch.lam ^ i * h i s)
    (hn : ∀ k < P.nm, w.nV k = 2 * ∑ i ∈ range P.M, ch.lam ^ i * n i k) :
    coeff 3 (f P ch w) = rowE0 P ch w + ∑ i ∈ range P.M, ch.lam ^ i * rowL P ch w u n i +
      ch.lam ^ P.M * rowS P ch w + ∑ j ∈ range (P.nm + 7), ∑ i ∈ range P.M,
        ch.lam ^ (P.M * (j + 1) + 1 + i) * rowR P h n j i := by
  rw [coeff3_f P ch hδ, shape_sum]
  simp only [mul_add, sum_add_distrib]
  rw [pieceO P ch hμ, pieceR P ch hμ, pieceL P ch hμ, pieceV P ch w n hμ hn, pieceOV P ch w n hn,
    pieceH P ch w h hl, hv]
  have hL : ∑ i ∈ range P.M, ch.lam ^ i * rowL P ch w u n i =
      2 * ∑ i ∈ range P.M, ch.lam ^ i * u i - 4 * ch.δ * ∑ i ∈ range P.M, ch.lam ^ i *
        ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w.nO k * n i k) -
      2 * ∑ i ∈ range P.M, ch.lam ^ i * ∑ t ∈ range P.D, 16 ^ t * w.nL (i * P.D + t) := by
    rw [mul_sum, mul_sum, mul_sum, ← sum_sub_distrib, ← sum_sub_distrib]
    exact sum_congr rfl fun i _ => by simp only [rowL]; ring
  rw [hL]
  simp only [rowE0, rowS, lamAl, mul_add, sum_add_distrib]
  ring_nf
  simp only [mul_comm P.D]
  ring
end Inputs

/-! ## Vanishing of the rows -/

lemma shape_exp_inj {M j j' i i' : ℕ} (hi : i < M) (hi' : i' < M)
    (h : M * (j + 1) + 1 + i = M * (j' + 1) + 1 + i') : j = j' ∧ i = i' := by
  rcases lt_trichotomy j j' with hj | rfl | hj
  · have : M * (j + 2) ≤ M * (j' + 1) := Nat.mul_le_mul_left _ (by omega)
    have : M * (j + 2) = M * (j + 1) + M := by ring
    omega
  · omega
  · have : M * (j' + 2) ≤ M * (j + 1) := Nat.mul_le_mul_left _ (by omega)
    have : M * (j' + 2) = M * (j' + 1) + M := by ring
    omega

open Polynomial in
/-- If the polynomial in `λ` with the rows as coefficients vanishes at `M(nm+8)+1` distinct
points, every row vanishes, the degree-0 one together with the first value link. -/
lemma rows_zero (hM : 0 < P.M) (E0 S : F) (L : ℕ → F) (R : ℕ → ℕ → F)
    (x : Fin (P.M * (P.nm + 8) + 1) → F) (hx : Function.Injective x)
    (h : ∀ r, E0 + ∑ i ∈ range P.M, x r ^ i * L i + x r ^ P.M * S + ∑ j ∈ range (P.nm + 7),
      ∑ i ∈ range P.M, x r ^ (P.M * (j + 1) + 1 + i) * R j i = 0) :
    E0 + L 0 = 0 ∧ (∀ i, 1 ≤ i → i < P.M → L i = 0) ∧ S = 0 ∧
      ∀ j < P.nm + 7, ∀ i < P.M, R j i = 0 := by
  set Q : F[X] := Polynomial.C E0 + ∑ i ∈ range P.M, Polynomial.C (L i) * X ^ i +
    Polynomial.C S * X ^ P.M + ∑ j ∈ range (P.nm + 7), ∑ i ∈ range P.M, Polynomial.C (R j i) * X ^ (P.M * (j + 1) + 1 + i)
  have hMj : ∀ j, P.M ≤ P.M * (j + 1) := fun j => Nat.le_mul_of_pos_right _ (by omega)
  have hco : ∀ d, Q.coeff d = (if d = 0 then E0 else 0) +
      ∑ i ∈ range P.M, (if d = i then L i else 0) + (if d = P.M then S else 0) +
      ∑ j ∈ range (P.nm + 7), ∑ i ∈ range P.M,
        (if d = P.M * (j + 1) + 1 + i then R j i else 0) := fun d => by
    simp only [Q, coeff_add, finsetSum_coeff, coeff_C_mul, coeff_X_pow, coeff_C, mul_ite, mul_one,
      mul_zero]
  have hQ : Q = 0 := by
    refine eq_zero_of_degree_lt_of_eval_index_eq_zero univ hx.injOn ?_ fun r _ => ?_
    · rw [card_univ, Fintype.card_fin, degree_lt_iff_coeff_zero]
      intro d hd
      have hd : P.M * (P.nm + 8) + 1 ≤ d := by exact_mod_cast hd
      have hle : ∀ j < P.nm + 7, P.M * (j + 1) + P.M ≤ P.M * (P.nm + 8) := fun j hj => by
        have : P.M * (j + 2) ≤ P.M * (P.nm + 8) := Nat.mul_le_mul_left _ (by omega)
        have : P.M * (j + 2) = P.M * (j + 1) + P.M := by ring
        omega
      have : P.M ≤ P.M * (P.nm + 8) := Nat.le_mul_of_pos_right _ (by omega)
      rw [hco, if_neg (by omega), if_neg (by omega)]
      rw [sum_eq_zero fun i hi => if_neg (by simp at hi; omega),
        sum_eq_zero fun j hj => sum_eq_zero fun i hi => if_neg (by
          simp at hi hj; have := hle j hj; omega)]
      simp
    · simp only [Q, eval_add, eval_C, eval_finsetSum, eval_mul, eval_pow, eval_X]
      simpa only [mul_comm] using h r
  have c : ∀ d, Q.coeff d = 0 := fun d => by rw [hQ, coeff_zero]
  have hsh : ∀ d < P.M + 1, ∑ j ∈ range (P.nm + 7), ∑ i ∈ range P.M,
      (if d = P.M * (j + 1) + 1 + i then R j i else 0) = 0 := fun d hd =>
    sum_eq_zero fun j _ => sum_eq_zero fun i _ => if_neg (by have := hMj j; omega)
  refine ⟨?_, fun i hi1 hi => ?_, ?_, fun j hj i hi => ?_⟩
  · have := c 0
    rw [hco, hsh 0 (by omega), if_pos rfl, if_neg (by omega), sum_ite_eq] at this
    simpa [hM] using this
  · have := c i
    rw [hco, hsh i (by omega), if_neg (by omega), if_neg (by omega), sum_ite_eq] at this
    simpa [hi] using this
  · have := c P.M
    rw [hco, hsh P.M (by omega), if_neg (by omega), if_pos rfl,
      sum_eq_zero fun i hi => if_neg (by simp at hi; omega)] at this
    simpa using this
  · have hj1 := hMj j
    have := c (P.M * (j + 1) + 1 + i)
    rw [hco, if_neg (by omega), if_neg (by omega),
      sum_eq_zero fun i' hi' => if_neg (by simp at hi'; omega), sum_eq_single j, sum_eq_single i]
      at this
    · simpa using this
    · intro i' hi' hne; exact if_neg fun e => hne (shape_exp_inj hi (by simpa using hi') e).2.symm
    · intro hi'; exact absurd (mem_range.mpr hi) hi'
    · intro j' hj' hne
      exact sum_eq_zero fun i' hi' => if_neg fun e =>
        hne (shape_exp_inj hi (by simpa using hi') e).1.symm
    · intro hj'; exact absurd (mem_range.mpr hj) hj'

/-- The rows depend on the opening only through `n_O`, `n_L`, `n_R` and three blindings. -/
lemma rows_congr {w w' : Opening F} (hO : ∀ k < P.nm, w.nO k = w'.nO k)
    (hL : ∀ k < P.nm, w.nL k = w'.nL k) (hR : ∀ k < P.nm, w.nR k = w'.nR k)
    (hrO : w.rO 4 = w'.rO 4) (hrL : w.rL 3 = w'.rL 3) (hrR : w.rR 2 = w'.rR 2) :
    rowE0 P ch w = rowE0 P ch w' ∧ rowS P ch w = rowS P ch w' ∧
      ∀ (u : ℕ → F) (n : ℕ → ℕ → F), ∀ i < P.M, rowL P ch w u n i = rowL P ch w' u n i := by
  refine ⟨?_, ?_, fun u n i hi => ?_⟩
  · have : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) *
        (w.nL k * w.nR k + if k < P.Nd then ch.α * w.nR k else 0) =
        ∑ k ∈ range P.nm, ch.μ ^ (k + 1) *
        (w'.nL k * w'.nR k + if k < P.Nd then ch.α * w'.nR k else 0) :=
      sum_congr rfl fun k hk => by rw [hL k (mem_range.1 hk), hR k (mem_range.1 hk)]
    simp only [rowE0, this, hrO, hrL, hrR]
  · have : ∑ k ∈ range P.nm,
        ((if k ≤ 14 then w.nO k * (((k : F) + 1) / (ch.α * (ch.α + ((k : F) + 1)))) else 0) +
          if k < P.Nd then w.nR k else 0) = ∑ k ∈ range P.nm,
        ((if k ≤ 14 then w'.nO k * (((k : F) + 1) / (ch.α * (ch.α + ((k : F) + 1)))) else 0) +
          if k < P.Nd then w'.nR k else 0) :=
      sum_congr rfl fun k hk => by rw [hO k (mem_range.1 hk), hR k (mem_range.1 hk)]
    simp only [rowS, this]
  · have h1 : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w.nO k * n i k) =
        ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w'.nO k * n i k) :=
      sum_congr rfl fun k hk => by rw [hO k (mem_range.1 hk)]
    have h2 : ∑ t ∈ range P.D, 16 ^ t * w.nL (i * P.D + t) =
        ∑ t ∈ range P.D, 16 ^ t * w'.nL (i * P.D + t) := sum_congr rfl fun t ht => by
      have := Nat.mul_le_mul_right P.D (show i + 1 ≤ P.M by omega)
      have := P.hnm
      have : (i + 1) * P.D = i * P.D + P.D := by ring
      rw [hL _ (by simp at ht; omega)]
    simp only [rowL, h1, h2]

section Extract

variable {E : Type*} [AddCommGroup E] [Module F E] (g : E) (H G : ℕ → E)

variable (F) in
/-- A nontrivial linear relation among `g`, `H_0, ..., H_7` and `G_0, ..., G_{nm-1}`. -/
def Relation : Prop :=
  ∃ (s : F) (h n : ℕ → F), (s ≠ 0 ∨ (∃ j < 8, h j ≠ 0) ∨ (∃ j < P.nm, n j ≠ 0)) ∧
    commit P g H G s h n = 0

/-- The relation the `τ` level returns is one. -/
lemma relation_of_tau {ch : Challenges F} {cS cO cL cR V : E} {rho : F} {τ : Fˣ}
    (h : NormLinear.Relation g (tauInst P ch g H G cS cO cL cR V rho τ)) : Relation F P g H G := by
  obtain ⟨s, h, n, hne, he⟩ := h
  exact ⟨s, h, n, hne, he⟩

/-- Two openings of one element agree, or their difference is a relation. -/
lemma binding {s s' : F} {h h' n n' : ℕ → F}
    (he : commit P g H G s h n = commit P g H G s' h' n') :
    (s = s' ∧ (∀ j < 8, h j = h' j) ∧ ∀ j < P.nm, n j = n' j) ∨ Relation F P g H G := by
  by_cases hc : s = s' ∧ (∀ j < 8, h j = h' j) ∧ ∀ j < P.nm, n j = n' j
  · exact Or.inl hc
  right
  refine ⟨s - s', fun j => h j - h' j, fun j => n j - n' j, ?_, ?_⟩
  · by_contra hn
    push Not at hn
    exact hc ⟨sub_eq_zero.1 hn.1, fun j hj => sub_eq_zero.1 (hn.2.1 j hj),
      fun j hj => sub_eq_zero.1 (hn.2.2 j hj)⟩
  · rw [commit_sub, he, sub_self]

/-- **The `λ` level.** Take `M(nm+8)+1` distinct `λ`, the other challenges fixed, each with an
opening of `C_O`, `C_L`, `C_R` and `V̂ = 2Σ_i λ^i V_i` whose error polynomial vanishes. Either the
inputs open in the `(g, H_0)`-plane, set membership holds, the value links of the inputs `i ≥ 1`
hold and the degree-0 residue vanishes, or the generators satisfy a nontrivial relation. -/
lemma extract_lam (h2 : (2 : F) ≠ 0) (hM : 0 < P.M) (hδ : ch.δ ≠ 0) (hμ : ch.μ ≠ 0)
    (cO cL cR : E) (V : ℕ → E) (lam : Fin (P.M * (P.nm + 8) + 1) → F)
    (hlam : Function.Injective lam) (wo : Fin (P.M * (P.nm + 8) + 1) → Opening F)
    (hf : ∀ r, f P { ch with lam := lam r } (wo r) = 0)
    (hO : ∀ r, cO = Spec.cO P g H G (wo r)) (hL : ∀ r, cL = Spec.cL P g H G (wo r))
    (hR : ∀ r, cR = Spec.cR P g H G (wo r))
    (hV : ∀ r, vHat P { ch with lam := lam r } V =
      commit P g H G (wo r).vhat (lin (wo r).rV (wo r).ℓV) (wo r).nV) :
    (∃ (u : ℕ → F) (h n : ℕ → ℕ → F), (∀ i < P.M, V i = commit P g H G (u i) (h i) (n i)) ∧
      (∀ i < P.M, ∀ k < P.nm, n i k = 0) ∧ (∀ i < P.M, ∀ s, 1 ≤ s → s < 8 → h i s = 0) ∧
      rowS P ch (wo 0) = 0 ∧
      (∀ i, 1 ≤ i → i < P.M → u i = ∑ t ∈ range P.D, 16 ^ t * (wo 0).nL (i * P.D + t)) ∧
      rowE0 P ch (wo 0) + rowL P ch (wo 0) u n 0 = 0) ∨ Relation F P g H G := by
  by_cases hrel : Relation F P g H G
  · exact Or.inr hrel
  left
  -- The openings of `C_O`, `C_L`, `C_R` agree across branches.
  have aO := fun r => (binding P g H G ((hO r).symm.trans (hO 0))).resolve_right hrel
  have aL := fun r => (binding P g H G ((hL r).symm.trans (hL 0))).resolve_right hrel
  have aR := fun r => (binding P g H G ((hR r).symm.trans (hR 0))).resolve_right hrel
  -- Open each `V_i` by inverting the Vandermonde matrix of the first `M` branches.
  have hMN : P.M ≤ P.M * (P.nm + 8) + 1 := by
    have : P.M ≤ P.M * (P.nm + 8) := Nat.le_mul_of_pos_right _ (by omega)
    omega
  set ι : Fin P.M → Fin (P.M * (P.nm + 8) + 1) := Fin.castLE hMN
  set t : Fin P.M → F := fun k => lam (ι k)
  have ht : Function.Injective t := hlam.comp (Fin.castLE_injective _)
  obtain ⟨W, hW1, -⟩ := vandermonde_inv t ht
  have hVF : ∀ b : Fin P.M, V b = commit P g H G (∑ k, W b k / 2 * (wo (ι k)).vhat)
      (fun j => ∑ k, W b k / 2 * lin (wo (ι k)).rV (wo (ι k)).ℓV j)
      (fun j => ∑ k, W b k / 2 * (wo (ι k)).nV j) := fun b => by
    rw [commit_sum]
    have e1 : ∀ k, commit P g H G (wo (ι k)).vhat (lin (wo (ι k)).rV (wo (ι k)).ℓV)
        (wo (ι k)).nV = (2 : F) • ∑ i : Fin P.M, t k ^ (i : ℕ) • V i := fun k => by
      rw [← hV]
      simp only [vHat]
      exact congrArg _ (Fin.sum_univ_eq_sum_range (fun i => lam (ι k) ^ i • V i) P.M).symm
    simp only [e1, smul_sum, smul_smul]
    rw [sum_comm]
    simp only [← sum_smul]
    have : ∀ i : Fin P.M, ∑ k, W b k / 2 * (2 * t k ^ (i : ℕ)) = if b = i then 1 else 0 :=
      fun i => by
        rw [← hW1 b i]
        exact sum_congr rfl fun k _ => by field_simp
    simp only [this, ite_smul, one_smul, zero_smul, sum_ite_eq, mem_univ, if_true]
  set u : ℕ → F := fun i => if hi : i < P.M then ∑ k, W ⟨i, hi⟩ k / 2 * (wo (ι k)).vhat else 0
  set hh : ℕ → ℕ → F := fun i j =>
    if hi : i < P.M then ∑ k, W ⟨i, hi⟩ k / 2 * lin (wo (ι k)).rV (wo (ι k)).ℓV j else 0
  set nn : ℕ → ℕ → F := fun i j =>
    if hi : i < P.M then ∑ k, W ⟨i, hi⟩ k / 2 * (wo (ι k)).nV j else 0
  have hVu : ∀ i < P.M, V i = commit P g H G (u i) (hh i) (nn i) := fun i hi => by
    simp only [u, hh, nn, dif_pos hi]
    exact hVF ⟨i, hi⟩
  -- In every branch `V̂` opens to the `λ`-combination of these.
  have hVr : ∀ r, (wo r).vhat = 2 * ∑ i ∈ range P.M, lam r ^ i * u i ∧
      (∀ s < 8, lin (wo r).rV (wo r).ℓV s = 2 * ∑ i ∈ range P.M, lam r ^ i * hh i s) ∧
      (∀ k < P.nm, (wo r).nV k = 2 * ∑ i ∈ range P.M, lam r ^ i * nn i k) := fun r => by
    have e := (commit_sum P g H G (range P.M) (fun i => 2 * lam r ^ i) u hh nn).trans
      (?_ : _ = commit P g H G (wo r).vhat (lin (wo r).rV (wo r).ℓV) (wo r).nV)
    · obtain ⟨e1, e2, e3⟩ := (binding P g H G e).resolve_right hrel
      refine ⟨?_, fun s hs => ?_, fun k hk => ?_⟩
      · rw [← e1, mul_sum]; exact sum_congr rfl fun i _ => by ring
      · rw [← e2 s hs, mul_sum]; exact sum_congr rfl fun i _ => by ring
      · rw [← e3 k hk, mul_sum]; exact sum_congr rfl fun i _ => by ring
    · rw [← hV r]
      simp only [vHat, smul_sum, smul_smul]
      exact sum_congr rfl fun i hi => by rw [hVu i (mem_range.1 hi)]
  -- The value row vanishes in every branch, as a polynomial in `λ` with fixed coefficients.
  have hrow : ∀ r, rowE0 P ch (wo 0) + ∑ i ∈ range P.M, lam r ^ i * rowL P ch (wo 0) u nn i +
      lam r ^ P.M * rowS P ch (wo 0) + ∑ j ∈ range (P.nm + 7), ∑ i ∈ range P.M,
        lam r ^ (P.M * (j + 1) + 1 + i) * rowR P hh nn j i = 0 := fun r => by
    obtain ⟨hv, hl, hn⟩ := hVr r
    have h3 := coeff3_rows P { ch with lam := lam r } (wo r) u hh nn hδ hμ hv hl hn
    rw [hf r, map_zero] at h3
    obtain ⟨c1, c2, c3⟩ := rows_congr P ch (fun k hk => (aO r).2.2 k hk)
      (fun k hk => (aL r).2.2 k hk) (fun k hk => (aR r).2.2 k hk)
      (by simpa [lin] using (aO r).2.1 3 (by norm_num))
      (by simpa [lin] using (aL r).2.1 2 (by norm_num))
      (by simpa [lin] using (aR r).2.1 1 (by norm_num))
    have hLs : ∑ i ∈ range P.M, lam r ^ i * rowL P ch (wo r) u nn i =
        ∑ i ∈ range P.M, lam r ^ i * rowL P ch (wo 0) u nn i :=
      sum_congr rfl fun i hi => by rw [c3 u nn i (mem_range.1 hi)]
    change 0 = rowE0 P ch (wo r) + ∑ i ∈ range P.M, lam r ^ i * rowL P ch (wo r) u nn i +
      lam r ^ P.M * rowS P ch (wo r) + _ at h3
    rw [c1, c2, hLs] at h3
    exact h3.symm
  obtain ⟨hE, hLi, hS, hRz⟩ := rows_zero P hM _ _ _ _ lam hlam hrow
  -- Read off the rows.
  have h4 : (4 : F) ≠ 0 := by
    rw [show (4 : F) = 2 * 2 by norm_num]; exact mul_ne_zero h2 h2
  have hn0 : ∀ i < P.M, ∀ k < P.nm, nn i k = 0 := fun i hi k hk => by
    have := hRz k (by omega) i hi
    simp only [rowR, if_pos hk] at this
    exact (mul_eq_zero.1 this).resolve_left (neg_ne_zero.2 h4)
  refine ⟨u, hh, nn, hVu, hn0, fun i hi s hs1 hs8 => ?_, hS, fun i hi1 hi => ?_, hE⟩
  · have := hRz (P.nm + s - 1) (by omega) i hi
    simp only [rowR, show ¬ P.nm + s - 1 < P.nm by omega, if_false,
      show P.nm + s - 1 - P.nm + 1 = s by omega] at this
    exact (mul_eq_zero.1 this).resolve_left (neg_ne_zero.2 h2)
  · have := hLi i hi1 hi
    have hz : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * ((wo 0).nO k * nn i k) = 0 :=
      sum_eq_zero fun k hk => by rw [hn0 i hi k (mem_range.1 hk)]; ring
    simp only [rowL, hz, mul_zero, sub_zero] at this
    exact mul_left_cancel₀ h2 (by linear_combination this)

/-! ## The `β` level -/

/-- The residue (36), scaled by `2`: the first value link and the Hadamard rows, weighted by
powers of `μ`. `w` supplies `n_L`, `n_R` and `u0` is the `g`-coordinate of `V_0`. -/
noncomputable def row36 (w : Opening F) (u0 : F) : F :=
  2 * muAm P ch - 2 * ∑ k ∈ range P.nm, ch.μ ^ (k + 1) *
    (w.nL k * w.nR k + if k < P.Nd then ch.α * w.nR k else 0) +
  2 * u0 - 2 * ∑ t ∈ range P.D, 16 ^ t * w.nL t

/-- With `V_0` in the `(g, H_0)`-plane, the degree-0 residue is (36) less the blinding bracket. -/
lemma residue_eq (x : F) (w : Opening F) (u : ℕ → F) (n : ℕ → ℕ → F)
    (hn : ∀ k < P.nm, n 0 k = 0) :
    rowE0 P { ch with β := x } w + rowL P { ch with β := x } w u n 0 =
      row36 P ch w (u 0) - x * (ch.δ * w.rO 4 + w.rL 3 + w.rR 2) := by
  have hz : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (w.nO k * n 0 k) = 0 :=
    sum_eq_zero fun k hk => by rw [hn k (mem_range.1 hk)]; ring
  simp only [rowE0, rowL, row36, muAm, hz, zero_mul, zero_add]
  ring

/-- **The `β` level.** Take two distinct `β`, the other challenges fixed, each with openings of
`C_O`, `C_L`, `C_R` and of `V_0` in the `(g, H_0)`-plane whose degree-0 residue vanishes. Either
(36) holds, or the generators satisfy a nontrivial relation. -/
lemma extract_beta (hM : 0 < P.M) (cO cL cR V0 : E) (β : Fin 2 → F) (hβ : Function.Injective β)
    (w : Fin 2 → Opening F) (u : Fin 2 → ℕ → F) (h n : Fin 2 → ℕ → ℕ → F)
    (hO : ∀ b, cO = Spec.cO P g H G (w b)) (hL : ∀ b, cL = Spec.cL P g H G (w b))
    (hR : ∀ b, cR = Spec.cR P g H G (w b)) (hV : ∀ b, V0 = commit P g H G (u b 0) (h b 0) (n b 0))
    (hn : ∀ b, ∀ k < P.nm, n b 0 k = 0)
    (hres : ∀ b, rowE0 P { ch with β := β b } (w b) + rowL P { ch with β := β b } (w b) (u b) (n b) 0 = 0) :
    row36 P ch (w 0) (u 0 0) = 0 ∨ Relation F P g H G := by
  by_cases hrel : Relation F P g H G
  · exact Or.inr hrel
  left
  have aO := (binding P g H G ((hO 1).symm.trans (hO 0))).resolve_right hrel
  have aL := (binding P g H G ((hL 1).symm.trans (hL 0))).resolve_right hrel
  have aR := (binding P g H G ((hR 1).symm.trans (hR 0))).resolve_right hrel
  have aV := (binding P g H G ((hV 1).symm.trans (hV 0))).resolve_right hrel
  have hrO : (w 1).rO 4 = (w 0).rO 4 := by simpa [lin] using aO.2.1 3 (by norm_num)
  have hrL : (w 1).rL 3 = (w 0).rL 3 := by simpa [lin] using aL.2.1 2 (by norm_num)
  have hrR : (w 1).rR 2 = (w 0).rR 2 := by simpa [lin] using aR.2.1 1 (by norm_num)
  have h36 : row36 P ch (w 1) (u 1 0) = row36 P ch (w 0) (u 0 0) := by
    have : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) *
        ((w 1).nL k * (w 1).nR k + if k < P.Nd then ch.α * (w 1).nR k else 0) =
        ∑ k ∈ range P.nm, ch.μ ^ (k + 1) *
        ((w 0).nL k * (w 0).nR k + if k < P.Nd then ch.α * (w 0).nR k else 0) :=
      sum_congr rfl fun k hk => by rw [aL.2.2 k (mem_range.1 hk), aR.2.2 k (mem_range.1 hk)]
    have ht : ∑ t ∈ range P.D, 16 ^ t * (w 1).nL t = ∑ t ∈ range P.D, 16 ^ t * (w 0).nL t :=
      sum_congr rfl fun t ht => by
        have := P.hnm
        have : P.D ≤ P.M * P.D := Nat.le_mul_of_pos_left _ hM
        rw [aL.2.2 t (by simp at ht; omega)]
    simp only [row36, this, ht, aV.1]
  have e0 := hres 0
  have e1 := hres 1
  rw [residue_eq P ch _ _ _ _ (hn 0)] at e0
  rw [residue_eq P ch _ _ _ _ (hn 1), h36, hrO, hrL, hrR] at e1
  have hne : β 0 - β 1 ≠ 0 := sub_ne_zero.2 fun e => absurd (hβ e) (by decide)
  have hbr : ch.δ * (w 0).rO 4 + (w 0).rL 3 + (w 0).rR 2 = 0 :=
    (mul_eq_zero.1 (by linear_combination e1 - e0 : (β 0 - β 1) * _ = 0)).resolve_left hne
  rw [hbr, mul_zero, sub_zero] at e0
  exact e0

/-! ## The `ρ` level -/

open Polynomial in
/-- A polynomial of degree at most `N` with `N + 1` distinct roots is zero. -/
lemma poly_zero {N : ℕ} (a : ℕ → F) (x : Fin (N + 1) → F) (hx : Function.Injective x)
    (h : ∀ r, ∑ d ∈ range (N + 1), a d * x r ^ d = 0) : ∀ d ≤ N, a d = 0 := by
  set Q : F[X] := ∑ d ∈ range (N + 1), Polynomial.C (a d) * X ^ d
  have hco : ∀ d, Q.coeff d = if d < N + 1 then a d else 0 := fun d => by
    simp only [Q, finsetSum_coeff, coeff_C_mul, coeff_X_pow, mul_ite, mul_one, mul_zero]
    rw [sum_ite_eq]; simp
  have hQ : Q = 0 := by
    refine eq_zero_of_degree_lt_of_eval_index_eq_zero univ hx.injOn ?_ fun r _ => ?_
    · rw [card_univ, Fintype.card_fin, degree_lt_iff_coeff_zero]
      intro d hd
      have hd : N + 1 ≤ d := by exact_mod_cast hd
      rw [hco, if_neg (by omega)]
    · simpa only [Q, eval_finsetSum, eval_mul, eval_C, eval_pow, eval_X] using h r
  intro d hd
  have := hco d
  rw [hQ, coeff_zero, if_pos (by omega)] at this
  exact this.symm

/-- (36) as a polynomial in `μ`: the first value link at `μ⁰` and the Hadamard row of slot `k`
at `μ^{k+1}`. -/
lemma row36_eq (w : Opening F) (u0 : F) :
    row36 P ch w u0 = ∑ d ∈ range (P.nm + 1), (if d = 0 then
      2 * (u0 - ∑ t ∈ range P.D, 16 ^ t * w.nL t) else
      -2 * (w.nL (d - 1) * w.nR (d - 1) +
        if d - 1 < P.Nd then ch.α * w.nR (d - 1) - 1 else 0)) * ch.μ ^ d := by
  rw [sum_range_succ']
  simp only [Nat.succ_ne_zero, if_false, if_true, pow_zero, mul_one, Nat.add_sub_cancel]
  have hm : muAm P ch = ∑ k ∈ range P.nm, if k < P.Nd then ch.μ ^ (k + 1) else 0 := by
    rw [muAm, sum_range_of_le (m := P.Nd) P.hnm fun k hk => if_neg (by omega)]
    exact sum_congr rfl fun k hk => (if_pos (mem_range.1 hk)).symm
  have hs : ∀ k ∈ range P.nm, -2 * (w.nL k * w.nR k +
      (if k < P.Nd then ch.α * w.nR k - 1 else 0)) * ch.μ ^ (k + 1) =
      2 * (if k < P.Nd then ch.μ ^ (k + 1) else 0) - 2 * (ch.μ ^ (k + 1) *
        (w.nL k * w.nR k + if k < P.Nd then ch.α * w.nR k else 0)) := fun k _ => by
    split_ifs <;> ring
  rw [sum_congr rfl hs, sum_sub_distrib, ← mul_sum, ← mul_sum, ← hm, row36]
  ring

/-- **The `ρ` level.** Take `nm + 1` distinct `μ`, the other challenges fixed, each with openings
of `C_L`, `C_R` and `V_0` satisfying (36). Either the first value link and the Hadamard rows hold,
or the generators satisfy a nontrivial relation. -/
lemma extract_rho (h2 : (2 : F) ≠ 0) (hM : 0 < P.M) (cL cR V0 : E) (μ : Fin (P.nm + 1) → F)
    (hμ : Function.Injective μ) (w : Fin (P.nm + 1) → Opening F) (u0 : Fin (P.nm + 1) → F)
    (h0 n0 : Fin (P.nm + 1) → ℕ → F)
    (hL : ∀ r, cL = Spec.cL P g H G (w r)) (hR : ∀ r, cR = Spec.cR P g H G (w r))
    (hV : ∀ r, V0 = commit P g H G (u0 r) (h0 r) (n0 r))
    (h36 : ∀ r, row36 P { ch with μ := μ r } (w r) (u0 r) = 0) :
    (u0 0 = ∑ t ∈ range P.D, 16 ^ t * (w 0).nL t ∧
      (∀ k < P.Nd, (ch.α + (w 0).nL k) * (w 0).nR k = 1) ∧
      ∀ k, P.Nd ≤ k → k < P.nm → (w 0).nL k * (w 0).nR k = 0) ∨ Relation F P g H G := by
  by_cases hrel : Relation F P g H G
  · exact Or.inr hrel
  left
  have aL := fun r => (binding P g H G ((hL r).symm.trans (hL 0))).resolve_right hrel
  have aR := fun r => (binding P g H G ((hR r).symm.trans (hR 0))).resolve_right hrel
  have aV := fun r => (binding P g H G ((hV r).symm.trans (hV 0))).resolve_right hrel
  set a : ℕ → F := fun d => if d = 0 then
      2 * (u0 0 - ∑ t ∈ range P.D, 16 ^ t * (w 0).nL t) else
      -2 * ((w 0).nL (d - 1) * (w 0).nR (d - 1) +
        if d - 1 < P.Nd then ch.α * (w 0).nR (d - 1) - 1 else 0)
  have hz := poly_zero a μ hμ fun r => by
    have e := h36 r
    rw [row36_eq] at e
    refine (sum_congr rfl fun d hd => ?_).trans e
    have hd := mem_range.1 hd
    simp only [a]
    split_ifs
    · rw [(aV r).1]
      congr 3
      exact sum_congr rfl fun t ht => by
        have := P.hnm
        have : P.D ≤ P.M * P.D := Nat.le_mul_of_pos_left _ hM
        rw [(aL r).2.2 t (by simp at ht; omega)]
    · rw [(aL r).2.2 _ (by omega), (aR r).2.2 _ (by omega)]
    · rw [(aL r).2.2 _ (by omega), (aR r).2.2 _ (by omega)]
  refine ⟨?_, fun k hk => ?_, fun k hk1 hk2 => ?_⟩
  · have := hz 0 (by omega)
    simp only [a, if_pos rfl] at this
    exact sub_eq_zero.1 ((mul_eq_zero.1 this).resolve_left h2)
  · have := hz (k + 1) (by have := P.hnm; simp only [Params.Nd] at hk; omega)
    simp only [a, Nat.succ_ne_zero, if_false, Nat.add_sub_cancel, if_pos hk] at this
    have := (mul_eq_zero.1 this).resolve_left (neg_ne_zero.2 h2)
    linear_combination this
  · have := hz (k + 1) (by omega)
    simp only [a, Nat.succ_ne_zero, if_false, Nat.add_sub_cancel, if_neg (show ¬ k < P.Nd by omega),
      add_zero] at this
    exact (mul_eq_zero.1 this).resolve_left (neg_ne_zero.2 h2)

/-! ## The `α` level -/

/-- The residues (37) of set membership after substituting the Hadamard rows: at the pole `-p`,
`[p = 0](N_d - Σ_j m_j) + Σ_j [p = j] m_j - |{k < N_d : n_{L,k} = p}|`. -/
noncomputable def residue37 [DecidableEq F] (w : Opening F) (p : F) : F :=
  (if p = 0 then (P.Nd : F) else 0) - ∑ j ∈ range 15, w.nO j *
    ((if p = 0 then 1 else 0) - if p = ((j + 1 : ℕ) : F) then 1 else 0) -
  ∑ k ∈ range P.Nd, if w.nL k = p then 1 else 0

/-- The partial-fraction form of set membership, given the Hadamard rows. -/
lemma rowS_partial [DecidableEq F] (w : Opening F) (hα : ∀ j : ℕ, j < 16 → ch.α + j ≠ 0)
    (hR : ∀ k < P.Nd, w.nR k = (ch.α + w.nL k)⁻¹) (U : Finset F)
    (hU0 : ∀ j : ℕ, j < 16 → (j : F) ∈ U) (hUL : ∀ k < P.Nd, w.nL k ∈ U) :
    rowS P ch w = 2 * ∑ p ∈ U, residue37 P w p / (ch.α + p) := by
  have hα0 : ch.α ≠ 0 := by simpa using hα 0 (by norm_num)
  have hsel : ∀ q ∈ U, ∀ c : F, ∑ p ∈ U, (if p = q then c else 0) / (ch.α + p) = c / (ch.α + q) :=
    fun q hq c => by simp only [ite_div, zero_div, sum_ite_eq', if_pos hq]
  have hsel' : ∀ q ∈ U, ∀ c : F, ∑ p ∈ U, (if q = p then c else 0) / (ch.α + p) = c / (ch.α + q) :=
    fun q hq c => by simp only [ite_div, zero_div, sum_ite_eq, if_pos hq]
  have h0 : (0 : F) ∈ U := by simpa using hU0 0 (by norm_num)
  have hexp : ∑ p ∈ U, residue37 P w p / (ch.α + p) = P.Nd / ch.α - ∑ j ∈ range 15, w.nO j *
      (1 / ch.α - 1 / (ch.α + ((j + 1 : ℕ) : F))) - ∑ k ∈ range P.Nd, 1 / (ch.α + w.nL k) := by
    simp only [residue37, sub_div, sum_sub_distrib, sum_div, mul_sub, mul_div_assoc]
    have A : ∑ x ∈ U, ∑ j ∈ range 15, w.nO j * ((if x = 0 then 1 else 0) / (ch.α + x)) =
        ∑ j ∈ range 15, w.nO j * (1 / ch.α) := by
      rw [sum_comm]
      exact sum_congr rfl fun j _ => by rw [← mul_sum, hsel 0 h0, add_zero]
    have B : ∑ x ∈ U, ∑ j ∈ range 15,
        w.nO j * ((if x = ((j + 1 : ℕ) : F) then 1 else 0) / (ch.α + x)) =
        ∑ j ∈ range 15, w.nO j * (1 / (ch.α + ((j + 1 : ℕ) : F))) := by
      rw [sum_comm]
      exact sum_congr rfl fun j hj => by
        rw [← mul_sum, hsel _ (hU0 (j + 1) (by simp at hj; omega))]
    have C : ∑ x ∈ U, ∑ k ∈ range P.Nd, (if w.nL k = x then (1 : F) else 0) / (ch.α + x) =
        ∑ k ∈ range P.Nd, 1 / (ch.α + w.nL k) := by
      rw [sum_comm]
      exact sum_congr rfl fun k hk => hsel' _ (hUL k (mem_range.1 hk)) 1
    rw [hsel 0 h0, A, B, C, add_zero]
  rw [hexp, rowS]
  have h15 : ∑ k ∈ range P.nm,
      ((if k ≤ 14 then w.nO k * (((k : F) + 1) / (ch.α * (ch.α + ((k : F) + 1)))) else 0) +
        if k < P.Nd then w.nR k else 0) = ∑ j ∈ range 15, w.nO j *
          (1 / ch.α - 1 / (ch.α + ((j + 1 : ℕ) : F))) +
        ∑ k ∈ range P.Nd, 1 / (ch.α + w.nL k) := by
    rw [sum_add_distrib, sum_range_of_le (m := 15) P.h15 fun k hk => if_neg (by omega),
      sum_range_of_le (m := P.Nd) P.hnm fun k hk => if_neg (by omega)]
    congr 1
    · refine sum_congr rfl fun j hj => ?_
      have hj := mem_range.1 hj
      have := hα (j + 1) (by omega)
      push_cast at this ⊢
      rw [if_pos (by omega)]
      field_simp
      ring
    · exact sum_congr rfl fun k hk => by rw [if_pos (mem_range.1 hk), hR k (mem_range.1 hk),
        one_div]
  rw [h15]
  field_simp
  ring

lemma residue37_congr [DecidableEq F] {w w' : Opening F} (hO : ∀ k < P.nm, w.nO k = w'.nO k)
    (hL : ∀ k < P.Nd, w.nL k = w'.nL k) (p : F) : residue37 P w p = residue37 P w' p := by
  have h1 : ∑ j ∈ range 15, w.nO j *
      ((if p = 0 then 1 else 0) - if p = ((j + 1 : ℕ) : F) then 1 else 0) =
      ∑ j ∈ range 15, w'.nO j *
      ((if p = 0 then 1 else 0) - if p = ((j + 1 : ℕ) : F) then 1 else 0) :=
    sum_congr rfl fun j hj => by rw [hO j (by have := P.h15; simp at hj; omega)]
  have h2 : ∑ k ∈ range P.Nd, (if w.nL k = p then (1 : F) else 0) =
      ∑ k ∈ range P.Nd, if w'.nL k = p then 1 else 0 :=
    sum_congr rfl fun k hk => by rw [hL k (mem_range.1 hk)]
  simp only [residue37, h1, h2]

/-- **The `α` level.** Take `N_d + 16` distinct `α`, none in `{-15, ..., 0}`, the other challenges
fixed, each with openings of `C_O`, `C_L` and an `n_R` satisfying set membership and the Hadamard
rows. If no `m = 1, ..., N_d` is zero in the field, either every digit of `C_L` is in
`{0, ..., 15}`, or the generators satisfy a nontrivial relation. -/
lemma extract_alpha [DecidableEq F] (h2 : (2 : F) ≠ 0)
    (hchar : ∀ m : ℕ, 0 < m → m ≤ P.Nd → (m : F) ≠ 0)
    (cO cL : E) (α : Fin (P.Nd + 16) → F) (hα : Function.Injective α)
    (hpole : ∀ r, ∀ j : ℕ, j < 16 → α r + j ≠ 0) (w : Fin (P.Nd + 16) → Opening F)
    (hO : ∀ r, cO = Spec.cO P g H G (w r)) (hL : ∀ r, cL = Spec.cL P g H G (w r))
    (hS : ∀ r, rowS P { ch with α := α r } (w r) = 0)
    (hH : ∀ r, ∀ k < P.Nd, (α r + (w r).nL k) * (w r).nR k = 1) :
    (∀ k < P.Nd, ∃ d : ℕ, d < 16 ∧ (w 0).nL k = d) ∨ Relation F P g H G := by
  by_cases hrel : Relation F P g H G
  · exact Or.inr hrel
  left
  have aO := fun r => (binding P g H G ((hO r).symm.trans (hO 0))).resolve_right hrel
  have aL := fun r => (binding P g H G ((hL r).symm.trans (hL 0))).resolve_right hrel
  have hnL : ∀ r, ∀ k < P.Nd, (w r).nL k = (w 0).nL k := fun r k hk =>
    (aL r).2.2 k (by have := P.hnm; simp only [Params.Nd] at hk; omega)
  set U : Finset F := (range P.Nd).image (w 0).nL ∪ (range 16).image (fun j : ℕ => (j : F))
  have hU0 : ∀ j : ℕ, j < 16 → (j : F) ∈ U := fun j hj =>
    mem_union_right _ (mem_image.2 ⟨j, mem_range.2 hj, rfl⟩)
  have hUL : ∀ k < P.Nd, (w 0).nL k ∈ U := fun k hk =>
    mem_union_left _ (mem_image.2 ⟨k, mem_range.2 hk, rfl⟩)
  have hcard : U.card ≤ P.Nd + 16 := (card_union_le _ _).trans
    (add_le_add (card_image_le.trans (by simp)) (card_image_le.trans (by simp)))
  -- At every `α`, set membership is a vanishing sum of simple poles, so every residue is zero.
  have hres : ∀ p ∈ U, residue37 P (w 0) p = 0 := by
    refine reciprocal_zero U _ (fun k => α (Fin.castLE hcard k))
      (hα.comp (Fin.castLE_injective _)) ?_ fun k => ?_
    · intro k p hp
      rcases mem_union.1 hp with hp | hp
      · obtain ⟨k', hk', rfl⟩ := mem_image.1 hp
        have := hH (Fin.castLE hcard k) k' (mem_range.1 hk')
        rw [hnL _ k' (mem_range.1 hk')] at this
        exact left_ne_zero_of_mul_eq_one this
      · obtain ⟨j, hj, rfl⟩ := mem_image.1 hp
        exact hpole _ j (mem_range.1 hj)
    · set r := Fin.castLE hcard k
      have hR : ∀ k' < P.Nd, (w r).nR k' = (α r + (w r).nL k')⁻¹ := fun k' hk' =>
        eq_inv_of_mul_eq_one_right (hH r k' hk')
      have e := rowS_partial P { ch with α := α r } (w r) (hpole r) hR U hU0
        fun k' hk' => by rw [hnL r k' hk']; exact hUL k' hk'
      rw [hS r] at e
      have e' := (mul_eq_zero.1 e.symm).resolve_left h2
      refine (sum_congr rfl fun p _ => ?_).trans e'
      rw [residue37_congr P (fun k hk => (aO r).2.2 k hk) (hnL r) p]
  -- A digit outside the table would have a nonzero residue: minus its multiplicity.
  intro k0 hk0
  by_contra hne
  push Not at hne
  have := hres _ (hUL k0 hk0)
  have hz1 : (if (w 0).nL k0 = 0 then (P.Nd : F) else 0) = 0 :=
    if_neg fun h => hne 0 (by norm_num) (by simpa using h)
  have hz2 : ∑ j ∈ range 15, (w 0).nO j * ((if (w 0).nL k0 = 0 then 1 else 0) -
      if (w 0).nL k0 = ((j + 1 : ℕ) : F) then 1 else 0) = 0 :=
    sum_eq_zero fun j hj => by
      rw [if_neg fun h => hne 0 (by norm_num) (by simpa using h),
        if_neg fun h => hne (j + 1) (by simp at hj; omega) h]
      ring
  simp only [residue37, hz1, hz2, zero_sub, sub_zero, neg_eq_zero] at this
  rw [sum_boole] at this
  refine hchar ((range P.Nd).filter fun k => (w 0).nL k = (w 0).nL k0).card
    (card_pos.2 ⟨k0, mem_filter.2 ⟨mem_range.2 hk0, rfl⟩⟩) ?_ this
  exact (card_filter_le _ _).trans (by simp)

end Extract

end Bppp.Spec
