-- THIS FILE IS AI-ONLY
import bulletproofspp.Spec.Honest

/-!
# Completeness

For an honest witness with blinding in the zero pattern (22), the solved `r_S` makes the error
polynomial (28) vanish identically, so the norm-linear relation (27) holds at every `τ`.

The proof has three steps: `r_S` enters `f(T)` linearly (`f_opening`); with `r_S = 0` the powers
of `f(T)` are in `T⁻², ..., T⁶` (`supp_g`) and its `T³` coefficient, the value row (29), vanishes
(`coeff3_g`, `value_row`); and the entries of `r_S` cancel the remaining powers.
-/

open Finset LaurentPolynomial

namespace Bppp.Spec

variable {F : Type*} [Field F] (P : Params) (ch : Challenges F) (h : Honest F)

/-- `r_S` enters `f(T)` linearly, through `σ(T)` and `ℓ_1(T), ..., ℓ_7(T)`. -/
lemma f_opening (rS : ℕ → F) :
    f P ch (h.opening P ch rS) = f P ch (h.opening P ch 0) +
      (mono (-1) (rS 0) - ∑ s ∈ range 7, c P ch s * mono (-1) (rS (s + 1))) := by
  have hn : n P ch (h.opening P ch rS) = n P ch (h.opening P ch 0) := rfl
  rw [f, f, hn]
  simp only [σ, ℓ, Honest.opening, sum_range_succ, sum_range_zero]
  norm_num
  ring

/-- Proves `Supp g a b` for a sum of monomials with powers in `[a, b]`. -/
macro "supp_tac" : tactic =>
  `(tactic| repeat (first
    | apply Supp.add
    | apply Supp.sub
    | exact Supp.zero _ _
    | (apply Supp.mono <;> norm_num)))

lemma supp_normμ {v : ℕ → F[T;T⁻¹]} {a b : ℤ} (hv : ∀ k, Supp (v k) a b) :
    Supp (normμ P ch v) (a + a) (b + b) :=
  Supp.sum _ fun k _ =>
    ((Supp.mono _ le_rfl le_rfl).mul ((hv k).mul (hv k))).widen (by omega) (by omega)

lemma supp_pn (k : ℕ) : Supp (pn P ch k) 0 3 := by
  simp only [pn]; supp_tac

lemma supp_n (w : Opening F) (k : ℕ) : Supp (n P ch w k) (-1) 3 := by
  simp only [n, pn]; supp_tac

set_option maxHeartbeats 400000 in
variable {h} in
/-- With `r_S = 0`, the error polynomial has powers `T⁻², ..., T⁶` only. -/
lemma supp_g (hz : h.ZeroPattern) : Supp (f P ch (h.opening P ch 0)) (-2) 6 := by
  refine Supp.sub (Supp.sub ?_ ?_) ((supp_normμ P ch (supp_n P ch _)).widen le_rfl le_rfl)
  · refine Supp.add (Supp.add ?_ ?_) ?_
    · exact Supp.add ((supp_normμ P ch (supp_pn P ch)).widen
        (by norm_num) (by norm_num)) (Supp.mono _ (by norm_num) (by norm_num))
    · exact Supp.mono _ (by norm_num) (by norm_num)
    · simp only [Honest.opening]; supp_tac
  · simp only [sum_range_succ, sum_range_zero, c, ℓ, Honest.opening, clV, e]
    norm_num [add_mul, mul_add, mono_mul, hz.rO4, hz.rO7, hz.rL3, hz.rL6, hz.rL7, hz.rR2,
      hz.rR5, hz.rR6, hz.rR7]
    supp_tac

lemma mono_add (p : ℤ) (x y : F) : mono p (x + y) = mono p x + mono p y := by
  simp [mono, add_mul]

lemma coeff_mono_zero_mul (p : ℤ) (x : F) (g : F[T;T⁻¹]) :
    coeff p (mono 0 x * g) = x * coeff p g := by
  simp [mono, coeff_apply, ← smul_eq_C_mul]

lemma coeff3_sq (a b c d e : F) :
    coeff 3 ((mono (-1) a + mono 0 b + mono 1 c + mono 2 d + mono 3 e) *
      (mono (-1) a + mono 0 b + mono 1 c + mono 2 d + mono 3 e)) = 2 * (b * e + c * d) := by
  simp [add_mul, mul_add, mono_mul]; ring

lemma n_eq (w : Opening F) (k : ℕ) : n P ch w k =
    mono (-1) (w.nS k) + mono 0 (ch.δ * w.nO k + cnV P ch k) + mono 1 (w.nL k + cnR P ch k) +
      mono 2 (w.nR k + cnL P ch k) + mono 3 (w.nV k + ch.δ⁻¹ * cnO P ch k) := by
  simp only [n, pn, mono_add]; ring

lemma pn_eq (k : ℕ) : pn P ch k =
    mono (-1) 0 + mono 0 (cnV P ch k) + mono 1 (cnR P ch k) + mono 2 (cnL P ch k) +
      mono 3 (ch.δ⁻¹ * cnO P ch k) := by
  simp [pn]

lemma coeff3_normμ (v : ℕ → F[T;T⁻¹]) :
    coeff 3 (normμ P ch v) = ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * coeff 3 (v k * v k) := by
  simp [normμ, coeff_mono_zero_mul]

variable {h} in
lemma coeff3_g (hz : h.ZeroPattern) (hδ : ch.δ ≠ 0) :
    coeff 3 (f P ch (h.opening P ch 0)) = 2 * (lamAl P ch + muAm P ch) +
      (h.opening P ch 0).vhat - ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (2 *
        ((h.opening P ch 0).nO k * cnO P ch k + (h.opening P ch 0).nL k * (h.opening P ch 0).nR k +
          (h.opening P ch 0).nL k * cnL P ch k + cnR P ch k * (h.opening P ch 0).nR k)) := by
  have hcl : coeff 3 (∑ s ∈ range 8, c P ch s * ℓ ch (h.opening P ch 0) s) = 0 := by
    simp only [sum_range_succ, sum_range_zero, c, ℓ, Honest.opening, clV, e]
    norm_num [add_mul, mul_add, mono_mul, hz.rO4, hz.rO7, hz.rL3, hz.rL6, hz.rL7, hz.rR2,
      hz.rR5, hz.rR6, hz.rR7]
  simp only [f, σ, ps, map_sub, map_add, hcl, coeff3_normμ, n_eq, pn_eq, coeff3_sq, coeff_mono]
  norm_num
  have hnV : ∀ k, (h.opening P ch 0).nV k = 0 := fun _ => rfl
  have hsum : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (2 * (cnV P ch k * (ch.δ⁻¹ * cnO P ch k) +
      cnR P ch k * cnL P ch k)) - ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (2 *
      ((ch.δ * (h.opening P ch 0).nO k + cnV P ch k) *
        ((h.opening P ch 0).nV k + ch.δ⁻¹ * cnO P ch k) +
      ((h.opening P ch 0).nL k + cnR P ch k) * ((h.opening P ch 0).nR k + cnL P ch k))) +
      ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (2 *
        ((h.opening P ch 0).nO k * cnO P ch k + (h.opening P ch 0).nL k * (h.opening P ch 0).nR k +
          (h.opening P ch 0).nL k * cnL P ch k + cnR P ch k * (h.opening P ch 0).nR k)) = 0 := by
    rw [← sum_sub_distrib, ← sum_add_distrib]
    refine sum_eq_zero fun k _ => ?_
    rw [hnV]
    field_simp
    ring
  linear_combination hsum

/-! ## The value row for an honest witness -/

lemma sum_range_mul_div_mod (M D : ℕ) (φ : ℕ → ℕ → F) :
    ∑ k ∈ range (M * D), φ (k / D) (k % D) = ∑ i ∈ range M, ∑ t ∈ range D, φ i t := by
  induction M with
  | zero => simp
  | succ M ih =>
    rw [Nat.succ_mul, sum_range_add, ih, sum_range_succ]
    congr 1
    refine sum_congr rfl fun t ht => ?_
    have ht : t < D := mem_range.mp ht
    rw [show M * D + t = t + M * D by ring, Nat.add_mul_div_right _ _ (by omega),
      Nat.add_mul_mod_self_right, Nat.div_eq_of_lt ht, Nat.mod_eq_of_lt ht, zero_add]

omit [Field F] in
variable {P h} in
lemma dig_lt (hd : ∀ i < P.M, ∀ t < P.D, h.d i t < 16) (k : ℕ) : h.dig P k < 16 := by
  unfold Honest.dig
  split_ifs with hk
  · have hD : 0 < P.D := Nat.pos_of_ne_zero fun h0 => by simp [Params.Nd, h0] at hk
    exact hd _ (Nat.div_lt_of_lt_mul (by rw [mul_comm]; exact hk)) _ (Nat.mod_lt _ hD)
  · norm_num

/-- `Σ_{k<N_d} (α+d_k)⁻¹ + Σ_{j=1}^{15} j m_j/(α(α+j)) = N_d/α`, the set-membership row (6). -/
lemma set_membership (hα : ∀ j : ℕ, j < 16 → ch.α + j ≠ 0)
    (hd : ∀ i < P.M, ∀ t < P.D, h.d i t < 16) :
    ∑ k ∈ range P.Nd, (ch.α + h.dig P k)⁻¹ +
      ∑ j ∈ range 15, (h.mult P (j + 1) : F) * ((j + 1) / (ch.α * (ch.α + (j + 1)))) =
      P.Nd / ch.α := by
  have hmaps : ∀ k ∈ range P.Nd, h.dig P k ∈ range 16 := fun k _ => mem_range.mpr (dig_lt hd k)
  have hR : ∑ k ∈ range P.Nd, (ch.α + h.dig P k)⁻¹ =
      ∑ j ∈ range 16, (h.mult P j : F) * (ch.α + j)⁻¹ := by
    rw [← sum_fiberwise_of_maps_to hmaps]
    refine sum_congr rfl fun j _ => ?_
    rw [sum_congr rfl fun k hk => by rw [(mem_filter.mp hk).2], sum_const, nsmul_eq_mul]
    rfl
  have hN : P.Nd = ∑ j ∈ range 16, h.mult P j := by
    have := card_eq_sum_card_fiberwise hmaps
    rw [card_range] at this
    exact this
  have hA : ∑ j ∈ range 15, (h.mult P (j + 1) : F) * ((j + 1) / (ch.α * (ch.α + (j + 1)))) =
      ∑ j ∈ range 16, (h.mult P j : F) * (j / (ch.α * (ch.α + j))) := by
    rw [sum_range_succ' _ 15]; simp
  have hα0 : ch.α ≠ 0 := by simpa using hα 0 (by norm_num)
  rw [hR, hA, hN, Nat.cast_sum, sum_div, ← sum_add_distrib]
  refine sum_congr rfl fun j hj => ?_
  have := hα j (mem_range.mp hj)
  field_simp

lemma sum_range_of_le {m N : ℕ} (hmN : m ≤ N) {φ : ℕ → F} (hφ : ∀ k, m ≤ k → φ k = 0) :
    ∑ k ∈ range N, φ k = ∑ k ∈ range m, φ k :=
  (sum_subset (range_subset_range.mpr hmN) fun k _ hk => hφ k (by simpa using hk)).symm

/-- The value row (29) vanishes for an honest witness. -/
lemma value_row (hα : ∀ j : ℕ, j < 16 → ch.α + j ≠ 0) (hμ : ch.μ ≠ 0)
    (hd : ∀ i < P.M, ∀ t < P.D, h.d i t < 16) :
    2 * (lamAl P ch + muAm P ch) + (h.opening P ch 0).vhat - ∑ k ∈ range P.nm, ch.μ ^ (k + 1) *
      (2 * ((h.opening P ch 0).nO k * cnO P ch k +
        (h.opening P ch 0).nL k * (h.opening P ch 0).nR k +
        (h.opening P ch 0).nL k * cnL P ch k + cnR P ch k * (h.opening P ch 0).nR k)) = 0 := by
  have hα0 : ch.α ≠ 0 := by simpa using hα 0 (by norm_num)
  have hD : ∀ k, k < P.Nd → 0 < P.D := fun k hk =>
    Nat.pos_of_ne_zero fun h0 => by simp [Params.Nd, h0] at hk
  -- The multiplicity terms.
  have hO : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * ((h.opening P ch 0).nO k * cnO P ch k) =
      ch.lam ^ P.M * ∑ j ∈ range 15,
        (h.mult P (j + 1) : F) * ((j + 1) / (ch.α * (ch.α + (j + 1)))) := by
    rw [sum_range_of_le P.h15 fun k hk => by simp [Honest.opening, cnO]; omega, mul_sum]
    refine sum_congr rfl fun k hk => ?_
    have hk := mem_range.mp hk
    have := hα (k + 1) (by omega); push_cast at this
    simp only [Honest.opening, cnO, if_pos hk, if_pos (show k ≤ 14 by omega)]
    field_simp
  -- The Hadamard terms.
  have hLR : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * ((h.opening P ch 0).nL k *
      (h.opening P ch 0).nR k + cnR P ch k * (h.opening P ch 0).nR k) =
      muAm P ch + ch.lam ^ P.M * ∑ k ∈ range P.Nd, (ch.α + h.dig P k)⁻¹ := by
    rw [sum_range_of_le (m := P.Nd) P.hnm fun k hk => by
      have : ¬ k < P.Nd := by omega
      simp [Honest.opening, Honest.dig, cnR, this], muAm, mul_sum,
      ← sum_add_distrib]
    refine sum_congr rfl fun k hk => ?_
    have hk := mem_range.mp hk
    have := hα _ (dig_lt hd k)
    simp only [Honest.opening, cnR, if_pos hk]
    field_simp
    ring
  -- The value-link terms.
  have hL : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * ((h.opening P ch 0).nL k * cnL P ch k) =
      ∑ i ∈ range P.M, ch.lam ^ i * h.value P i := by
    rw [sum_range_of_le (m := P.Nd) P.hnm fun k hk => by simp [cnL]; omega]
    rw [sum_congr rfl fun k hk => show ch.μ ^ (k + 1) * ((h.opening P ch 0).nL k * cnL P ch k) =
        ch.lam ^ (k / P.D) * (16 ^ (k % P.D) * h.d (k / P.D) (k % P.D)) by
      have hk := mem_range.mp hk
      simp only [Honest.opening, Honest.dig, cnL, if_pos hk]
      field_simp]
    rw [show P.Nd = P.M * P.D from rfl, sum_range_mul_div_mod P.M P.D fun i t => ch.lam ^ i * (16 ^ t * h.d i t)]
    simp [Honest.value, mul_sum]
  have hsm := set_membership P ch h hα hd
  have hsplit : ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (2 * ((h.opening P ch 0).nO k * cnO P ch k +
      (h.opening P ch 0).nL k * (h.opening P ch 0).nR k + (h.opening P ch 0).nL k * cnL P ch k +
      cnR P ch k * (h.opening P ch 0).nR k)) =
      2 * (∑ k ∈ range P.nm, ch.μ ^ (k + 1) * ((h.opening P ch 0).nO k * cnO P ch k) +
        ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * ((h.opening P ch 0).nL k *
          (h.opening P ch 0).nR k + cnR P ch k * (h.opening P ch 0).nR k) +
        ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * ((h.opening P ch 0).nL k * cnL P ch k)) := by
    rw [← sum_add_distrib, ← sum_add_distrib, mul_sum]
    exact sum_congr rfl fun k _ => by ring
  rw [hsplit, hO, hLR, hL, lamAl, show (h.opening P ch 0).vhat =
    2 * ∑ i ∈ range P.M, ch.lam ^ i * h.value P i from rfl]
  linear_combination (-2 * ch.lam ^ P.M) * hsm

/-! ## Completeness -/

/-- **Completeness.** For an honest witness, blinding with the zero pattern (22) and the solved
`r_S`, the error polynomial (28) vanishes identically, so the norm-linear relation (27) holds at
every `τ`. -/
lemma completeness (hα : ∀ j : ℕ, j < 16 → ch.α + j ≠ 0) (hβ : ch.β ≠ 0) (hδ : ch.δ ≠ 0)
    (hμ : ch.μ ≠ 0) (hd : ∀ i < P.M, ∀ t < P.D, h.d i t < 16) (hz : h.ZeroPattern) :
    f P ch (h.opening P ch (h.rS P ch)) = 0 := by
  have hg3 : coeff 3 (f P ch (h.opening P ch 0)) = 0 := by
    rw [coeff3_g P ch hz hδ]; exact value_row P ch h hα hμ hd
  have hg := supp_g P ch hz
  rw [f_opening]
  refine ext_coeff fun p => ?_
  have hout : p < -2 ∨ 6 < p → coeff p (f P ch (h.opening P ch 0)) = 0 := fun hp =>
    by_contra fun h0 => by have := hg p h0; omega
  simp only [map_add, map_sub, map_zero, sum_range_succ, sum_range_zero, c, e, clV,
    Honest.rS, add_mul, mono_mul, coeff_mono]
  norm_num [mono_mul]
  by_cases hp : p < -2 ∨ 6 < p
  · rw [hout hp]
    simp [show (-2 : ℤ) ≠ p by omega, show (-1 : ℤ) ≠ p by omega, show (0 : ℤ) ≠ p by omega,
      show (1 : ℤ) ≠ p by omega, show (2 : ℤ) ≠ p by omega, show (4 : ℤ) ≠ p by omega,
      show (5 : ℤ) ≠ p by omega, show (6 : ℤ) ≠ p by omega]
  rcases (by omega : p = -2 ∨ p = -1 ∨ p = 0 ∨ p = 1 ∨ p = 2 ∨ p = 3 ∨ p = 4 ∨ p = 5 ∨ p = 6)
    with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals simp [hg3]
  all_goals rw [mul_div_cancel₀ _ hβ]; ring
