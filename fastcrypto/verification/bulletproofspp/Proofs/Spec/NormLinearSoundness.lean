-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Spec.NormLinearCompleteness
import bulletproofspp.Proofs.Spec.Interpolation

/-!
# Special soundness of the norm-linear argument

From openings of the folded commitment for four distinct `γ`, either the commitment of the round
opens to a witness of the relation (19), or the generators satisfy a nontrivial linear relation
(`extract_round`). This is the row `γ` of Table 1 of the paper.

The norm vector must have even length, as it does in `norm_linear.rs`; the linear vector may be
padded.
-/

open Finset

namespace Bppp.Spec.NormLinear

variable {F E : Type*} [Field F] [AddCommGroup E] [Module F E]
variable (g : E)

/-- The point `s g + <h, H> + <n, G>` over the generators of `x`. -/
def pt (x : Instance F E) (s : F) (h n : ℕ → F) : E := s • g + msm x.Lℓ h x.H + msm x.Ln n x.G

/-- A nontrivial linear relation among the generators `g`, `H_0, ...` and `G_0, ...` of `x`. -/
def Relation (x : Instance F E) : Prop :=
  ∃ (s : F) (h n : ℕ → F), (s ≠ 0 ∨ (∃ j < x.Lℓ, h j ≠ 0) ∨ (∃ j < x.Ln, n j ≠ 0)) ∧
    pt g x s h n = 0

/-- The coordinates over `H` of an opening `ℓ` over the folded `H' = [H]₀ + γ[H]₁`. -/
def unH (γ : F) (ℓ : ℕ → F) : ℕ → F := fun j => if j % 2 = 0 then ℓ (j / 2) else γ * ℓ (j / 2)

/-- The coordinates over `G` of an opening `n` over the folded `G' = ρ[G]₀ + γ[G]₁`. -/
def unG (ρ γ : F) (n : ℕ → F) : ℕ → F := fun j => if j % 2 = 0 then ρ * n (j / 2) else γ * n (j / 2)

@[simp] lemma unH_even (γ : F) (ℓ : ℕ → F) (i : ℕ) : unH γ ℓ (2 * i) = ℓ i := by
  simp [unH]

@[simp] lemma unH_odd (γ : F) (ℓ : ℕ → F) (i : ℕ) : unH γ ℓ (2 * i + 1) = γ * ℓ i := by
  rw [unH, if_neg (by omega), show (2 * i + 1) / 2 = i by omega]

@[simp] lemma unG_even (ρ γ : F) (n : ℕ → F) (i : ℕ) : unG ρ γ n (2 * i) = ρ * n i := by
  simp [unG]

@[simp] lemma unG_odd (ρ γ : F) (n : ℕ → F) (i : ℕ) : unG ρ γ n (2 * i + 1) = γ * n i := by
  rw [unG, if_neg (by omega), show (2 * i + 1) / 2 = i by omega]

lemma msm_unH (L : ℕ) (γ : F) (ℓ : ℕ → F) (H : ℕ → E) :
    msm (half L) ℓ (fun i => ev L H i + γ • od L H i) = msm L (unH γ ℓ) H := by
  rw [msm, msm, sum_split L]
  refine sum_congr rfl fun i hi => ?_
  have h2 : 2 * i < L := by simp only [mem_range, half] at hi; omega
  simp only [ev, od, pad, unH_even, unH_odd, if_pos h2, smul_add, smul_smul]
  split_ifs <;> simp [mul_comm]

lemma msm_unG (L : ℕ) (ρ γ : F) (n : ℕ → F) (G : ℕ → E) :
    msm (half L) n (fun i => ρ • ev L G i + γ • od L G i) = msm L (unG ρ γ n) G := by
  rw [msm, msm, sum_split L]
  refine sum_congr rfl fun i hi => ?_
  have h2 : 2 * i < L := by simp only [mem_range, half] at hi; omega
  simp only [ev, od, pad, unG_even, unG_odd, if_pos h2, smul_add, smul_smul]
  split_ifs <;> simp [mul_comm]

/-- An opening of a folded instance is an opening of the round's combination. -/
lemma fold_pt (x : Instance F E) (X R : E) (γ : F) (w : Witness F)
    (h : Rel g (foldInst x X R γ) w) :
    x.C + γ • X + (γ ^ 2 - 1) • R = pt g x
      (ip (half x.Lℓ) (foldInst x X R γ).c w.ℓ + wip (half x.Ln) (x.μ ^ 2) w.n w.n)
      (unH γ w.ℓ) (unG x.ρ γ w.n) := by
  rw [pt, ← msm_unH, ← msm_unG]
  exact h

lemma pt_add (x : Instance F E) (s s' : F) (h h' n n' : ℕ → F) :
    pt g x (s + s') (fun j => h j + h' j) (fun j => n j + n' j) = pt g x s h n + pt g x s' h' n' := by
  simp only [pt, msm, add_smul, sum_add_distrib]; abel

lemma pt_smul (x : Instance F E) (a s : F) (h n : ℕ → F) :
    pt g x (a * s) (fun j => a * h j) (fun j => a * n j) = a • pt g x s h n := by
  simp only [pt, msm, mul_smul, smul_add, smul_sum]

lemma pt_sum (x : Instance F E) {ι : Type*} (S : Finset ι) (a : ι → F) (s : ι → F)
    (h n : ι → ℕ → F) :
    pt g x (∑ m ∈ S, a m * s m) (fun j => ∑ m ∈ S, a m * h m j) (fun j => ∑ m ∈ S, a m * n m j) =
      ∑ m ∈ S, a m • pt g x (s m) (h m) (n m) := by
  simp only [pt, msm, sum_smul, smul_add, sum_add_distrib, smul_sum, mul_smul]
  rw [sum_comm (s := range x.Lℓ), sum_comm (s := range x.Ln)]

lemma pt_sub (x : Instance F E) (s s' : F) (h h' n n' : ℕ → F) :
    pt g x (s - s') (fun j => h j - h' j) (fun j => n j - n' j) = pt g x s h n - pt g x s' h' n' := by
  simp only [pt, msm, sub_smul, sum_sub_distrib]; abel

lemma comb3 {ι : Type*} (S : Finset ι) (a t : ι → F) (C X R : E) :
    ∑ m ∈ S, a m • (C + t m • X + (t m ^ 2 - 1) • R) =
      (∑ m ∈ S, a m) • C + (∑ m ∈ S, a m * t m) • X + (∑ m ∈ S, a m * (t m ^ 2 - 1)) • R := by
  simp only [smul_add, sum_add_distrib, sum_smul, smul_smul]

lemma sum_quad {ι : Type*} (S : Finset ι) (a b c : ι → F) (t : F) :
    ∑ i ∈ S, (a i + t * b i + t ^ 2 * c i) = ∑ i ∈ S, a i + t * ∑ i ∈ S, b i + t ^ 2 * ∑ i ∈ S, c i := by
  simp only [sum_add_distrib, mul_sum]

/-- The weights `(1, γ, γ² - 1)` of `C`, `X`, `R` in the round's combination. -/
def coef (γ : F) : Fin 3 → F := ![1, γ, γ ^ 2 - 1]

lemma sum_coef (γ : F) (f : Fin 3 → F) :
    ∑ b, coef γ b * f b = f 0 + γ * f 1 + (γ ^ 2 - 1) * f 2 := by
  simp [coef, Fin.sum_univ_three]

/-- Interpolating from `γ_0, γ_1, γ_2` and evaluating at `γ_k` returns the value at `γ_k`. -/
lemma interp {t0 t1 t2 : F} (h01 : t0 ≠ t1) (h02 : t0 ≠ t2) (h12 : t1 ≠ t2) (f : Fin 3 → F)
    (k : Fin 3) :
    ∑ b, coef (![t0, t1, t2] k) b * ∑ m, lam t0 t1 t2 b m * f m = f k := by
  simp only [mul_sum, ← mul_assoc]
  rw [sum_comm]
  have := fun m => lam_kron h01 h02 h12 k m
  simp only [← sum_mul, sum_coef]
  simp only [this, ite_mul, one_mul, zero_mul, sum_ite_eq, mem_univ, if_true]

/-- **One round of extraction.** From openings of the folded instance for four distinct
challenges, either the round's instance opens to a witness, or its generators satisfy a nontrivial
linear relation. -/
lemma extract_round (x : Instance F E) (X R : E) (γ : Fin 4 → F) (hγ : Function.Injective γ)
    (hρ : x.ρ ≠ 0) (hμ : x.μ = x.ρ ^ 2) (hn : x.Ln % 2 = 0) (w : Fin 4 → Witness F)
    (h : ∀ k, Rel g (foldInst x X R (γ k)) (w k)) :
    (∃ w, Rel g x w) ∨ Relation g x := by
  set σ : Fin 4 → F := fun k => ip (half x.Lℓ) (foldInst x X R (γ k)).c (w k).ℓ +
    wip (half x.Ln) (x.μ ^ 2) (w k).n (w k).n
  set hh : Fin 4 → ℕ → F := fun k => unH (γ k) (w k).ℓ
  set nn : Fin 4 → ℕ → F := fun k => unG x.ρ (γ k) (w k).n
  have hV : ∀ k, x.C + γ k • X + (γ k ^ 2 - 1) • R = pt g x (σ k) (hh k) (nn k) :=
    fun k => fold_pt g x X R (γ k) (w k) (h k)
  have hne : ∀ i j : Fin 4, i ≠ j → γ i ≠ γ j := fun i j hij e => hij (hγ e)
  have h01 := hne 0 1 (by decide); have h02 := hne 0 2 (by decide)
  have h12 := hne 1 2 (by decide)
  set lw := lam (γ 0) (γ 1) (γ 2)
  have ht : ∀ m : Fin 3, ![γ 0, γ 1, γ 2] m = γ m.castSucc := by intro m; fin_cases m <;> rfl
  -- The openings of `C`, `X`, `R` (`b = 0, 1, 2`), interpolated from `γ_0, γ_1, γ_2`.
  set cs : Fin 3 → F := fun b => ∑ m, lw b m * σ m.castSucc
  set ch : Fin 3 → ℕ → F := fun b j => ∑ m, lw b m * hh m.castSucc j
  set cn : Fin 3 → ℕ → F := fun b j => ∑ m, lw b m * nn m.castSucc j
  have hpt : ∀ b, pt g x (cs b) (ch b) (cn b) =
      (if b = 0 then (1 : F) else 0) • x.C + (if b = 1 then (1 : F) else 0) • X +
        (if b = 2 then (1 : F) else 0) • R := fun b => by
    rw [pt_sum]
    simp_rw [← hV]
    rw [comb3]
    obtain ⟨d0, d1, d2⟩ := lam_dual h01 h02 h12 b
    simp only [← ht]
    rw [d0, d1, d2]
  -- The opening of the combination at any `γ`.
  set us : F → F := fun t => ∑ b, coef t b * cs b
  set uh : F → ℕ → F := fun t j => ∑ b, coef t b * ch b j
  set un : F → ℕ → F := fun t j => ∑ b, coef t b * cn b j
  have hupt : ∀ t, pt g x (us t) (uh t) (un t) = x.C + t • X + (t ^ 2 - 1) • R := fun t => by
    rw [pt_sum]
    simp only [hpt, Fin.sum_univ_three, coef]
    simp
  -- It agrees with the given openings at `γ_0, γ_1, γ_2`.
  have hint : ∀ m : Fin 3, us (γ m.castSucc) = σ m.castSucc ∧
      (∀ j, uh (γ m.castSucc) j = hh m.castSucc j) ∧ (∀ j, un (γ m.castSucc) j = nn m.castSucc j) :=
    fun m => by
      refine ⟨?_, fun j => ?_, fun j => ?_⟩ <;> rw [← ht m] <;>
        exact interp h01 h02 h12 _ m
  -- At `γ_3`, either it agrees with the given opening, or their difference is a relation.
  by_cases heq : us (γ 3) = σ 3 ∧ (∀ j < x.Lℓ, uh (γ 3) j = hh 3 j) ∧
      (∀ j < x.Ln, un (γ 3) j = nn 3 j)
  swap
  · right
    refine ⟨us (γ 3) - σ 3, fun j => uh (γ 3) j - hh 3 j, fun j => un (γ 3) j - nn 3 j, ?_, ?_⟩
    · by_contra hc
      push Not at hc
      exact heq ⟨sub_eq_zero.1 hc.1, fun j hj => sub_eq_zero.1 (hc.2.1 j hj),
        fun j hj => sub_eq_zero.1 (hc.2.2 j hj)⟩
    · rw [pt_sub, hupt, ← hV, sub_self]
  left
  obtain ⟨hs3, hh3, hn3⟩ := heq
  -- At all four challenges, on the generators' range.
  have hall : ∀ k : Fin 4, us (γ k) = σ k ∧ (∀ j < x.Lℓ, uh (γ k) j = hh k j) ∧
      (∀ j < x.Ln, un (γ k) j = nn k j) := by
    intro k
    by_cases hk : k = 3
    · subst hk; exact ⟨hs3, hh3, hn3⟩
    · obtain ⟨m, rfl⟩ : ∃ m : Fin 3, m.castSucc = k := ⟨⟨k, by omega⟩, rfl⟩
      obtain ⟨a, b, c⟩ := hint m
      exact ⟨a, fun j _ => b j, fun j _ => c j⟩
  have huh : ∀ t j, uh t j = ch 0 j + t * ch 1 j + (t ^ 2 - 1) * ch 2 j := fun t j => sum_coef _ _
  have hun : ∀ t j, un t j = cn 0 j + t * cn 1 j + (t ^ 2 - 1) * cn 2 j := fun t j => sum_coef _ _
  have hus : ∀ t, us t = cs 0 + t * cs 1 + (t ^ 2 - 1) * cs 2 := fun t => sum_coef _ _
  -- The pairs of coordinates over `H` and `G` are tied as the fold ties them.
  have hH : ∀ i, 2 * i + 1 < x.Lℓ → ch 2 (2 * i) = 0 ∧ ch 0 (2 * i + 1) = ch 1 (2 * i) := by
    intro i hi
    have e : ∀ k, (ch 0 (2 * i + 1) - ch 2 (2 * i + 1)) +
        (ch 1 (2 * i + 1) - ch 0 (2 * i) + ch 2 (2 * i)) * γ k +
        (ch 2 (2 * i + 1) - ch 1 (2 * i)) * γ k ^ 2 + (-ch 2 (2 * i)) * γ k ^ 3 = 0 := by
      intro k
      have h1 := (hall k).2.1 (2 * i + 1) hi
      have h0 := (hall k).2.1 (2 * i) (by omega)
      simp only [hh, unH_odd, unH_even] at h1 h0
      rw [huh] at h1 h0
      linear_combination h1 - γ k * h0
    obtain ⟨a0, a1, a2, a3⟩ := cubic_zero γ hγ _ _ _ _ e
    exact ⟨by linear_combination -a3, by linear_combination a0 + a2⟩
  have hG : ∀ i, 2 * i + 1 < x.Ln → cn 2 (2 * i) = 0 ∧ cn 1 (2 * i) = x.ρ * cn 0 (2 * i + 1) := by
    intro i hi
    have e : ∀ k, x.ρ * (cn 0 (2 * i + 1) - cn 2 (2 * i + 1)) +
        (x.ρ * cn 1 (2 * i + 1) - cn 0 (2 * i) + cn 2 (2 * i)) * γ k +
        (x.ρ * cn 2 (2 * i + 1) - cn 1 (2 * i)) * γ k ^ 2 + (-cn 2 (2 * i)) * γ k ^ 3 = 0 := by
      intro k
      have h1 := (hall k).2.2 (2 * i + 1) hi
      have h0 := (hall k).2.2 (2 * i) (by omega)
      simp only [nn, unG_odd, unG_even] at h1 h0
      rw [hun] at h1 h0
      linear_combination x.ρ * h1 - γ k * h0
    obtain ⟨a0, a1, a2, a3⟩ := cubic_zero γ hγ _ _ _ _ e
    exact ⟨by linear_combination -a3, by linear_combination -a2 - a0⟩
  -- On a padded last pair of `H`, `[c]₁` is zero.
  have hpad : ∀ i, i < half x.Lℓ → od x.Lℓ x.c i * ch 2 (2 * i) = 0 := by
    intro i _
    by_cases hi : 2 * i + 1 < x.Lℓ
    · rw [(hH i hi).1, mul_zero]
    · simp [od, pad, hi]
  -- The relation at each challenge is a quadratic in it, which vanishes at three points.
  set e : ℕ → F := ev x.Lℓ x.c
  set o : ℕ → F := od x.Lℓ x.c
  set W : ℕ → F := fun i => (x.μ ^ 2) ^ (i + 1)
  set p0 := (cs 0 - cs 2) - ∑ i ∈ range (half x.Lℓ), e i * (ch 0 (2 * i) - ch 2 (2 * i)) -
    ∑ i ∈ range (half x.Ln), W i * (cn 0 (2 * i) ^ 2 / x.ρ ^ 2)
  set p1 := cs 1 - ∑ i ∈ range (half x.Lℓ),
      (e i * ch 1 (2 * i) + o i * (ch 0 (2 * i) - ch 2 (2 * i))) -
    ∑ i ∈ range (half x.Ln), W i * (2 * cn 0 (2 * i) * cn 1 (2 * i) / x.ρ ^ 2)
  set p2 := cs 2 - ∑ i ∈ range (half x.Lℓ), (e i * ch 2 (2 * i) + o i * ch 1 (2 * i)) -
    ∑ i ∈ range (half x.Ln), W i * (cn 1 (2 * i) ^ 2 / x.ρ ^ 2)
  have hq : ∀ m : Fin 3, p0 + p1 * γ m.castSucc + p2 * γ m.castSucc ^ 2 = 0 := by
    intro m
    have hl : ∀ i ∈ range (half x.Lℓ), (w m.castSucc).ℓ i = uh (γ m.castSucc) (2 * i) :=
      fun i hi => by
        have := (hall m.castSucc).2.1 (2 * i) (by simp only [mem_range, half] at hi; omega)
        simp only [hh, unH_even] at this; exact this.symm
    have hnv : ∀ i ∈ range (half x.Ln), (w m.castSucc).n i = un (γ m.castSucc) (2 * i) / x.ρ :=
      fun i hi => by
        have := (hall m.castSucc).2.2 (2 * i) (by simp only [mem_range, half] at hi; omega)
        simp only [nn, unG_even] at this; rw [this]; field_simp
    have hσ : us (γ m.castSucc) = σ m.castSucc := (hall m.castSucc).1
    simp only [σ, ip, wip, foldInst] at hσ
    have s1 : ∑ i ∈ range (half x.Lℓ), (ev x.Lℓ x.c i + γ m.castSucc * od x.Lℓ x.c i) *
        (w m.castSucc).ℓ i = ∑ i ∈ range (half x.Lℓ), (ev x.Lℓ x.c i + γ m.castSucc *
          od x.Lℓ x.c i) * uh (γ m.castSucc) (2 * i) := sum_congr rfl fun i hi => by rw [hl i hi]
    have s2 : ∑ i ∈ range (half x.Ln), (x.μ ^ 2) ^ (i + 1) * ((w m.castSucc).n i *
        (w m.castSucc).n i) = ∑ i ∈ range (half x.Ln), (x.μ ^ 2) ^ (i + 1) *
          (un (γ m.castSucc) (2 * i) / x.ρ * (un (γ m.castSucc) (2 * i) / x.ρ)) :=
      sum_congr rfl fun i hi => by rw [hnv i hi]
    rw [s1, s2] at hσ
    have h1 : ∀ i ∈ range (half x.Lℓ), (ev x.Lℓ x.c i + γ m.castSucc * od x.Lℓ x.c i) *
        uh (γ m.castSucc) (2 * i) = e i * (ch 0 (2 * i) - ch 2 (2 * i)) +
        γ m.castSucc * (e i * ch 1 (2 * i) + o i * (ch 0 (2 * i) - ch 2 (2 * i))) +
        γ m.castSucc ^ 2 * (e i * ch 2 (2 * i) + o i * ch 1 (2 * i)) := fun i hi => by
      rw [huh]; have := hpad i (mem_range.1 hi); linear_combination γ m.castSucc ^ 3 * this
    have h2 : ∀ i ∈ range (half x.Ln), (x.μ ^ 2) ^ (i + 1) * (un (γ m.castSucc) (2 * i) / x.ρ *
        (un (γ m.castSucc) (2 * i) / x.ρ)) = W i * (cn 0 (2 * i) ^ 2 / x.ρ ^ 2) +
        γ m.castSucc * (W i * (2 * cn 0 (2 * i) * cn 1 (2 * i) / x.ρ ^ 2)) +
        γ m.castSucc ^ 2 * (W i * (cn 1 (2 * i) ^ 2 / x.ρ ^ 2)) := fun i hi => by
      rw [hun, (hG i (by simp only [mem_range, half] at hi; omega)).1]
      simp only [W]; field_simp; ring
    rw [sum_congr rfl h1, sum_congr rfl h2, sum_quad, sum_quad, hus] at hσ
    linear_combination hσ
  obtain ⟨q0, -, q2⟩ := quadratic_zero (fun m : Fin 3 => γ m.castSucc)
    (hγ.comp (Fin.castSucc_injective 3)) p0 p1 p2 hq
  -- The interpolated opening of `C` satisfies the relation.
  refine ⟨⟨ch 0, cn 0⟩, ?_⟩
  have hC := hpt 0
  simp only [if_true, one_smul, show (0 : Fin 3) ≠ 1 from by decide,
    show (0 : Fin 3) ≠ 2 from by decide, if_false, zero_smul, add_zero] at hC
  rw [Rel, ← hC, pt]
  suffices hs : cs 0 = ip x.Lℓ x.c (ch 0) + wip x.Ln x.μ (cn 0) (cn 0) by rw [hs]
  rw [ip_split, wip_split x.Ln hρ hμ]
  have hip : ip (half x.Lℓ) (od x.Lℓ x.c) (od x.Lℓ (ch 0)) =
      ∑ i ∈ range (half x.Lℓ), o i * ch 1 (2 * i) := sum_congr rfl fun i hi => by
    by_cases h2 : 2 * i + 1 < x.Lℓ
    · simp only [od, pad, if_pos h2, (hH i h2).2, o]
    · simp [od, pad, h2, o]
  have hev : ip (half x.Lℓ) (ev x.Lℓ x.c) (ev x.Lℓ (ch 0)) =
      ∑ i ∈ range (half x.Lℓ), e i * ch 0 (2 * i) := sum_congr rfl fun i hi => by
    simp only [ev, pad, if_pos (show 2 * i < x.Lℓ by simp only [mem_range, half] at hi; omega), e]
  have hw0 : wip (half x.Ln) (x.μ ^ 2) (fun i => x.ρ⁻¹ * ev x.Ln (cn 0) i)
      (fun i => x.ρ⁻¹ * ev x.Ln (cn 0) i) = ∑ i ∈ range (half x.Ln), W i * (cn 0 (2 * i) ^ 2 / x.ρ ^ 2) :=
    sum_congr rfl fun i hi => by
      simp only [ev, pad, if_pos (show 2 * i < x.Ln by simp only [mem_range, half] at hi; omega), W]
      field_simp
  have hw1 : wip (half x.Ln) (x.μ ^ 2) (od x.Ln (cn 0)) (od x.Ln (cn 0)) =
      ∑ i ∈ range (half x.Ln), W i * (cn 1 (2 * i) ^ 2 / x.ρ ^ 2) := sum_congr rfl fun i hi => by
    have h2 : 2 * i + 1 < x.Ln := by simp only [mem_range, half] at hi; omega
    simp only [od, pad, if_pos h2, W, (hG i h2).2]
    field_simp
  have hcomb : ∑ i ∈ range (half x.Lℓ), e i * (ch 0 (2 * i) - ch 2 (2 * i)) +
      ∑ i ∈ range (half x.Lℓ), (e i * ch 2 (2 * i) + o i * ch 1 (2 * i)) =
      ∑ i ∈ range (half x.Lℓ), e i * ch 0 (2 * i) + ∑ i ∈ range (half x.Lℓ), o i * ch 1 (2 * i) := by
    rw [← sum_add_distrib, ← sum_add_distrib]; exact sum_congr rfl fun i _ => by ring
  rw [hip, hev, hw0, hw1]
  linear_combination q0 + q2 + hcomb

/-- A relation among the folded generators is a relation among the round's generators. -/
lemma relation_unfold (x : Instance F E) (X R : E) (γ : F) (hρ : x.ρ ≠ 0)
    (h : Relation g (foldInst x X R γ)) : Relation g x := by
  obtain ⟨s, h', n', hnt, hz⟩ := h
  refine ⟨s, unH γ h', unG x.ρ γ n', ?_, ?_⟩
  · rcases hnt with hs | ⟨j, hj, hh⟩ | ⟨j, hj, hn⟩
    · exact Or.inl hs
    · refine Or.inr (Or.inl ⟨2 * j, ?_, by rwa [unH_even]⟩)
      simp only [foldInst, half] at hj; omega
    · refine Or.inr (Or.inr ⟨2 * j, ?_, by rw [unG_even]; exact mul_ne_zero hρ hn⟩)
      simp only [foldInst, half] at hj; omega
  · rw [pt, ← msm_unH, ← msm_unG]; exact hz

variable (F E) in
/-- A tree of transcripts of the interactive norm-linear argument: in each round the prover's
messages `X`, `R` and, for four challenges, the rest of the transcript; at the end the opening
sent in the clear. -/
inductive Tree
  | leaf (w : Witness F)
  | node (X R : E) (γ : Fin 4 → F) (child : Fin 4 → Tree)

/-- The tree has `d` rounds along every branch. -/
inductive Tree.Depth : Tree F E → ℕ → Prop
  | leaf (w : Witness F) : Depth (.leaf w) 0
  | node (X R : E) (γ : Fin 4 → F) (child : Fin 4 → Tree F E) (d : ℕ)
      (h : ∀ k, Depth (child k) d) : Depth (.node X R γ child) (d + 1)

/-- Every transcript of the tree is accepted, and the challenges of each round are distinct. -/
def Accepts : Instance F E → Tree F E → Prop
  | x, .leaf w => Rel g x w
  | x, .node X R γ child => Function.Injective γ ∧ ∀ k, Accepts (foldInst x X R (γ k)) (child k)

/-- **Special soundness of the norm-linear argument.** From a tree of accepting transcripts with
four distinct challenges per round, either the commitment opens to a witness of the relation
(19), or the generators satisfy a nontrivial linear relation. -/
lemma extract : ∀ (t : Tree F E) (d : ℕ) (x : Instance F E), t.Depth d → 2 ^ d ∣ x.Ln →
    x.ρ ≠ 0 → x.μ = x.ρ ^ 2 → Accepts g x t → (∃ w, Rel g x w) ∨ Relation g x
  | .leaf w, _, x, _, _, _, _, h => Or.inl ⟨w, h⟩
  | .node X R γ child, _, x, .node _ _ _ _ d hd, hL, hρ, hμ, ⟨hγ, h⟩ => by
    have hn : x.Ln % 2 = 0 := by
      obtain ⟨q, hq⟩ := hL; rw [hq, pow_succ]; simp [Nat.mul_mod, Nat.mul_assoc]
    have hρ' : x.μ ≠ 0 := by rw [hμ]; exact pow_ne_zero 2 hρ
    have hL' : 2 ^ d ∣ (foldInst x X R (γ 0)).Ln := by
      obtain ⟨q, hq⟩ := hL
      refine ⟨q, ?_⟩
      simp only [foldInst, half, hq, pow_succ]
      rw [show 2 ^ d * 2 * q = 2 * (2 ^ d * q) by ring]; omega
    have ih : ∀ k, (∃ w, Rel g (foldInst x X R (γ k)) w) ∨ Relation g (foldInst x X R (γ k)) :=
      fun k => extract (child k) d _ (hd k) (by simpa [foldInst] using hL') hρ'
        (by simp [foldInst]) (h k)
    by_cases hrel : ∃ k, Relation g (foldInst x X R (γ k))
    · obtain ⟨k, hk⟩ := hrel
      exact Or.inr (relation_unfold g x X R (γ k) hρ hk)
    · push Not at hrel
      have hw : ∀ k, ∃ w, Rel g (foldInst x X R (γ k)) w := fun k => (ih k).resolve_right (hrel k)
      choose w hw using hw
      exact extract_round g x X R γ hγ hρ hμ hn w hw

/-- The instance after folding with the messages `rounds` and the challenges `γs`. -/
def foldPath : Instance F E → List (E × E) → List F → Instance F E
  | x, (X, R) :: rounds, γ :: γs => foldPath (foldInst x X R γ) rounds γs
  | x, _, _ => x

/-- The transcripts of the tree: for each path, its messages, challenges and final opening. -/
def Tree.paths : Tree F E → List (List (E × E) × List F × Witness F)
  | .leaf w => [([], [], w)]
  | .node X R γ child => (List.finRange 4).flatMap fun k =>
      (child k).paths.map fun p => ((X, R) :: p.1, γ k :: p.2.1, p.2.2)

/-- The challenges of each round of the tree are distinct. -/
def Tree.Distinct : Tree F E → Prop
  | .leaf _ => True
  | .node _ _ γ child => Function.Injective γ ∧ ∀ k, (child k).Distinct

/-- A tree accepts when its challenges are distinct and each of its transcripts accepts. -/
lemma accepts_of_paths : ∀ (t : Tree F E) (x : Instance F E), t.Distinct →
    (∀ p ∈ t.paths, Rel g (foldPath x p.1 p.2.1) p.2.2) → Accepts g x t
  | .leaf w, x, _, h => h ([], [], w) (by simp [Tree.paths])
  | .node X R γ child, x, ⟨hγ, hd⟩, h => ⟨hγ, fun k => accepts_of_paths (child k) _ (hd k)
      fun p hp => h ((X, R) :: p.1, γ k :: p.2.1, p.2.2)
        (by simp only [Tree.paths, List.mem_flatMap, List.mem_finRange, List.mem_map, true_and]
            exact ⟨k, p, hp, rfl⟩)⟩

end Bppp.Spec.NormLinear
