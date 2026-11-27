-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Spec.NormLinear

/-!
# Completeness of the norm-linear argument

One honest round maps an instance satisfying the relation (19) to a folded instance satisfying
it (`fold_rel`).
-/

open Finset

namespace Bppp.Spec.NormLinear

variable {F E : Type*} [Field F] [AddCommGroup E] [Module F E]

/-! ## Splitting into even and odd halves -/

lemma sum_range_two_mul {M : Type*} [AddCommMonoid M] (m : ℕ) (ψ : ℕ → M) :
    ∑ k ∈ range (2 * m), ψ k = ∑ i ∈ range m, (ψ (2 * i) + ψ (2 * i + 1)) := by
  induction m with
  | zero => simp
  | succ m ih =>
    rw [show 2 * (m + 1) = 2 * m + 1 + 1 by ring, sum_range_succ, sum_range_succ, ih,
      sum_range_succ, add_assoc]

/-- A sum over `L` entries is the sum over the halves of the vector padded to even length. -/
lemma sum_split {M : Type*} [AddCommMonoid M] (L : ℕ) (φ : ℕ → M) :
    ∑ k ∈ range L, φ k = ∑ i ∈ range (half L), (pad L φ (2 * i) + pad L φ (2 * i + 1)) := by
  rw [← sum_range_two_mul]
  refine sum_subset_zero_on_sdiff (range_subset_range.mpr (by unfold half; omega)) ?_ ?_
  · intro k hk
    simp only [mem_sdiff, mem_range] at hk
    simp [pad, hk.2]
  · intro k hk
    simp [pad, mem_range.mp hk]

lemma ip_split (L : ℕ) (a b : ℕ → F) :
    ip L a b = ip (half L) (ev L a) (ev L b) + ip (half L) (od L a) (od L b) := by
  rw [ip, sum_split, ip, ip, ← sum_add_distrib]
  refine sum_congr rfl fun i _ => ?_
  simp only [pad, ev, od]
  split_ifs <;> simp

lemma msm_split (L : ℕ) (a : ℕ → F) (G : ℕ → E) :
    msm L a G = msm (half L) (ev L a) (ev L G) + msm (half L) (od L a) (od L G) := by
  rw [msm, sum_split, msm, msm, ← sum_add_distrib]
  refine sum_congr rfl fun i _ => ?_
  simp only [pad, ev, od]
  split_ifs <;> simp

/-- With `μ = ρ²`, `‖a‖²_μ = ‖ρ⁻¹[a]₀‖²_{μ²} + ‖[a]₁‖²_{μ²}`. -/
lemma wip_split (L : ℕ) {ρ μ : F} (hρ : ρ ≠ 0) (hμ : μ = ρ ^ 2) (a : ℕ → F) :
    wip L μ a a = wip (half L) (μ ^ 2) (fun i => ρ⁻¹ * ev L a i) (fun i => ρ⁻¹ * ev L a i) +
      wip (half L) (μ ^ 2) (od L a) (od L a) := by
  rw [wip, sum_split, wip, wip, ← sum_add_distrib]
  refine sum_congr rfl fun i _ => ?_
  subst hμ
  simp only [pad, ev, od]
  split_ifs <;> field_simp <;> ring

/-! ## One round -/

variable (g : E) (x : Instance F E) (w : Witness F)

lemma fold_rel (hρ : x.ρ ≠ 0) (hμ : x.μ = x.ρ ^ 2) (γ : F) (h : Rel g x w) :
    Rel g (foldInst x (msgX g x w) (msgR g x w) γ) (foldWit x w γ) := by
  -- `⟨c', ℓ'⟩`, `‖n'‖²_{μ²}`, `⟨ℓ', H'⟩` and `⟨n', G'⟩` in terms of the halves.
  have hc : ip (half x.Lℓ) (fun i => ev x.Lℓ x.c i + γ * od x.Lℓ x.c i)
      (fun i => ev x.Lℓ w.ℓ i + γ * od x.Lℓ w.ℓ i) = ip x.Lℓ x.c w.ℓ +
      γ * (ip (half x.Lℓ) (ev x.Lℓ x.c) (od x.Lℓ w.ℓ) + ip (half x.Lℓ) (od x.Lℓ x.c) (ev x.Lℓ w.ℓ)) +
      (γ ^ 2 - 1) * ip (half x.Lℓ) (od x.Lℓ x.c) (od x.Lℓ w.ℓ) := by
    rw [ip_split x.Lℓ]
    simp only [ip, mul_sum, ← sum_add_distrib]
    exact sum_congr rfl fun i _ => by ring
  have hn : wip (half x.Ln) (x.μ ^ 2) (fun i => x.ρ⁻¹ * ev x.Ln w.n i + γ * od x.Ln w.n i)
      (fun i => x.ρ⁻¹ * ev x.Ln w.n i + γ * od x.Ln w.n i) = wip x.Ln x.μ w.n w.n +
      γ * (2 * x.ρ⁻¹ * wip (half x.Ln) (x.μ ^ 2) (ev x.Ln w.n) (od x.Ln w.n)) +
      (γ ^ 2 - 1) * wip (half x.Ln) (x.μ ^ 2) (od x.Ln w.n) (od x.Ln w.n) := by
    rw [wip_split x.Ln hρ hμ]
    simp only [wip, mul_sum, ← sum_add_distrib]
    exact sum_congr rfl fun i _ => by ring
  have hH : msm (half x.Lℓ) (fun i => ev x.Lℓ w.ℓ i + γ * od x.Lℓ w.ℓ i)
      (fun i => ev x.Lℓ x.H i + γ • od x.Lℓ x.H i) = msm x.Lℓ w.ℓ x.H +
      γ • (msm (half x.Lℓ) (od x.Lℓ w.ℓ) (ev x.Lℓ x.H) +
        msm (half x.Lℓ) (ev x.Lℓ w.ℓ) (od x.Lℓ x.H)) +
      (γ ^ 2 - 1) • msm (half x.Lℓ) (od x.Lℓ w.ℓ) (od x.Lℓ x.H) := by
    rw [msm_split x.Lℓ]
    simp only [msm, smul_sum, ← sum_add_distrib]
    exact sum_congr rfl fun i _ => by module
  have hG : msm (half x.Ln) (fun i => x.ρ⁻¹ * ev x.Ln w.n i + γ * od x.Ln w.n i)
      (fun i => x.ρ • ev x.Ln x.G i + γ • od x.Ln x.G i) = msm x.Ln w.n x.G +
      γ • (msm (half x.Ln) (fun i => x.ρ * od x.Ln w.n i) (ev x.Ln x.G) +
        msm (half x.Ln) (fun i => x.ρ⁻¹ * ev x.Ln w.n i) (od x.Ln x.G)) +
      (γ ^ 2 - 1) • msm (half x.Ln) (od x.Ln w.n) (od x.Ln x.G) := by
    rw [msm_split x.Ln]
    simp only [msm, smul_sum, ← sum_add_distrib]
    refine sum_congr rfl fun i _ => ?_
    match_scalars <;> field_simp
    ring
  unfold Rel foldInst foldWit
  dsimp only
  rw [hc, hn, hH, hG, h, msgX, msgR]
  module

end Bppp.Spec.NormLinear
