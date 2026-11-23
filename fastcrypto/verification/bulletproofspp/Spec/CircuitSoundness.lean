-- THIS FILE IS AI-ONLY
import bulletproofspp.Spec.Completeness
import bulletproofspp.Spec.Commitment
import bulletproofspp.Spec.Interpolation
import bulletproofspp.Spec.NormLinearSoundness

/-!
# Special soundness of the range circuit

The extractor of §5.3 of the paper, level by level, from the innermost outward. Openings are
arbitrary: no zero pattern, and `C_O`, `C_L`, `C_R` may have `H_7`-coordinates.
-/

open Finset LaurentPolynomial

namespace Bppp.Spec

variable {F : Type*} [Field F] (P : Params) (ch : Challenges F)

/-! ## The support of `f(T)` -/

lemma e_range (s : ℕ) : -1 ≤ e s ∧ e s ≤ 7 := by
  unfold e; split <;> norm_num

lemma supp_c (s : ℕ) : Supp (c P ch s) (-1) 7 := by
  unfold c
  refine Supp.add ?_ (Supp.mono _ (by norm_num) (by norm_num))
  split_ifs
  · exact Supp.mono _ (e_range s).1 (e_range s).2
  · exact Supp.zero _ _

lemma supp_ℓ (w : Opening F) (s : ℕ) : Supp (ℓ ch w s) (-1) 3 := by
  unfold ℓ; split_ifs <;> supp_tac

/-- For any opening, the error polynomial has powers `T⁻², ..., T¹⁰` only. -/
lemma supp_f (w : Opening F) : Supp (f P ch w) (-2) 10 := by
  refine Supp.sub (Supp.sub ?_ ?_) ((supp_normμ P ch (supp_n P ch w)).widen le_rfl (by norm_num))
  · simp only [σ, ps]
    refine Supp.add (Supp.add (Supp.add ((supp_normμ P ch (supp_pn P ch)).widen
      (by norm_num) (by norm_num)) (Supp.mono _ (by norm_num) (by norm_num)))
      (Supp.mono _ (by norm_num) (by norm_num))) ?_
    supp_tac
  · exact Supp.sum _ fun s _ => ((supp_c P ch s).mul (supp_ℓ ch w s)).widen (by norm_num)
      (by norm_num)

/-! ## Evaluations -/

variable (τ : Fˣ) (w : Opening F)

lemma eval_σ : evalAt τ (σ P ch w) = evalAt τ (ps P ch) + (τ : F) ^ (-1 : ℤ) * w.rS 0 +
    ch.δ * w.rO 0 + (τ : F) * w.rL 0 + (τ : F) ^ 2 * w.rR 0 + (τ : F) ^ 3 * w.vhat := by
  simp only [σ, map_add, evalAt_mono, zpow_ofNat]; ring

lemma eval_ℓ (s : ℕ) (_hs : s < 8) : evalAt τ (ℓ ch w s) = (τ : F) ^ (-1 : ℤ) * lin w.rS w.ℓS s +
    ch.δ * lin w.rO w.ℓO s + (τ : F) * lin w.rL w.ℓL s + (τ : F) ^ 2 * lin w.rR w.ℓR s +
    (τ : F) ^ 3 * lin w.rV w.ℓV s := by
  simp only [ℓ, lin]
  split_ifs <;> simp only [map_add, evalAt_mono, zpow_ofNat] <;> ring

lemma eval_n (k : ℕ) : evalAt τ (n P ch w k) = evalAt τ (pn P ch k) + (τ : F) ^ (-1 : ℤ) * w.nS k +
    ch.δ * w.nO k + (τ : F) * w.nL k + (τ : F) ^ 2 * w.nR k + (τ : F) ^ 3 * w.nV k := by
  simp only [n, map_add, evalAt_mono, zpow_ofNat]; ring

lemma eval_f : evalAt τ (f P ch w) = evalAt τ (σ P ch w) -
    ∑ s ∈ range 8, evalAt τ (c P ch s) * evalAt τ (ℓ ch w s) -
    ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (evalAt τ (n P ch w k) * evalAt τ (n P ch w k)) := by
  simp only [f, normμ, map_sub, map_sum, map_mul, evalAt_mono, zpow_zero, mul_one]

/-! ## Evaluation (`τ`: 13) -/

section Tau

variable {E : Type*} [AddCommGroup E] [Module F E] (g : E) (H G : ℕ → E)

/-- The instance of the norm-linear argument at `τ`: `C(τ)` (25) and `c(τ)`. -/
noncomputable def tauInst (cS cO cL cR V : E) (rho : F) (τ : Fˣ) : NormLinear.Instance F E where
  C := combined P g G ch τ cS cO cL cR V
  c s := evalAt τ (Spec.c P ch s)
  H := H
  G := G
  Lℓ := 8
  Ln := P.nm
  ρ := rho
  μ := ch.μ

lemma commit_sum {ι : Type*} (S : Finset ι) (a s : ι → F) (h n : ι → ℕ → F) :
    commit P g H G (∑ m ∈ S, a m * s m) (fun j => ∑ m ∈ S, a m * h m j)
      (fun j => ∑ m ∈ S, a m * n m j) = ∑ m ∈ S, a m • commit P g H G (s m) (h m) (n m) := by
  simp only [commit, NormLinear.msm, sum_smul, smul_add, sum_add_distrib, smul_sum, mul_smul]
  rw [sum_comm (s := range 8), sum_comm (s := range P.nm)]

lemma commit_smul (a s : F) (h n : ℕ → F) :
    commit P g H G (a * s) (fun j => a * h j) (fun j => a * n j) = a • commit P g H G s h n := by
  simp only [commit, NormLinear.msm, mul_smul, smul_add, smul_sum]

lemma commit_sub (s s' : F) (h h' n n' : ℕ → F) :
    commit P g H G (s - s') (fun j => h j - h' j) (fun j => n j - n' j) =
      commit P g H G s h n - commit P g H G s' h' n' := by
  simp only [commit, NormLinear.msm, sub_smul, sum_sub_distrib]; abel

lemma commit_congr (s : F) {h h' n n' : ℕ → F} (hh : ∀ j < 8, h j = h' j)
    (hn : ∀ j < P.nm, n j = n' j) : commit P g H G s h n = commit P g H G s h' n' := by
  simp only [commit, NormLinear.msm]
  congr 1
  · congr 1; exact sum_congr rfl fun j hj => by rw [hh j (mem_range.1 hj)]
  · exact sum_congr rfl fun j hj => by rw [hn j (mem_range.1 hj)]

lemma lin_shift (c a : F) (h : ℕ → F) (s : ℕ) (hs : s < 8) :
    lin (fun j => c * if j = 0 then a else h (j - 1)) (c * h 7) s = c * h s := by
  unfold lin
  split_ifs with h1
  · simp
  · obtain rfl : s = 7 := by omega
    rfl

/-- **The `τ` level.** From openings of `C(τ)` satisfying the norm-linear relation at thirteen
distinct `τ`, either `C_S`, `C_O`, `C_L`, `C_R`, `V̂` open to an opening with `f(T) ≡ 0`, or the
generators satisfy a nontrivial linear relation. -/
lemma extract_tau (cS cO cL cR V : E) (rho : F) (τ : Fin 13 → Fˣ) (hτ : Function.Injective τ)
    (hδ : ch.δ ≠ 0) (w : Fin 13 → NormLinear.Witness F)
    (h : ∀ k, NormLinear.Rel g (tauInst P ch g H G cS cO cL cR V rho (τ k)) (w k)) :
    (∃ wo : Opening F, f P ch wo = 0 ∧ cS = Spec.cS P g H G wo ∧ cO = Spec.cO P g H G wo ∧
      cL = Spec.cL P g H G wo ∧ cR = Spec.cR P g H G wo ∧
      V = commit P g H G wo.vhat (lin wo.rV wo.ℓV) wo.nV) ∨
    NormLinear.Relation g (tauInst P ch g H G cS cO cL cR V rho (τ 0)) := by
  -- The openings of `Y(τ) = τ⁻¹C_S + δC_O + τC_L + τ²C_R + τ³V̂`, scaled by `τ`.
  set ys : Fin 13 → F := fun k => (τ k : F) * (NormLinear.ip 8 (fun s => evalAt (τ k)
    (Spec.c P ch s)) (w k).ℓ + NormLinear.wip P.nm ch.μ (w k).n (w k).n - evalAt (τ k) (ps P ch))
  set yh : Fin 13 → ℕ → F := fun k j => (τ k : F) * (w k).ℓ j
  set yn : Fin 13 → ℕ → F := fun k j => (τ k : F) * ((w k).n j - evalAt (τ k) (pn P ch j))
  set Zp : Fin 5 → E := ![cS, ch.δ • cO, cL, cR, V]
  have hpoly : ∀ t : Fˣ, (t : F) • ((t : F) ^ (-1 : ℤ) • cS + ch.δ • cO + (t : F) • cL +
      (t : F) ^ 2 • cR + (t : F) ^ 3 • V) = ∑ j : Fin 5, (t : F) ^ (j : ℕ) • Zp j := fun t => by
    have e : (t : F) * (t : F) ^ (-1 : ℤ) = 1 := by rw [zpow_neg_one]; exact mul_inv_cancel₀ t.ne_zero
    simp only [Fin.sum_univ_five, Zp, smul_add, smul_smul, e, one_smul]
    simp
    module
  have hY : ∀ k, commit P g H G (ys k) (yh k) (yn k) = ∑ j : Fin 5, (τ k : F) ^ (j : ℕ) • Zp j := by
    intro k
    rw [← hpoly]
    have hk := h k
    simp only [NormLinear.Rel, tauInst, combined] at hk
    have hun : commit P g H G (NormLinear.ip 8 (fun s => evalAt (τ k) (Spec.c P ch s)) (w k).ℓ +
        NormLinear.wip P.nm ch.μ (w k).n (w k).n - evalAt (τ k) (ps P ch)) (w k).ℓ
        (fun j => (w k).n j - evalAt (τ k) (pn P ch j)) =
        (τ k : F) ^ (-1 : ℤ) • cS + ch.δ • cO + (τ k : F) • cL + (τ k : F) ^ 2 • cR +
          (τ k : F) ^ 3 • V := by
      have e : commit P g H G (NormLinear.ip 8 (fun s => evalAt (τ k) (Spec.c P ch s)) (w k).ℓ +
          NormLinear.wip P.nm ch.μ (w k).n (w k).n - evalAt (τ k) (ps P ch)) (w k).ℓ
          (fun j => (w k).n j - evalAt (τ k) (pn P ch j)) =
          ((NormLinear.ip 8 (fun s => evalAt (τ k) (Spec.c P ch s)) (w k).ℓ +
            NormLinear.wip P.nm ch.μ (w k).n (w k).n) • g + NormLinear.msm 8 (w k).ℓ H +
            NormLinear.msm P.nm (w k).n G) -
          (evalAt (τ k) (ps P ch) • g +
            NormLinear.msm P.nm (fun j => evalAt (τ k) (pn P ch j)) G) := by
        simp only [commit, NormLinear.msm, sub_smul, sum_sub_distrib]; abel
      rw [e, ← hk]; abel
    exact (commit_smul P g H G (τ k : F) _ _ _).trans (by rw [hun])
  -- Interpolate the openings of `C_S, δC_O, C_L, C_R, V̂` from the first five `τ`.
  set ι : Fin 5 → Fin 13 := Fin.castLE (by norm_num)
  have hι : Function.Injective ι := Fin.castLE_injective _
  set t : Fin 5 → F := fun k => (τ (ι k) : F)
  have ht : Function.Injective t := fun a b e => hι (hτ (Units.ext e))
  obtain ⟨W, hW1, hW2⟩ := vandermonde_inv t ht
  set zs : Fin 5 → F := fun b => ∑ k, W b k * ys (ι k)
  set zh : Fin 5 → ℕ → F := fun b j => ∑ k, W b k * yh (ι k) j
  set zn : Fin 5 → ℕ → F := fun b j => ∑ k, W b k * yn (ι k) j
  have hZ : ∀ b, commit P g H G (zs b) (zh b) (zn b) = Zp b := fun b => by
    rw [commit_sum]
    simp only [hY, smul_sum, smul_smul]
    rw [sum_comm]
    simp only [← sum_smul]
    have : ∀ j : Fin 5, ∑ k, W b k * (τ (ι k) : F) ^ (j : ℕ) = if b = j then 1 else 0 :=
      fun j => hW1 b j
    simp only [this, ite_smul, one_smul, zero_smul, sum_ite_eq, mem_univ, if_true]
  -- The combination at any `τ`, which agrees with the given openings at the first five.
  set us : F → F := fun x => ∑ b : Fin 5, x ^ (b : ℕ) * zs b
  set uh : F → ℕ → F := fun x j => ∑ b : Fin 5, x ^ (b : ℕ) * zh b j
  set un : F → ℕ → F := fun x j => ∑ b : Fin 5, x ^ (b : ℕ) * zn b j
  have hu : ∀ x : F, commit P g H G (us x) (uh x) (un x) = ∑ j : Fin 5, x ^ (j : ℕ) • Zp j :=
    fun x => by rw [commit_sum]; simp only [hZ]
  have hfirst : ∀ m : Fin 5, us (t m) = ys (ι m) ∧ (∀ j, uh (t m) j = yh (ι m) j) ∧
      (∀ j, un (t m) j = yn (ι m) j) := fun m => by
    have key : ∀ y : Fin 5 → F, ∑ b : Fin 5, t m ^ (b : ℕ) * ∑ k, W b k * y k = y m := fun y => by
      simp only [mul_sum, ← mul_assoc]
      rw [sum_comm]
      simp only [← sum_mul, hW2, ite_mul, one_mul, zero_mul, sum_ite_eq, mem_univ, if_true]
    exact ⟨key _, fun j => key _, fun j => key _⟩
  -- At every `τ`, either the combination opens `C(τ)` as given, or their difference is a relation.
  by_cases hall : ∀ k, us (τ k) = ys k ∧ (∀ j < 8, uh (τ k) j = yh k j) ∧
      (∀ j < P.nm, un (τ k) j = yn k j)
  swap
  · right
    push Not at hall
    obtain ⟨k, hk⟩ := hall
    refine ⟨us (τ k) - ys k, fun j => uh (τ k) j - yh k j, fun j => un (τ k) j - yn k j, ?_, ?_⟩
    · by_contra hc
      push Not at hc
      exact hk (sub_eq_zero.1 hc.1) (fun j hj => sub_eq_zero.1 (hc.2.1 j hj))
        |>.elim fun j ⟨hj, hne⟩ => hne (sub_eq_zero.1 (hc.2.2 j hj))
    · show commit P g H G _ _ _ = 0
      rw [commit_sub, hu, hY, sub_self]
  left
  -- The opening read off the interpolated coordinates, `C_O` unscaled by `δ`.
  set op : F → Fin 5 → ℕ → F := fun c b j => c * if j = 0 then zs b else zh b (j - 1)
  have hop : ∀ c b, commit P g H G (op c b 0) (lin (op c b) (c * zh b 7)) (fun j => c * zn b j) =
      c • Zp b := fun c b => by
    rw [← hZ, ← commit_smul]
    exact commit_congr P g H G _ (fun j hj => lin_shift c _ _ j hj) (fun _ _ => rfl)
  set d := ch.δ⁻¹
  set wo : Opening F := {
    nS := fun j => 1 * zn 0 j, nO := fun j => d * zn 1 j, nL := fun j => 1 * zn 2 j,
    nR := fun j => 1 * zn 3 j, ℓS := 1 * zh 0 7, rS := op 1 0, rO := op d 1, rL := op 1 2,
    rR := op 1 3, vhat := op 1 4 0, rV := op 1 4, ℓV := 1 * zh 4 7, ℓO := d * zh 1 7,
    ℓL := 1 * zh 2 7, ℓR := 1 * zh 3 7, nV := fun j => 1 * zn 4 j }
  have hd : ch.δ * d = 1 := mul_inv_cancel₀ hδ
  refine ⟨wo, ?_, ?_, ?_, ?_, ?_, ?_⟩
  rotate_left
  · exact ((hop 1 0).trans (one_smul _ _)).symm
  · show cO = commit P g H G (op d 1 0) (lin (op d 1) (d * zh 1 7)) (fun j => d * zn 1 j)
    rw [hop]; show cO = d • (ch.δ • cO); rw [smul_smul, mul_comm, hd, one_smul]
  · exact ((hop 1 2).trans (one_smul _ _)).symm
  · exact ((hop 1 3).trans (one_smul _ _)).symm
  · exact ((hop 1 4).trans (one_smul _ _)).symm
  -- `f` vanishes at all 13 challenges, so it is zero.
  refine laurent_zero (n := 12) (a := -2) (supp_f P ch wo) τ hτ fun k => ?_
  obtain ⟨hs, hh, hn⟩ := hall k
  have tk := (τ k).ne_zero
  have ti : (τ k : F) ^ (-1 : ℤ) * (τ k : F) = 1 := by
    rw [zpow_neg_one]; exact inv_mul_cancel₀ tk
  have e5 : ∀ y : Fin 5 → F, ∑ b : Fin 5, (τ k : F) ^ (b : ℕ) * y b =
      (τ k : F) * ((τ k : F) ^ (-1 : ℤ) * y 0 + ch.δ * (d * y 1) + (τ k : F) * y 2 +
        (τ k : F) ^ 2 * y 3 + (τ k : F) ^ 3 * y 4) := fun y => by
    simp only [Fin.sum_univ_five, Fin.val_zero, Fin.val_one, Fin.val_two, pow_zero, pow_one]
    have : ((3 : Fin 5) : ℕ) = 3 := rfl
    have : ((4 : Fin 5) : ℕ) = 4 := rfl
    simp only [*]
    linear_combination -(y 0) * ti - (τ k : F) * y 1 * hd
  have hσ : evalAt (τ k) (σ P ch wo) = NormLinear.ip 8 (fun s => evalAt (τ k) (Spec.c P ch s))
      (w k).ℓ + NormLinear.wip P.nm ch.μ (w k).n (w k).n := by
    have h1 : (τ k : F) * _ = (τ k : F) * _ := (e5 zs).symm.trans hs
    have h2 := mul_left_cancel₀ tk h1
    rw [eval_σ]
    simp only [wo, op, if_true, one_mul]
    linear_combination h2
  have hℓ : ∀ s < 8, evalAt (τ k) (ℓ ch wo s) = (w k).ℓ s := fun s hs8 => by
    have hl : ∀ c b, lin (op c b) (c * zh b 7) s = c * zh b s := fun c b => lin_shift c _ _ s hs8
    have h1 : (τ k : F) * _ = (τ k : F) * _ := (e5 fun b => zh b s).symm.trans (hh s hs8)
    have h2 := mul_left_cancel₀ tk h1
    rw [eval_ℓ _ _ _ _ hs8]
    simp only [wo]
    rw [hl, hl, hl, hl, hl]
    linear_combination h2
  have hnk : ∀ j < P.nm, evalAt (τ k) (n P ch wo j) = (w k).n j := fun j hj => by
    have h1 : (τ k : F) * _ = (τ k : F) * _ := (e5 fun b => zn b j).symm.trans (hn j hj)
    have h2 := mul_left_cancel₀ tk h1
    rw [eval_n]
    simp only [wo, one_mul]
    linear_combination h2
  have s1 : ∑ s ∈ range 8, evalAt (τ k) (c P ch s) * evalAt (τ k) (ℓ ch wo s) =
      NormLinear.ip 8 (fun s => evalAt (τ k) (Spec.c P ch s)) (w k).ℓ :=
    sum_congr rfl fun s hs8 => by rw [hℓ s (mem_range.1 hs8)]
  have s2 : ∑ j ∈ range P.nm, ch.μ ^ (j + 1) * (evalAt (τ k) (n P ch wo j) *
      evalAt (τ k) (n P ch wo j)) = NormLinear.wip P.nm ch.μ (w k).n (w k).n :=
    sum_congr rfl fun j hj => by rw [hnk j (mem_range.1 hj)]
  rw [eval_f, hσ, s1, s2]
  ring

end Tau

end Bppp.Spec
