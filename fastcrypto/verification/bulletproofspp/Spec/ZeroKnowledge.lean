-- THIS FILE IS AI-ONLY
import bulletproofspp.Spec.Completeness
import bulletproofspp.Spec.CircuitSoundness
import VCVio.OracleComp.Constructions.SampleableType.Measure
import VCVio.EvalDist.EvalDistEq

/-!
# Zero-knowledge

Honest-verifier zero-knowledge of the range circuit (Theorem 1 of the paper). With the challenges
fixed, the commitments `C_O`, `C_L`, `C_R` and the opening `(ℓ(τ), n(τ))` of `C(τ)` are uniform
and independent; `C_S` and the norm-linear messages are functions of them and public data.

Distributions are VCVio's: `$ᵗ X` samples `X` uniformly, and `=ᵈ` is equality in distribution.
-/

open Finset

namespace Bppp.Spec

/-! ## Uniform pushforwards -/

section Uniform

open scoped ENNReal

/-- A map whose fibers all have the same size pushes the uniform distribution to the uniform
distribution. -/
lemma map_uniform_of_card_fiber {X Y : Type} [Fintype X] [SampleableType X] [Fintype Y]
    [SampleableType Y] [DecidableEq Y] (f : X → Y) (k : ℕ)
    (hk : ∀ y, (univ.filter fun x => f x = y).card = k) :
    f <$> ($ᵗ X) =ᵈ $ᵗ Y := by
  classical
  have hX : Fintype.card X = k * Fintype.card Y := by
    rw [← Finset.card_univ, Finset.card_eq_sum_card_fiberwise (f := f) (t := univ)
      (fun _ _ => mem_univ _)]
    simp [hk, mul_comm]
  have hk0 : k ≠ 0 := by
    intro h0; have := Fintype.card_pos (α := X); rw [hX, h0, zero_mul] at this; omega
  intro p
  rw [prEvent_map, SampleableType.prEvent_uniformSample, SampleableType.prEvent_uniformSample]
  have hp : (univ.filter fun x => p (f x)).card = k * (univ.filter p).card := by
    rw [Finset.card_eq_sum_card_fiberwise (f := f) (t := univ.filter p)
      (fun x hx => by simpa using hx)]
    rw [Finset.sum_congr rfl fun y hy => ?_, Finset.sum_const, smul_eq_mul, mul_comm]
    rw [← hk y]
    congr 1
    ext x
    simp only [mem_filter, mem_univ, true_and] at hy ⊢
    exact ⟨fun h => h.2, fun h => ⟨h ▸ hy, h⟩⟩
  rw [hp, hX, Nat.cast_mul, Nat.cast_mul,
    ENNReal.mul_div_mul_left _ _ (by exact_mod_cast hk0) (by simp)]

/-- The fibers of `(m, b) ↦ (ψ m, κ m + L b)`, for a bijection `ψ` and an additive map `L` with
a right inverse, all have the size of the kernel of `L`. -/
lemma card_fiber_affine {M B Y₁ Y₂ : Type*} [Fintype M] [Fintype B] [DecidableEq M]
    [DecidableEq B] [DecidableEq Y₁] [DecidableEq Y₂] [AddCommGroup B] [AddCommGroup Y₂]
    (ψ : M ≃ Y₁) (κ : M → Y₂) (L : B →+ Y₂) (R : Y₂ → B) (hR : ∀ z, L (R z) = z)
    (y : Y₁ × Y₂) :
    (univ.filter fun x : M × B => (ψ x.1, κ x.1 + L x.2) = y).card =
      (univ.filter fun b => L b = 0).card := by
  obtain ⟨y₁, y₂⟩ := y
  refine Finset.card_bij' (fun x _ => x.2 - R (y₂ - κ x.1))
    (fun b _ => (ψ.symm y₁, b + R (y₂ - κ (ψ.symm y₁)))) ?_ ?_ ?_ ?_
  · intro x hx
    simp only [mem_filter, mem_univ, true_and, Prod.mk.injEq] at hx ⊢
    rw [map_sub, hR]; rw [← hx.2]; abel
  · intro b hb
    simp only [mem_filter, mem_univ, true_and, Prod.mk.injEq] at hb ⊢
    refine ⟨by simp, ?_⟩
    rw [map_add, hb, hR]; abel
  · intro x hx
    simp only [mem_filter, mem_univ, true_and, Prod.mk.injEq] at hx
    obtain ⟨m, b⟩ := x
    simp only at hx ⊢
    rw [show ψ.symm y₁ = m by rw [← hx.1]; simp]
    simp
  · intro b _
    simp

end Uniform

/-! ## The honest prover's randomness -/

section Honest

open LaurentPolynomial

variable {F : Type} [Field F] (P : Params) (ch : Challenges F)

/-- The free blindings of `C_O` under the zero pattern (22), `r_{O,j}` for `j = 0, 1, 2, 3, 5, 6`,
as entries `0, ..., 5` of `b`. -/
def blindO (b : Fin 15 → F) : ℕ → F
  | 0 => b 0 | 1 => b 1 | 2 => b 2 | 3 => b 3 | 5 => b 4 | 6 => b 5 | _ => 0

/-- `r_{L,j}` for `j = 0, 1, 2, 4, 5`, entries `6, ..., 10` of `b`. -/
def blindL (b : Fin 15 → F) : ℕ → F
  | 0 => b 6 | 1 => b 7 | 2 => b 8 | 4 => b 9 | 5 => b 10 | _ => 0

/-- `r_{R,j}` for `j = 0, 1, 3, 4`, entries `11, ..., 14` of `b`. -/
def blindR (b : Fin 15 → F) : ℕ → F
  | 0 => b 11 | 1 => b 12 | 3 => b 13 | 4 => b 14 | _ => 0

@[simp] lemma blindO_zero (j : ℕ) : blindO (0 : Fin 15 → F) j = 0 := by
  unfold blindO; split <;> rfl
@[simp] lemma blindL_zero (j : ℕ) : blindL (0 : Fin 15 → F) j = 0 := by
  unfold blindL; split <;> rfl
@[simp] lemma blindR_zero (j : ℕ) : blindR (0 : Fin 15 → F) j = 0 := by
  unfold blindR; split <;> rfl

/-- The masks `n_S` and `ℓ_S` of `C_S`. -/
abbrev Masks (F : Type*) (P : Params) := (Fin P.nm → F) × F

/-- The honest prover with digits `d`, input blindings `s`, masks `m` and blindings `b`. -/
def zkHonest (d : ℕ → ℕ → ℕ) (s : ℕ → F) (m : Masks F P) (b : Fin 15 → F) : Honest F where
  d := d
  s := s
  nS k := if h : k < P.nm then m.1 ⟨k, h⟩ else 0
  ℓS := m.2
  rO := blindO b
  rL := blindL b
  rR := blindR b

lemma zkHonest_zeroPattern (d : ℕ → ℕ → ℕ) (s : ℕ → F) (m : Masks F P) (b : Fin 15 → F) :
    (zkHonest P d s m b).ZeroPattern :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- The part of `f(T)` at `r_S = 0` that the blindings of `C_O`, `C_L`, `C_R` add. -/
noncomputable def linPoly (b : Fin 15 → F) : F[T;T⁻¹] :=
  (mono 0 (ch.δ * blindO b 0) + mono 1 (blindL b 0) + mono 2 (blindR b 0)) -
    ∑ s ∈ range 7, c P ch s * (mono 0 (ch.δ * blindO b (s + 1)) + mono 1 (blindL b (s + 1)) +
      mono 2 (blindR b (s + 1)))

lemma f_blind (d : ℕ → ℕ → ℕ) (s : ℕ → F) (m : Masks F P) (b : Fin 15 → F) :
    f P ch ((zkHonest P d s m b).opening P ch 0) =
      f P ch ((zkHonest P d s m 0).opening P ch 0) + linPoly P ch b := by
  have hℓ : ∀ j, ℓ ch ((zkHonest P d s m b).opening P ch 0) j =
      ℓ ch ((zkHonest P d s m 0).opening P ch 0) j + if j < 7 then
        mono 0 (ch.δ * blindO b (j + 1)) + mono 1 (blindL b (j + 1)) + mono 2 (blindR b (j + 1))
      else 0 := fun j => by
    unfold ℓ; split_ifs <;> simp [Honest.opening, zkHonest]; ring
  have hsum : ∑ j ∈ range 8, c P ch j * ℓ ch ((zkHonest P d s m b).opening P ch 0) j =
      ∑ j ∈ range 8, c P ch j * ℓ ch ((zkHonest P d s m 0).opening P ch 0) j +
        ∑ j ∈ range 7, c P ch j * (mono 0 (ch.δ * blindO b (j + 1)) + mono 1 (blindL b (j + 1)) +
          mono 2 (blindR b (j + 1))) := by
    have h7 : ∀ X : ℕ → F[T;T⁻¹], ∑ j ∈ range 8, c P ch j * (if j < 7 then X j else 0) =
        ∑ j ∈ range 7, c P ch j * X j := fun X => by
      rw [Finset.sum_range_succ]
      simp only [lt_irrefl, if_false, mul_zero, add_zero]
      exact sum_congr rfl fun j hj => by rw [if_pos (mem_range.1 hj)]
    simp only [hℓ, mul_add, sum_add_distrib]
    rw [h7 fun j => mono 0 (ch.δ * blindO b (j + 1)) + mono 1 (blindL b (j + 1)) +
      mono 2 (blindR b (j + 1))]
    simp only [mul_add, sum_add_distrib]
  have hσ : σ P ch ((zkHonest P d s m b).opening P ch 0) =
      σ P ch ((zkHonest P d s m 0).opening P ch 0) +
        (mono 0 (ch.δ * blindO b 0) + mono 1 (blindL b 0) + mono 2 (blindR b 0)) := by
    simp only [σ, Honest.opening, Honest.value, zkHonest, blindO_zero, blindL_zero, blindR_zero,
      mul_zero, mono_zero]
    ring
  have hn : n P ch ((zkHonest P d s m b).opening P ch 0) =
      n P ch ((zkHonest P d s m 0).opening P ch 0) := rfl
  rw [f, f, hsum, hσ, hn, linPoly]
  abel

/-- The coefficients of `linPoly` at the powers `e_s - 1` that `r_{S,s+1}` cancels. -/
lemma coeff_linPoly (b : Fin 15 → F) :
    coeff (-2) (linPoly P ch b) = 0 ∧
    coeff 0 (linPoly P ch b) = ch.δ * b 0 - ch.β * b 7 - ch.δ * (ch.lam ^ P.g 1 * b 2 +
      ch.lam ^ P.g 2 * b 3 + ch.lam ^ P.g 4 * b 4 + ch.lam ^ P.g 5 * b 5) ∧
    coeff 1 (linPoly P ch b) = b 6 - ch.β * ch.δ * b 2 - ch.β * b 12 -
      (ch.lam ^ P.g 1 * b 8 + ch.lam ^ P.g 3 * b 9 + ch.lam ^ P.g 4 * b 10) ∧
    coeff 2 (linPoly P ch b) = b 11 - ch.β * ch.δ * b 3 - ch.β * b 8 - ch.lam ^ P.g 2 * b 13 -
      ch.lam ^ P.g 3 * b 14 ∧
    coeff 4 (linPoly P ch b) = -ch.β * b 9 - ch.β * b 13 ∧
    coeff 5 (linPoly P ch b) = -ch.β * ch.δ * b 4 - ch.β * b 14 ∧
    coeff 6 (linPoly P ch b) = -ch.β * ch.δ * b 5 - ch.β * b 10 := by
  simp only [linPoly, sum_range_succ, sum_range_zero, c, e, clV, blindO, blindL, blindR]
  norm_num [add_mul, mul_add, mono_mul]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> ring

/-- The honest opening with masks `m` and blindings `b`. -/
noncomputable def zkOpening (d : ℕ → ℕ → ℕ) (s : ℕ → F) (m : Masks F P) (b : Fin 15 → F) :
    Opening F :=
  (zkHonest P d s m b).opening P ch ((zkHonest P d s m b).rS P ch)

/-- The linear part, in the blindings, of `ℓ(τ)_0, ..., ℓ(τ)_6` and of the discrete logs of
`C_O`, `C_L`, `C_R` over the discrete logs `h` of `H`. -/
noncomputable def linRow (τ : F) (h : ℕ → F) (b : Fin 15 → F) : Fin 10 → F :=
  ![ch.δ * b 1 + τ * b 7 + τ ^ 2 * b 12,
    (ch.δ * b 0 - ch.β * b 7 - ch.δ * (ch.lam ^ P.g 1 * b 2 + ch.lam ^ P.g 2 * b 3 +
      ch.lam ^ P.g 4 * b 4 + ch.lam ^ P.g 5 * b 5)) / (ch.β * τ) + ch.δ * b 2 + τ * b 8,
    (b 6 - ch.β * ch.δ * b 2 - ch.β * b 12 - (ch.lam ^ P.g 1 * b 8 + ch.lam ^ P.g 3 * b 9 +
      ch.lam ^ P.g 4 * b 10)) / (ch.β * τ) + ch.δ * b 3 + τ ^ 2 * b 13,
    (b 11 - ch.β * ch.δ * b 3 - ch.β * b 8 - ch.lam ^ P.g 2 * b 13 - ch.lam ^ P.g 3 * b 14) /
      (ch.β * τ) + τ * b 9 + τ ^ 2 * b 14,
    (-ch.β * b 9 - ch.β * b 13) / (ch.β * τ) + ch.δ * b 4 + τ * b 10,
    (-ch.β * ch.δ * b 4 - ch.β * b 14) / (ch.β * τ) + ch.δ * b 5,
    (-ch.β * ch.δ * b 5 - ch.β * b 10) / (ch.β * τ),
    b 0 + b 1 * h 0 + b 2 * h 1 + b 3 * h 2 + b 4 * h 4 + b 5 * h 5,
    b 6 + b 7 * h 0 + b 8 * h 1 + b 9 * h 3 + b 10 * h 4,
    b 11 + b 12 * h 0 + b 13 * h 2 + b 14 * h 3]

lemma linRow_7 (τ : F) (h : ℕ → F) (b : Fin 15 → F) :
    linRow P ch τ h b 7 = b 0 + b 1 * h 0 + b 2 * h 1 + b 3 * h 2 + b 4 * h 4 + b 5 * h 5 := rfl
lemma linRow_8 (τ : F) (h : ℕ → F) (b : Fin 15 → F) :
    linRow P ch τ h b 8 = b 6 + b 7 * h 0 + b 8 * h 1 + b 9 * h 3 + b 10 * h 4 := rfl
lemma linRow_9 (τ : F) (h : ℕ → F) (b : Fin 15 → F) :
    linRow P ch τ h b 9 = b 11 + b 12 * h 0 + b 13 * h 2 + b 14 * h 3 := rfl

variable (d : ℕ → ℕ → ℕ) (s : ℕ → F) (τ : Fˣ)

lemma rS_blind (m : Masks F P) (b : Fin 15 → F) (j : ℕ) :
    (zkHonest P d s m b).rS P ch (j + 1) = (zkHonest P d s m 0).rS P ch (j + 1) +
      coeff (e j - 1) (linPoly P ch b) / ch.β := by
  simp only [Honest.rS, Nat.succ_ne_zero, if_false, Nat.add_sub_cancel]
  rw [f_blind P ch d s m b, map_add, add_div]

/-- `ℓ(τ)_s` for `s < 7` is affine in the blindings, with linear part `linRow`. -/
lemma ell_blind (h : ℕ → F) (m : Masks F P) (b : Fin 15 → F) (j : Fin 7) :
    evalAt τ (ℓ ch (zkOpening P ch d s m b) j) =
      evalAt τ (ℓ ch (zkOpening P ch d s m 0) j) + linRow P ch τ h b (Fin.castLE (by norm_num) j) := by
  obtain ⟨h0, h1, h2, h3, h4, h5, h6⟩ := coeff_linPoly P ch b
  have hj : (j : ℕ) < 8 := by omega
  rw [eval_ℓ _ _ _ _ hj, eval_ℓ _ _ _ _ hj]
  simp only [zkOpening, Honest.opening, lin, if_pos j.isLt]
  rw [rS_blind P ch d s m b]
  simp only [zkHonest, blindO_zero, blindL_zero, blindR_zero]
  fin_cases j <;> simp [linRow, e, blindO, blindL, blindR, h0, h1, h2, h3, h4, h5, h6] <;>
    field_simp <;> ring

/-- The discrete log of `commit σ ℓ n` over the discrete logs `h`, `gg` of `H`, `G`. -/
def dlogCommit (h gg : ℕ → F) (σ : F) (ℓ n : ℕ → F) : F :=
  σ + ∑ j ∈ range 8, ℓ j * h j + ∑ k ∈ range P.nm, n k * gg k

lemma commit_dlog {E : Type*} [AddCommGroup E] [Module F E] (g : E) (H G : ℕ → E)
    (h gg : ℕ → F) (hH : ∀ j, H j = h j • g) (hG : ∀ k, G k = gg k • g) (σ : F) (ℓ n : ℕ → F) :
    commit P g H G σ ℓ n = dlogCommit P h gg σ ℓ n • g := by
  simp only [commit, NormLinear.msm, dlogCommit, hH, hG, smul_smul, add_smul, sum_smul]

/-- The discrete logs of `C_O`, `C_L`, `C_R` of an opening. -/
def dlogO (h gg : ℕ → F) (w : Opening F) : F := dlogCommit P h gg (w.rO 0) (lin w.rO w.ℓO) w.nO
def dlogL (h gg : ℕ → F) (w : Opening F) : F := dlogCommit P h gg (w.rL 0) (lin w.rL w.ℓL) w.nL
def dlogR (h gg : ℕ → F) (w : Opening F) : F := dlogCommit P h gg (w.rR 0) (lin w.rR w.ℓR) w.nR

lemma dlog_blind (h gg : ℕ → F) (m : Masks F P) (b : Fin 15 → F) :
    dlogO P h gg (zkOpening P ch d s m b) = dlogO P h gg (zkOpening P ch d s m 0) +
      linRow P ch τ h b 7 ∧
    dlogL P h gg (zkOpening P ch d s m b) = dlogL P h gg (zkOpening P ch d s m 0) +
      linRow P ch τ h b 8 ∧
    dlogR P h gg (zkOpening P ch d s m b) = dlogR P h gg (zkOpening P ch d s m 0) +
      linRow P ch τ h b 9 := by
  simp only [dlogO, dlogL, dlogR, dlogCommit, zkOpening, Honest.opening, zkHonest, lin,
    sum_range_succ, sum_range_zero, blindO, blindL, blindR, linRow_7, linRow_8, linRow_9, Honest.mult, Honest.dig]
  norm_num
  refine ⟨?_, ?_, ?_⟩ <;> ring

/-! ## The linear part is onto -/

/-- `linRow` as an additive map. -/
noncomputable def linMap (τ : F) (h : ℕ → F) : (Fin 15 → F) →+ (Fin 10 → F) :=
  AddMonoidHom.mk' (linRow P ch τ h) fun a b => by
    funext i; fin_cases i <;> simp [linRow] <;> ring

/-- A right inverse of `linRow`: the triangular pivots `r_{O,1}, r_{O,0}, r_{L,0}, r_{R,0},
r_{L,4}, r_{R,4}, r_{L,5}` for `ℓ(τ)`, and `r_{O,2}, r_{L,1}, r_{R,1}` for the commitments, the
other blindings zero. -/
noncomputable def linInv (τ : F) (h : ℕ → F) (y : Fin 10 → F) : Fin 15 → F :=
  let β := ch.β
  let δ := ch.δ
  let Λ := fun i => ch.lam ^ P.g i
  let L5 := -τ * y 6
  let R4 := -τ * y 5
  let L4 := τ * (τ * L5 - y 4)
  let R0 := Λ 3 * R4 + β * τ * (y 3 - τ * L4 - τ ^ 2 * R4)
  let R1 := (y 9 - R0 - R4 * h 3) / h 0
  let AL := y 8 - β * τ * y 2 - Λ 3 * L4 - Λ 4 * L5 - L4 * h 3 - L5 * h 4 - β * R1
  let AO := δ * y 7 - β * τ * y 1 - h 0 * y 0 + h 0 * τ ^ 2 * R1
  let D := δ * (β ^ 2 - h 0 * (h 1 + Λ 1))
  let O2 := (AL * (β - τ * h 0) - h 0 * AO) / D
  let L1 := (β * δ * AO - δ * (h 1 + Λ 1 - β * τ) * AL) / D
  let O0 := (β * τ * (y 1 - δ * O2) + β * L1 + δ * Λ 1 * O2) / δ
  let O1 := (y 0 - τ * L1 - τ ^ 2 * R1) / δ
  let L0 := β * τ * y 2 + β * δ * O2 + β * R1 + Λ 3 * L4 + Λ 4 * L5
  ![O0, O1, O2, 0, 0, 0, L0, L1, 0, L4, L5, R0, R1, 0, R4]

lemma linRow_linInv (τ : F) (h : ℕ → F) (hτ : τ ≠ 0) (hβ : ch.β ≠ 0) (hδ : ch.δ ≠ 0)
    (hh : h 0 ≠ 0) (hD : ch.β ^ 2 - h 0 * (h 1 + ch.lam ^ P.g 1) ≠ 0) (y : Fin 10 → F) :
    linRow P ch τ h (linInv P ch τ h y) = y := by
  funext i
  fin_cases i <;> simp [linRow, linInv] <;> field_simp <;> ring

/-! ## The opening and the commitments are uniform -/

variable (h gg : ℕ → F)

/-- What the verifier sees before `C_S` and the norm-linear messages, as field elements:
`(n(τ), ℓ(τ)_7)` from the masks, then `ℓ(τ)_0, ..., ℓ(τ)_6` and the discrete logs of `C_O`,
`C_L`, `C_R`. -/
noncomputable def realY (x : Masks F P × (Fin 15 → F)) : ((Fin P.nm → F) × F) × (Fin 10 → F) :=
  let w := zkOpening P ch d s x.1 x.2
  ((fun k => evalAt τ (n P ch w k), evalAt τ (ℓ ch w 7)),
    ![evalAt τ (ℓ ch w 0), evalAt τ (ℓ ch w 1), evalAt τ (ℓ ch w 2), evalAt τ (ℓ ch w 3),
      evalAt τ (ℓ ch w 4), evalAt τ (ℓ ch w 5), evalAt τ (ℓ ch w 6), dlogO P h gg w,
      dlogL P h gg w, dlogR P h gg w])

/-- The masks give `n(τ)` and `ℓ(τ)_7` bijectively, each with coefficient `τ⁻¹`. -/
noncomputable def maskEquiv : Masks F P ≃ (Fin P.nm → F) × F where
  toFun m := (fun k => (τ : F)⁻¹ * m.1 k + evalAt τ (n P ch (zkOpening P ch d s 0 0) k),
    (τ : F)⁻¹ * m.2)
  invFun y := (fun k => (τ : F) * (y.1 k - evalAt τ (n P ch (zkOpening P ch d s 0 0) k)),
    (τ : F) * y.2)
  left_inv m := by
    obtain ⟨m1, m2⟩ := m
    have := τ.ne_zero
    ext k <;> simp
  right_inv y := by
    obtain ⟨y1, y2⟩ := y
    have := τ.ne_zero
    ext k <;> simp

lemma realY_fst (m : Masks F P) (b : Fin 15 → F) :
    (realY P ch d s τ h gg (m, b)).1 = maskEquiv P ch d s τ m := by
  have hz : ∀ k : Fin P.nm, (zkOpening P ch d s 0 0).nS k = 0 := fun k => by
    simp [zkOpening, Honest.opening, zkHonest]
  refine Prod.ext (funext fun k => ?_) ?_
  · simp only [realY, maskEquiv, Equiv.coe_fn_mk]
    rw [eval_n, eval_n, hz]
    simp only [zkOpening, Honest.opening, zkHonest, zpow_neg_one, dif_pos k.isLt, Fin.eta]
    simp [Honest.mult, Honest.dig]
    ring
  · simp only [realY, maskEquiv, Equiv.coe_fn_mk]
    rw [eval_ℓ _ _ _ _ (by norm_num)]
    simp [zkOpening, Honest.opening, zkHonest, lin]

lemma realY_snd (m : Masks F P) (b : Fin 15 → F) :
    (realY P ch d s τ h gg (m, b)).2 = (realY P ch d s τ h gg (m, 0)).2 + linRow P ch τ h b := by
  obtain ⟨hO, hL, hR⟩ := dlog_blind P ch d s τ h gg m b
  funext i
  fin_cases i
  · exact ell_blind P ch d s τ h m b 0
  · exact ell_blind P ch d s τ h m b 1
  · exact ell_blind P ch d s τ h m b 2
  · exact ell_blind P ch d s τ h m b 3
  · exact ell_blind P ch d s τ h m b 4
  · exact ell_blind P ch d s τ h m b 5
  · exact ell_blind P ch d s τ h m b 6
  · exact hO
  · exact hL
  · exact hR

/-- **The view is uniform.** Under uniform masks and blindings, `(n(τ), ℓ(τ))` and the
discrete logs of `C_O`, `C_L`, `C_R` are uniform and independent. -/
lemma map_realY [Fintype F] [DecidableEq F] [SampleableType F] (hβ : ch.β ≠ 0) (hδ : ch.δ ≠ 0)
    (hh : h 0 ≠ 0) (hD : ch.β ^ 2 - h 0 * (h 1 + ch.lam ^ P.g 1) ≠ 0) :
    realY P ch d s τ h gg <$> ($ᵗ (Masks F P × (Fin 15 → F))) =ᵈ
      $ᵗ (((Fin P.nm → F) × F) × (Fin 10 → F)) := by
  have hY : realY P ch d s τ h gg = fun x => (maskEquiv P ch d s τ x.1,
      (realY P ch d s τ h gg (x.1, 0)).2 + linMap P ch τ h x.2) := by
    funext x
    obtain ⟨m, b⟩ := x
    exact Prod.ext (realY_fst P ch d s τ h gg m b) (realY_snd P ch d s τ h gg m b)
  refine map_uniform_of_card_fiber _ ((univ.filter fun b => linMap P ch τ h b = 0).card)
    fun y => ?_
  rw [hY]
  exact card_fiber_affine (maskEquiv P ch d s τ) (fun m => (realY P ch d s τ h gg (m, 0)).2)
    (linMap P ch τ h) (linInv P ch τ h)
    (linRow_linInv P ch τ h τ.ne_zero hβ hδ hh hD) y

/-! ## The simulator -/

variable {E : Type} [AddCommGroup E] [Module F E] (g : E) (H G : ℕ → E)

/-- What the verifier sees before the norm-linear messages: `C_O`, `C_L`, `C_R`, `C_S` and the
opening `(ℓ(τ), n(τ))` of `C(τ)`, from which the norm-linear prover computes its messages. -/
abbrev View (F E : Type*) (P : Params) := E × E × E × E × (Fin 8 → F) × (Fin P.nm → F)

/-- The honest prover's view, with masks `x.1` and blindings `x.2`. -/
noncomputable def realView (x : Masks F P × (Fin 15 → F)) : View F E P :=
  let w := zkOpening P ch d s x.1 x.2
  (cO P g H G w, cL P g H G w, cR P g H G w, cS P g H G w, fun j => evalAt τ (ℓ ch w j),
    fun k => evalAt τ (n P ch w k))

/-- **The simulator.** From uniform `(n(τ), ℓ(τ)_7)`, `ℓ(τ)_0, ..., ℓ(τ)_6` and discrete logs of
`C_O`, `C_L`, `C_R` (over `g`), it sets `σ(τ) = ⟨c(τ), ℓ(τ)⟩ + ‖n(τ)‖²_μ` and solves `C_S` from
the opening identity of (25). It uses only the inputs `V`, the generators and the challenges. -/
noncomputable def simView (V : ℕ → E) (y : ((Fin P.nm → F) × F) × (Fin 10 → F)) : View F E P :=
  let ℓv : Fin 8 → F := fun j => if hj : (j : ℕ) < 7 then y.2 ⟨j, by omega⟩ else y.1.2
  let ℓe : ℕ → F := fun j => if hj : j < 8 then ℓv ⟨j, hj⟩ else 0
  let ne : ℕ → F := fun k => if hk : k < P.nm then y.1.1 ⟨k, hk⟩ else 0
  let σ := ∑ j ∈ range 8, evalAt τ (c P ch j) * ℓe j +
    ∑ k ∈ range P.nm, ch.μ ^ (k + 1) * (ne k * ne k)
  let cO := y.2 7 • g
  let cL := y.2 8 • g
  let cR := y.2 9 • g
  (cO, cL, cR, (τ : F) • (commit P g H G σ ℓe ne - evalAt τ (ps P ch) • g -
      NormLinear.msm P.nm (fun k => evalAt τ (pn P ch k)) G - ch.δ • cO - (τ : F) • cL -
      (τ : F) ^ 2 • cR - (τ : F) ^ 3 • vHat P ch V), ℓv, y.1.1)

lemma realView_eq (hH : ∀ j, H j = h j • g) (hG : ∀ k, G k = gg k • g)
    (hα : ∀ j : ℕ, j < 16 → ch.α + j ≠ 0) (hβ : ch.β ≠ 0) (hδ : ch.δ ≠ 0) (hμ : ch.μ ≠ 0)
    (hd : ∀ i < P.M, ∀ t < P.D, d i t < 16) (x : Masks F P × (Fin 15 → F)) :
    realView P ch d s τ g H G x = simView P ch τ g H G
      (Honest.inputs (P := P) g H (zkHonest P d s 0 0)) (realY P ch d s τ h gg x) := by
  obtain ⟨m, b⟩ := x
  set w := zkOpening P ch d s m b with hw
  have hℓ : ∀ j : Fin 8, (if hj : (j : ℕ) < 7 then (realY P ch d s τ h gg (m, b)).2 ⟨j, by omega⟩
      else (realY P ch d s τ h gg (m, b)).1.2) = evalAt τ (ℓ ch w j) := fun j => by
    fin_cases j <;> rfl
  have hcO : cO P g H G w = dlogO P h gg w • g := commit_dlog P g H G h gg hH hG _ _ _
  have hcL : cL P g H G w = dlogL P h gg w • g := commit_dlog P g H G h gg hH hG _ _ _
  have hcR : cR P g H G w = dlogR P h gg w • g := commit_dlog P g H G h gg hH hG _ _ _
  refine Prod.ext hcO (Prod.ext hcL (Prod.ext hcR (Prod.ext ?_ (Prod.ext
    (funext fun j => (hℓ j).symm) rfl))))
  -- `C_S` from the opening identity.
  have hf : f P ch w = 0 := completeness P ch (zkHonest P d s m b) hα hβ hδ hμ hd
    (zkHonest_zeroPattern P d s m b)
  have hσ := eval_f P ch τ w
  rw [hf, map_zero] at hσ
  have hcomb : combined P g G ch τ (cS P g H G w) (cO P g H G w) (cL P g H G w) (cR P g H G w)
      (vHat P ch (Honest.inputs (P := P) g H (zkHonest P d s 0 0))) =
      commit P g H G (evalAt τ (σ P ch w)) (fun j => evalAt τ (ℓ ch w j))
        (fun k => evalAt τ (n P ch w k)) := by
    rw [show Honest.inputs (P := P) g H (zkHonest P d s 0 0) =
      Honest.inputs (P := P) g H (zkHonest P d s m b) from rfl,
      vHat_honest P g H G ch (zkHonest P d s m b) ((zkHonest P d s m b).rS P ch)]
    exact combined_eq P g H G ch τ w
  have hℓe : ∀ j < 8, (fun j => if hj : j < 8 then (fun j : Fin 8 =>
      if hj : (j : ℕ) < 7 then (realY P ch d s τ h gg (m, b)).2 ⟨j, by omega⟩
      else (realY P ch d s τ h gg (m, b)).1.2) ⟨j, hj⟩ else 0) j = evalAt τ (ℓ ch w j) :=
    fun j hj => by simp only [dif_pos hj]; exact hℓ ⟨j, hj⟩
  have hne : ∀ k < P.nm, (fun k => if hk : k < P.nm then (realY P ch d s τ h gg (m, b)).1.1
      ⟨k, hk⟩ else 0) k = evalAt τ (n P ch w k) := fun k hk => by simp [dif_pos hk, realY, hw]
  simp only [realView, simView]
  rw [commit_congr P g H G _ hℓe hne]
  have e7 : (realY P ch d s τ h gg (m, b)).2 7 • g = cO P g H G w := hcO.symm
  have e8 : (realY P ch d s τ h gg (m, b)).2 8 • g = cL P g H G w := hcL.symm
  have e9 : (realY P ch d s τ h gg (m, b)).2 9 • g = cR P g H G w := hcR.symm
  have hs : (∑ x ∈ range 8, evalAt τ (c P ch x) * (if h_1 : x < 8 then
      (if h_2 : x < 7 then (realY P ch d s τ h gg (m, b)).2 ⟨x, by omega⟩
        else (realY P ch d s τ h gg (m, b)).1.2) else 0)) +
      ∑ x ∈ range P.nm, ch.μ ^ (x + 1) *
        ((if hk : x < P.nm then (realY P ch d s τ h gg (m, b)).1.1 ⟨x, hk⟩ else 0) *
          (if hk : x < P.nm then (realY P ch d s τ h gg (m, b)).1.1 ⟨x, hk⟩ else 0)) =
      evalAt τ (σ P ch w) := by
    have s1 : ∑ x ∈ range 8, evalAt τ (c P ch x) * (if h_1 : x < 8 then
        (if h_2 : x < 7 then (realY P ch d s τ h gg (m, b)).2 ⟨x, by omega⟩
          else (realY P ch d s τ h gg (m, b)).1.2) else 0) =
        ∑ x ∈ range 8, evalAt τ (c P ch x) * evalAt τ (ℓ ch w x) :=
      sum_congr rfl fun x hx => by rw [← hℓe x (mem_range.1 hx)]
    have s2 : ∑ x ∈ range P.nm, ch.μ ^ (x + 1) *
        ((if hk : x < P.nm then (realY P ch d s τ h gg (m, b)).1.1 ⟨x, hk⟩ else 0) *
          (if hk : x < P.nm then (realY P ch d s τ h gg (m, b)).1.1 ⟨x, hk⟩ else 0)) =
        ∑ x ∈ range P.nm, ch.μ ^ (x + 1) * (evalAt τ (n P ch w x) * evalAt τ (n P ch w x)) :=
      sum_congr rfl fun x hx => by rw [← hne x (mem_range.1 hx)]
    rw [s1, s2]
    linear_combination hσ
  rw [hs, e7, e8, e9, ← hcomb]
  simp only [combined, smul_sub, smul_add, smul_smul]
  rw [zpow_neg_one, mul_inv_cancel₀ τ.ne_zero, one_smul]
  abel

/-- **Honest-verifier zero-knowledge** (Theorem 1). Fix challenges with `α ∉ {0, -1, ..., -15}`,
`μ, β, δ ≠ 0`, and generators in the span of `g`, `H_j = h_j g`, with `h_0 ≠ 0` and
`β² ≠ h_0 (h_1 + λ^{g_1})`. For digits `d` in base 16 and input blindings `s`, the honest prover's
`C_O`, `C_L`, `C_R`, `C_S` and opening `(ℓ(τ), n(τ))` of `C(τ)`, under uniform masks and blindings,
have the distribution of `simView`, which sees only the inputs `V_i = v_i g + s_i H_0`, the
generators and the challenges. The norm-linear messages are computed from the opening. -/
lemma zero_knowledge [Fintype F] [DecidableEq F] [SampleableType F] (hH : ∀ j, H j = h j • g)
    (hG : ∀ k, G k = gg k • g) (hα : ∀ j : ℕ, j < 16 → ch.α + j ≠ 0) (hμ : ch.μ ≠ 0)
    (hβ : ch.β ≠ 0) (hδ : ch.δ ≠ 0) (hh : h 0 ≠ 0)
    (hD : ch.β ^ 2 - h 0 * (h 1 + ch.lam ^ P.g 1) ≠ 0) (hd : ∀ i < P.M, ∀ t < P.D, d i t < 16) :
    realView P ch d s τ g H G <$> ($ᵗ (Masks F P × (Fin 15 → F))) =ᵈ
      simView P ch τ g H G (Honest.inputs (P := P) g H (zkHonest P d s 0 0)) <$>
        ($ᵗ (((Fin P.nm → F) × F) × (Fin 10 → F))) := by
  rw [show realView P ch d s τ g H G = simView P ch τ g H G
      (Honest.inputs (P := P) g H (zkHonest P d s 0 0)) ∘ realY P ch d s τ h gg from
    funext (realView_eq P ch d s τ h gg g H G hH hG hα hβ hδ hμ hd), LawfulFunctor.comp_map]
  exact (map_realY P ch d s τ h gg hβ hδ hh hD).map _

end Honest

end Bppp.Spec
