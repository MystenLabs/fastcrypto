-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Spec.Honest
import bulletproofspp.Proofs.Spec.NormLinear

/-!
# Commitments and the combined commitment

The norm-linear commitments (22) and the combined commitment `C(τ)` (25) the verifier forms, over
any `F`-module `E` in place of the group, with generators `g` (the paper's `G`), `H_0, ..., H_7`
and `G_0, ..., G_{nm-1}`.
-/

open Finset LaurentPolynomial

namespace Bppp.Spec

variable {F E : Type*} [Field F] [AddCommGroup E] [Module F E]
variable (P : Params) (g : E) (H G : ℕ → E)

/-- The norm-linear commitment `σg + ⟨ℓ, H⟩ + ⟨n, G⟩`, with `ℓ ∈ F⁸` and `n ∈ F^{nm}`. -/
def commit (σ : F) (ℓ n : ℕ → F) : E :=
  σ • g + NormLinear.msm 8 ℓ H + NormLinear.msm P.nm n G

/-- The `H`-coordinates `r_{X,1:7} ‖ ℓ_X` of a commitment (22). -/
def lin (r : ℕ → F) (ℓX : F) : ℕ → F := fun s => if s < 7 then r (s + 1) else ℓX

variable (w : Opening F)

/-- `C_S`, `C_O`, `C_L`, `C_R` (22) for the opening `w`. -/
def cS : E := commit P g H G (w.rS 0) (lin w.rS w.ℓS) w.nS
def cO : E := commit P g H G (w.rO 0) (lin w.rO w.ℓO) w.nO
def cL : E := commit P g H G (w.rL 0) (lin w.rL w.ℓL) w.nL
def cR : E := commit P g H G (w.rR 0) (lin w.rR w.ℓR) w.nR

variable {P} in
/-- The inputs `V_i = v_i g + s_i H_0` of an honest prover. -/
def Honest.inputs (h : Honest F) (i : ℕ) : E := h.value P i • g + h.s i • H 0

variable (ch : Challenges F) (τ : Fˣ)

/-- The combined commitment (25), `C(τ) = P(τ) + τ⁻¹C_S + δC_O + τC_L + τ²C_R + τ³V̂` with
`P(τ) = p_s(τ)g + ⟨p_n(τ), G⟩`, from public data and the messages alone. -/
noncomputable def combined (cS cO cL cR vHat : E) : E :=
  evalAt τ (ps P ch) • g + NormLinear.msm P.nm (fun k => evalAt τ (pn P ch k)) G +
    (τ : F) ^ (-1 : ℤ) • cS + ch.δ • cO + (τ : F) • cL + (τ : F) ^ 2 • cR + (τ : F) ^ 3 • vHat

/-- `V̂ = 2Σ_i λ^i V_i` (21). -/
noncomputable def vHat (V : ℕ → E) : E := (2 : F) • ∑ i ∈ range P.M, ch.lam ^ i • V i

/-! ## `C(τ)` commits to the evaluated opening -/

section

variable (P : Params) (g : E) (H G : ℕ → E) (ch : Challenges F) (τ : Fˣ)

/-- `C(τ)` is linear in the openings of the commitments it combines. -/
lemma combined_commit (σS σO σL σR σV : F) (ℓS ℓO ℓL ℓR ℓV nS nO nL nR nV : ℕ → F) :
    combined P g G ch τ (commit P g H G σS ℓS nS) (commit P g H G σO ℓO nO)
      (commit P g H G σL ℓL nL) (commit P g H G σR ℓR nR) (commit P g H G σV ℓV nV) =
    commit P g H G
      (evalAt τ (ps P ch) + (τ : F) ^ (-1 : ℤ) * σS + ch.δ * σO + (τ : F) * σL +
        (τ : F) ^ 2 * σR + (τ : F) ^ 3 * σV)
      (fun s => (τ : F) ^ (-1 : ℤ) * ℓS s + ch.δ * ℓO s + (τ : F) * ℓL s + (τ : F) ^ 2 * ℓR s +
        (τ : F) ^ 3 * ℓV s)
      (fun k => evalAt τ (pn P ch k) + (τ : F) ^ (-1 : ℤ) * nS k + ch.δ * nO k +
        (τ : F) * nL k + (τ : F) ^ 2 * nR k + (τ : F) ^ 3 * nV k) := by
  simp only [combined, commit, NormLinear.msm, smul_add, smul_sum, smul_smul, add_smul,
    sum_add_distrib]
  module

variable (w : Opening F)

/-- `C(τ)` commits to the evaluated opening `(σ(τ), ℓ(τ), n(τ))` (26), for any opening. -/
lemma combined_eq (w : Opening F) :
    combined P g G ch τ (cS P g H G w) (cO P g H G w) (cL P g H G w) (cR P g H G w)
      (commit P g H G w.vhat (lin w.rV w.ℓV) w.nV) =
    commit P g H G (evalAt τ (σ P ch w)) (fun s => evalAt τ (ℓ ch w s))
      (fun k => evalAt τ (n P ch w k)) := by
  rw [cS, cO, cL, cR, combined_commit]
  congr 1
  case e_σ =>
    simp only [σ, map_add, evalAt_mono, zpow_ofNat]; ring
  case e_ℓ =>
    funext s; simp only [lin, ℓ]; split_ifs <;> simp only [map_add, evalAt_mono, zpow_ofNat] <;> ring
  case e_n =>
    funext k; simp only [n, pn, map_add, evalAt_mono, zpow_ofNat]; ring

variable (h : Honest F)

/-- The honest inputs aggregate to the commitment to the input coordinates of the opening:
`2Σ_i λ^i V_i = v̂g + r_{V,1}H_0`. -/
lemma vHat_honest (rS : ℕ → F) :
    vHat P ch (Honest.inputs (P := P) g H h) = commit P g H G (h.opening P ch rS).vhat
      (lin (h.opening P ch rS).rV (h.opening P ch rS).ℓV) (h.opening P ch rS).nV := by
  have h8 : NormLinear.msm 8 (lin (h.opening P ch rS).rV (h.opening P ch rS).ℓV) H =
      (2 * ∑ i ∈ range P.M, ch.lam ^ i * h.s i) • H 0 := by
    simp [NormLinear.msm, lin, Honest.opening, sum_range_succ]
  rw [commit, h8]
  simp only [vHat, Honest.inputs, Honest.opening, NormLinear.msm, zero_smul, sum_const_zero,
    add_zero, smul_add, sum_add_distrib, smul_sum, smul_smul, mul_sum, sum_smul]

end

end Bppp.Spec
