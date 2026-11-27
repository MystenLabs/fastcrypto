-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Spec.Protocol

/-!
# The honest prover

The honest witness placement of §5.1, after (22), for inputs `V_i = v_i G + s_i H_0` on the
`(G, H_0)`-plane, and the prover's choice of the blinding `r_S` of `C_S`.
-/

open Finset LaurentPolynomial

namespace Bppp.Spec

variable {F : Type*} [Field F]

/-- The honest prover's choices: base-16 digits `d i t` of value `i`, the blindings `s_i` of the
inputs, the masks `n_S`, `ℓ_S` and the blindings of `C_O`, `C_L`, `C_R`. -/
structure Honest (F : Type*) where
  d : ℕ → ℕ → ℕ
  s : ℕ → F
  nS : ℕ → F
  ℓS : F
  rO : ℕ → F
  rL : ℕ → F
  rR : ℕ → F

/-- The zero pattern (22) of the blindings of `C_O`, `C_L`, `C_R`. -/
structure Honest.ZeroPattern (h : Honest F) : Prop where
  rO4 : h.rO 4 = 0
  rO7 : h.rO 7 = 0
  rL3 : h.rL 3 = 0
  rL6 : h.rL 6 = 0
  rL7 : h.rL 7 = 0
  rR2 : h.rR 2 = 0
  rR5 : h.rR 5 = 0
  rR6 : h.rR 6 = 0
  rR7 : h.rR 7 = 0

variable (P : Params) (ch : Challenges F) (h : Honest F)

/-- The digit in slot `k = D*i + t`, zero on the padding `k ≥ N_d`. -/
def Honest.dig (k : ℕ) : ℕ := if k < P.Nd then h.d (k / P.D) (k % P.D) else 0

/-- The value `v_i = Σ_t 16^t d_{i,t}`. -/
def Honest.value (i : ℕ) : F := ∑ t ∈ range P.D, (16 : F) ^ t * h.d i t

/-- The multiplicity `m_j = |{k < N_d : d_k = j}|`. -/
def Honest.mult (j : ℕ) : ℕ := ((range P.Nd).filter fun k => h.dig P k = j).card

/-- The honest opening, with the blinding `rS` of `C_S`. -/
noncomputable def Honest.opening (rS : ℕ → F) : Opening F where
  nS := h.nS
  nO k := if k < 15 then (h.mult P (k + 1) : F) else 0
  nL k := h.dig P k
  nR k := if k < P.Nd then (ch.α + h.dig P k)⁻¹ else 0
  ℓS := h.ℓS
  rS := rS
  rO := h.rO
  rL := h.rL
  rR := h.rR
  vhat := 2 * ∑ i ∈ range P.M, ch.lam ^ i * h.value P i
  rV j := if j = 1 then 2 * ∑ i ∈ range P.M, ch.lam ^ i * h.s i else 0
  ℓV := 0
  nV _ := 0
  ℓO := 0
  ℓL := 0
  ℓR := 0

/-- The blinding `r_S` that cancels every coefficient of `f(T)` other than `T³`: with
`g(T) = f(T)` at `r_S = 0`, the entry `r_{S,s+1}` cancels `T^{e_s - 1}` and `r_{S,0}` cancels
`T⁻¹`. -/
noncomputable def Honest.rS : ℕ → F := fun j =>
  let g := f P ch (h.opening P ch 0)
  if j = 0 then
    (∑ s ∈ range 7, clV P ch s * (coeff (e s - 1) g / ch.β)) - coeff (-1) g
  else coeff (e (j - 1) - 1) g / ch.β

end Bppp.Spec
