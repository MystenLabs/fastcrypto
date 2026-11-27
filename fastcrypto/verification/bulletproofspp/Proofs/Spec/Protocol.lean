-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Spec.Poly

/-!
# The batched range proof

The public data, openings and error polynomial of §5.1 of
[ePrint 2026/2648](https://eprint.iacr.org/2026/2648), with equation numbers from there.

Vectors are functions `ℕ → F`, and only their first `nm` entries are used. Inputs are indexed
`i = 0, ..., M-1`, so the paper's `λ^{i-1}` is `λ^i` here. Entry `s = 0, ..., 7` of `ℓ(T)` and
`c(T)` is the paper's entry `s + 1`: for `s < 7` it is the coordinate on `H_s`, carrying the
blinding `r_{X,s+1}`, and `s = 7` is the `H_7`-coordinate.
-/

open Finset LaurentPolynomial

namespace Bppp.Spec

variable {F : Type*} [Field F]

/-- The parameters (20): batch size `M`, digits per value `D` and norm length `nm`. -/
structure Params where
  M : ℕ
  D : ℕ
  nm : ℕ
  hnm : M * D ≤ nm
  h15 : 15 ≤ nm

namespace Params

variable (P : Params)

/-- The number of digits `N_d = M*D`. -/
def Nd : ℕ := P.M * P.D

/-- The shape exponents `g_m = M(nm+m)+1` (23). -/
def g (m : ℕ) : ℕ := P.M * (P.nm + m) + 1

end Params

/-- The verifier's challenges `α` (step 2) and `μ = ρ²`, `λ`, `β`, `δ` (step 4). -/
structure Challenges (F : Type*) where
  α : F
  μ : F
  lam : F
  β : F
  δ : F

variable (P : Params) (ch : Challenges F)

/-! ## Public data (23) and (24) -/

/-- `c_{n,L}`. -/
noncomputable def cnL (k : ℕ) : F :=
  if k < P.Nd then ch.lam ^ (k / P.D) * 16 ^ (k % P.D) / ch.μ ^ (k + 1) else 0

/-- `c_{n,R}`. -/
noncomputable def cnR (k : ℕ) : F :=
  if k < P.Nd then ch.lam ^ P.M / ch.μ ^ (k + 1) + ch.α else 0

/-- `c_{n,O}`. -/
noncomputable def cnO (k : ℕ) : F :=
  if k ≤ 14 then (k + 1) * ch.lam ^ P.M / (ch.α * (ch.α + (k + 1)) * ch.μ ^ (k + 1)) else 0

/-- `c_{n,V}`. -/
noncomputable def cnV (k : ℕ) : F := ch.lam ^ (P.M * (k + 1) + 1) / ch.μ ^ (k + 1)

/-- `c_{ℓ,V} = (0, λ^{g_1}, ..., λ^{g_7})`. -/
noncomputable def clV (s : ℕ) : F := if s = 0 then 0 else ch.lam ^ P.g s

/-- `λ_al = N_d λ^M / α`. -/
noncomputable def lamAl : F := P.Nd * ch.lam ^ P.M / ch.α

/-- `μ_am = Σ_{k=1}^{N_d} μ^k`. -/
noncomputable def muAm : F := ∑ k ∈ range P.Nd, ch.μ ^ (k + 1)

/-- The powers of `T` in `ĉ_r(T) = β(T^{-1}, T, T^2, T^3, T^5, T^6, T^7 ‖ 0)`. -/
def e : ℕ → ℤ
  | 0 => -1
  | 1 => 1
  | 2 => 2
  | 3 => 3
  | 4 => 5
  | 5 => 6
  | _ => 7

/-- The weighted norm `‖v‖²_μ = Σ_k μ^{k+1} v_k²`. -/
noncomputable def normμ (v : ℕ → F[T;T⁻¹]) : F[T;T⁻¹] :=
  ∑ k ∈ range P.nm, mono 0 (ch.μ ^ (k + 1)) * (v k * v k)

/-- `p_n(T) = c_{n,V} + T c_{n,R} + T² c_{n,L} + δ⁻¹ T³ c_{n,O}`. -/
noncomputable def pn (k : ℕ) : F[T;T⁻¹] :=
  mono 0 (cnV P ch k) + mono 1 (cnR P ch k) + mono 2 (cnL P ch k) + mono 3 (ch.δ⁻¹ * cnO P ch k)

/-- `p_s(T) = ‖p_n(T)‖²_μ + 2(λ_al + μ_am)T³`. -/
noncomputable def ps : F[T;T⁻¹] :=
  normμ P ch (pn P ch) + mono 3 (2 * (lamAl P ch + muAm P ch))

/-- `c(T) = ĉ_r(T) + c_{ℓ,V}`. -/
noncomputable def c (s : ℕ) : F[T;T⁻¹] :=
  (if s < 7 then mono (e s) ch.β else 0) + mono 0 (clV P ch s)

/-! ## Openings (21), (22) and the Laurent vectors (26) -/

/-- The openings of `C_S`, `C_O`, `C_L`, `C_R` (22) and the coordinates of `V̂` (21). -/
structure Opening (F : Type*) where
  nS : ℕ → F
  nO : ℕ → F
  nL : ℕ → F
  nR : ℕ → F
  ℓS : F
  /-- Blindings `r_{X,0..7}`. -/
  rS : ℕ → F
  rO : ℕ → F
  rL : ℕ → F
  rR : ℕ → F
  /-- `v̂`, the `G`-coordinate of `V̂`. -/
  vhat : F
  /-- `r_{V,j}`, the `H_{j-1}`-coordinate of `V̂`, for `j = 1..7`. -/
  rV : ℕ → F
  /-- `ℓ_V̂`, the `H_7`-coordinate of `V̂`. -/
  ℓV : F
  /-- `ℓ_O`, `ℓ_L`, `ℓ_R`, the `H_7`-coordinates of `C_O`, `C_L`, `C_R`; zero for an honest
  prover. -/
  ℓO : F
  ℓL : F
  ℓR : F
  /-- `n_V̂`, the `𝐆`-coordinates of `V̂`. -/
  nV : ℕ → F

variable (w : Opening F)

/-- `n(T) = T⁻¹n_S + δn_O + Tn_L + T²n_R + T³n_V̂ + p_n(T)`. -/
noncomputable def n (k : ℕ) : F[T;T⁻¹] :=
  mono (-1) (w.nS k) + mono 0 (ch.δ * w.nO k) + mono 1 (w.nL k) + mono 2 (w.nR k) +
    mono 3 (w.nV k) + pn P ch k

/-- `ℓ(T) = (ℓ_1(T), ..., ℓ_7(T) ‖ T⁻¹ℓ_S + δℓ_O + Tℓ_L + T²ℓ_R + T³ℓ_V̂)`. -/
noncomputable def ℓ (s : ℕ) : F[T;T⁻¹] :=
  if s < 7 then
    mono (-1) (w.rS (s + 1)) + mono 0 (ch.δ * w.rO (s + 1)) + mono 1 (w.rL (s + 1)) +
      mono 2 (w.rR (s + 1)) + mono 3 (w.rV (s + 1))
  else mono (-1) w.ℓS + mono 0 (ch.δ * w.ℓO) + mono 1 w.ℓL + mono 2 w.ℓR + mono 3 w.ℓV

/-- `σ(T) = p_s(T) + v̂T³ + r_0(T)`. -/
noncomputable def σ : F[T;T⁻¹] :=
  ps P ch + mono 3 w.vhat +
    (mono (-1) (w.rS 0) + mono 0 (ch.δ * w.rO 0) + mono 1 (w.rL 0) + mono 2 (w.rR 0))

/-- The error polynomial `f(T) = σ(T) - ⟨c(T), ℓ(T)⟩ - ‖n(T)‖²_μ` (28). -/
noncomputable def f : F[T;T⁻¹] :=
  σ P ch w - ∑ s ∈ range 8, c P ch s * ℓ ch w s - normμ P ch (n P ch w)

end Bppp.Spec
