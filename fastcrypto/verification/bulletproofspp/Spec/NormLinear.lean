-- THIS FILE IS AI-ONLY
import Mathlib.Tactic

/-!
# The norm-linear argument

The folding argument of §4.9 of [ePrint 2026/2648](https://eprint.iacr.org/2026/2648) (and
[bp++ §4]), over any `F`-module `E` in place of the group. It proves knowledge of an opening of
`C = σg + ⟨ℓ, H⟩ + ⟨n, G⟩` satisfying `σ = ⟨c, ℓ⟩ + ‖n‖²_μ` with `μ = ρ²` (19).

A vector of length `L` is a function `ℕ → F` of which only the first `L` entries are used.
Each round zero-pads the vectors to even length and splits them into their even- and odd-indexed
halves `[v]₀`, `[v]₁`.
-/

open Finset

namespace Bppp.Spec.NormLinear

variable {F E : Type*} [Field F] [AddCommGroup E] [Module F E]

section Vectors

variable {α : Type*} [Zero α]

/-- `v`, zero-padded beyond its length `L`. -/
def pad (L : ℕ) (v : ℕ → α) : ℕ → α := fun k => if k < L then v k else 0

/-- The even-indexed half `[v]₀` of `v` padded to even length. -/
def ev (L : ℕ) (v : ℕ → α) : ℕ → α := fun i => pad L v (2 * i)

/-- The odd-indexed half `[v]₁` of `v` padded to even length. -/
def od (L : ℕ) (v : ℕ → α) : ℕ → α := fun i => pad L v (2 * i + 1)

end Vectors

/-- The length `⌈L/2⌉` of a half. -/
def half (L : ℕ) : ℕ := (L + 1) / 2

/-- `⟨a, b⟩`. -/
def ip (L : ℕ) (a b : ℕ → F) : F := ∑ k ∈ range L, a k * b k

/-- `⟨a, b⟩_μ = Σ_k μ^{k+1} a_k b_k`, so `‖a‖²_μ = ⟨a, a⟩_μ`. -/
def wip (L : ℕ) (μ : F) (a b : ℕ → F) : F := ∑ k ∈ range L, μ ^ (k + 1) * (a k * b k)

/-- `⟨a, G⟩ = Σ_k a_k G_k`. -/
def msm (L : ℕ) (a : ℕ → F) (G : ℕ → E) : E := ∑ k ∈ range L, a k • G k

variable (F E) in
/-- An instance: the commitment `C`, the public vector `c`, the generators `H` and `G` of the
linear and norm parts, their lengths, and the weights `ρ` and `μ = ρ²`. -/
structure Instance where
  C : E
  c : ℕ → F
  H : ℕ → E
  G : ℕ → E
  Lℓ : ℕ
  Ln : ℕ
  ρ : F
  μ : F

variable (F) in
/-- The opening `(ℓ, n)`; `σ` is implied by the relation. -/
structure Witness where
  ℓ : ℕ → F
  n : ℕ → F

variable (g : E) (x : Instance F E) (w : Witness F)

/-- The norm-linear relation (19): `C = σg + ⟨ℓ, H⟩ + ⟨n, G⟩` with `σ = ⟨c, ℓ⟩ + ‖n‖²_μ`. -/
def Rel : Prop :=
  x.C = (ip x.Lℓ x.c w.ℓ + wip x.Ln x.μ w.n w.n) • g + msm x.Lℓ w.ℓ x.H + msm x.Ln w.n x.G

/-- The prover's first message of a round,
`X = v_x g + ⟨[ℓ]₁, [H]₀⟩ + ⟨[ℓ]₀, [H]₁⟩ + ⟨ρ[n]₁, [G]₀⟩ + ⟨ρ⁻¹[n]₀, [G]₁⟩` with
`v_x = 2ρ⁻¹⟨[n]₀, [n]₁⟩_{μ²} + ⟨[c]₀, [ℓ]₁⟩ + ⟨[c]₁, [ℓ]₀⟩`. -/
noncomputable def msgX : E :=
  (2 * x.ρ⁻¹ * wip (half x.Ln) (x.μ ^ 2) (ev x.Ln w.n) (od x.Ln w.n) +
      ip (half x.Lℓ) (ev x.Lℓ x.c) (od x.Lℓ w.ℓ) + ip (half x.Lℓ) (od x.Lℓ x.c) (ev x.Lℓ w.ℓ)) • g +
    msm (half x.Lℓ) (od x.Lℓ w.ℓ) (ev x.Lℓ x.H) + msm (half x.Lℓ) (ev x.Lℓ w.ℓ) (od x.Lℓ x.H) +
    msm (half x.Ln) (fun i => x.ρ * od x.Ln w.n i) (ev x.Ln x.G) +
    msm (half x.Ln) (fun i => x.ρ⁻¹ * ev x.Ln w.n i) (od x.Ln x.G)

/-- The prover's second message of a round,
`R = v_r g + ⟨[ℓ]₁, [H]₁⟩ + ⟨[n]₁, [G]₁⟩` with `v_r = ‖[n]₁‖²_{μ²} + ⟨[c]₁, [ℓ]₁⟩`. -/
noncomputable def msgR : E :=
  (wip (half x.Ln) (x.μ ^ 2) (od x.Ln w.n) (od x.Ln w.n) +
      ip (half x.Lℓ) (od x.Lℓ x.c) (od x.Lℓ w.ℓ)) • g +
    msm (half x.Lℓ) (od x.Lℓ w.ℓ) (od x.Lℓ x.H) + msm (half x.Ln) (od x.Ln w.n) (od x.Ln x.G)

/-- The verifier's fold, from the public instance, the messages `X`, `R` and the challenge `γ`:
`C ← C + γX + (γ²-1)R`, `c' = [c]₀ + γ[c]₁`, `H' = [H]₀ + γ[H]₁`, `G' = ρ[G]₀ + γ[G]₁`,
`ρ ← μ`, `μ ← μ²`. -/
def foldInst (X R : E) (γ : F) : Instance F E where
  C := x.C + γ • X + (γ ^ 2 - 1) • R
  c i := ev x.Lℓ x.c i + γ * od x.Lℓ x.c i
  H i := ev x.Lℓ x.H i + γ • od x.Lℓ x.H i
  G i := x.ρ • ev x.Ln x.G i + γ • od x.Ln x.G i
  Lℓ := half x.Lℓ
  Ln := half x.Ln
  ρ := x.μ
  μ := x.μ ^ 2

/-- The prover's fold: `ℓ' = [ℓ]₀ + γ[ℓ]₁`, `n' = ρ⁻¹[n]₀ + γ[n]₁`. -/
noncomputable def foldWit (γ : F) : Witness F where
  ℓ i := ev x.Lℓ w.ℓ i + γ * od x.Lℓ w.ℓ i
  n i := x.ρ⁻¹ * ev x.Ln w.n i + γ * od x.Ln w.n i

end Bppp.Spec.NormLinear
