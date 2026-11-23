-- THIS FILE IS AI-ONLY
import bulletproofspp.Spec.RowSoundness

/-!
# The circuit extractor

The levels of §5.3 composed. A tree of challenges forks `α` (`N_d + 16`), then `μ = ρ²`
(`nm + 1`), `β` (2), `λ` (`M(nm+8)+1`) and `τ` (13), each challenge depending on the path above
it and `δ` on `α` and `μ`. `C_O`, `C_L` and the inputs are fixed, `C_R` depends on `α` and `C_S`
on the path down to `λ`. If every leaf opens the combined commitment `C(τ)` to a witness of the
norm-linear relation, every input is `v_i g + s_i H_0` with `v_i < 16^D`, or the generators
satisfy a nontrivial relation.
-/

open Finset

namespace Bppp.Spec

variable {F : Type*} [Field F] [DecidableEq F] (P : Params)
variable {E : Type*} [AddCommGroup E] [Module F E] (g : E) (H G : ℕ → E)

/-- `Σ_{t<D} 16^t d_t < 16^D` for digits `d_t < 16`. -/
lemma digits_lt (D : ℕ) (d : ℕ → ℕ) (hd : ∀ t < D, d t < 16) :
    ∑ t ∈ range D, 16 ^ t * d t < 16 ^ D := by
  induction D with
  | zero => simp
  | succ D ih =>
    rw [sum_range_succ, pow_succ]
    have := ih fun t ht => hd t (by omega)
    have := hd D (by omega)
    nlinarith [Nat.one_le_pow D 16 (by norm_num)]

omit [DecidableEq F] in
/-- An opening with no `G`-coordinates and no `H_1, ..., H_7`-coordinates is on the
`(g, H_0)`-plane. -/
lemma commit_plane (u : F) (h n : ℕ → F) (hh : ∀ s, 1 ≤ s → s < 8 → h s = 0)
    (hn : ∀ k < P.nm, n k = 0) : commit P g H G u h n = u • g + h 0 • H 0 := by
  have h8 : NormLinear.msm 8 h H = h 0 • H 0 := by
    simp only [NormLinear.msm, sum_range_succ, sum_range_zero, zero_add]
    simp [hh 1 le_rfl (by norm_num), hh 2 (by norm_num) (by norm_num), hh 3 (by norm_num) (by norm_num),
      hh 4 (by norm_num) (by norm_num), hh 5 (by norm_num) (by norm_num),
      hh 6 (by norm_num) (by norm_num), hh 7 (by norm_num) (by norm_num)]
  have hG : NormLinear.msm P.nm n G = 0 :=
    sum_eq_zero fun k hk => by rw [hn k (mem_range.1 hk), zero_smul]
  rw [commit, h8, hG, add_zero]

/-- The challenges at a node of the tree. -/
def treeCh {A R L : ℕ} (α : Fin A → F) (μ δ : Fin A → Fin R → F) (β : Fin A → Fin R → Fin 2 → F)
    (lam : Fin A → Fin R → Fin 2 → Fin L → F) (a : Fin A) (r : Fin R) (b : Fin 2) (l : Fin L) :
    Challenges F :=
  ⟨α a, μ a r, lam a r b l, β a r b, δ a r⟩

/-- **The circuit extractor.** For a tree of challenges in the good set, with distinct values at
every fork, whose every leaf opens `C(τ)` to a norm-linear witness, every input `V_i` is
`v_i g + s_i H_0` with `v_i < 16^D`, or the generators satisfy a nontrivial linear relation. It
assumes `2 ≠ 0`, that no `m = 1, ..., N_d` is zero in the field, and a nonempty batch. -/
lemma circuit_extract (h2 : (2 : F) ≠ 0) (hchar : ∀ m : ℕ, 0 < m → m ≤ P.Nd → (m : F) ≠ 0)
    (hM : 0 < P.M) (V : ℕ → E) (cO cL : E) (cR : Fin (P.Nd + 16) → E)
    (cS : Fin (P.Nd + 16) → Fin (P.nm + 1) → Fin 2 → Fin (P.M * (P.nm + 8) + 1) → E)
    (α : Fin (P.Nd + 16) → F) (μ δ rho : Fin (P.Nd + 16) → Fin (P.nm + 1) → F)
    (β : Fin (P.Nd + 16) → Fin (P.nm + 1) → Fin 2 → F)
    (lam : Fin (P.Nd + 16) → Fin (P.nm + 1) → Fin 2 → Fin (P.M * (P.nm + 8) + 1) → F)
    (τ : Fin (P.Nd + 16) → Fin (P.nm + 1) → Fin 2 → Fin (P.M * (P.nm + 8) + 1) → Fin 13 → Fˣ)
    (hα : Function.Injective α) (hμ : ∀ a, Function.Injective (μ a))
    (hβ : ∀ a r, Function.Injective (β a r)) (hlam : ∀ a r b, Function.Injective (lam a r b))
    (hτ : ∀ a r b l, Function.Injective (τ a r b l))
    (hpole : ∀ a, ∀ j : ℕ, j < 16 → α a + j ≠ 0) (hμ0 : ∀ a r, μ a r ≠ 0)
    (hδ0 : ∀ a r, δ a r ≠ 0)
    (w : Fin (P.Nd + 16) → Fin (P.nm + 1) → Fin 2 → Fin (P.M * (P.nm + 8) + 1) → Fin 13 →
      NormLinear.Witness F)
    (hw : ∀ a r b l t, NormLinear.Rel g (tauInst P (treeCh α μ δ β lam a r b l) g H G
      (cS a r b l) cO cL (cR a) (vHat P (treeCh α μ δ β lam a r b l) V) (rho a r) (τ a r b l t))
      (w a r b l t)) :
    (∃ (v : ℕ → ℕ) (s : ℕ → F), ∀ i < P.M, v i < 16 ^ P.D ∧ V i = (v i : F) • g + s i • H 0) ∨
      Relation F P g H G := by
  by_cases hrel : Relation F P g H G
  · exact Or.inr hrel
  left
  set ch := treeCh α μ δ β lam
  -- `τ`: every node above the leaves opens its commitments with `f ≡ 0`.
  have tau := fun a r b l => (extract_tau P (ch a r b l) g H G (cS a r b l) cO cL (cR a)
    (vHat P (ch a r b l) V) (rho a r) (τ a r b l) (hτ a r b l) (hδ0 a r) (w a r b l)
    (hw a r b l)).resolve_right fun h => hrel (relation_of_tau P g H G h)
  choose wo hf hS hO hL hR hV using tau
  -- `λ`: the inputs open in the plane, with set membership and the value links `i ≥ 1`.
  have lamL := fun a r b => (extract_lam P (ch a r b 0) g H G h2 hM (hδ0 a r) (hμ0 a r) cO cL
    (cR a) V (lam a r b) (hlam a r b) (wo a r b) (hf a r b) (hO a r b) (hL a r b) (hR a r b)
    (hV a r b)).resolve_right hrel
  choose u hh nn hVu hn0 hh0 hSrow hlink hres using lamL
  -- `β`: (36).
  have betaL := fun a r => (extract_beta P (ch a r 0 0) g H G hM cO cL (cR a) (V 0) (β a r)
    (hβ a r) (fun b => wo a r b 0) (u a r) (hh a r) (nn a r) (fun b => hO a r b 0)
    (fun b => hL a r b 0) (fun b => hR a r b 0) (fun b => hVu a r b 0 hM)
    (fun b => hn0 a r b 0 hM) (fun b => hres a r b)).resolve_right hrel
  -- `ρ`: the first value link and the Hadamard rows.
  have rhoL := fun a => (extract_rho P (ch a 0 0 0) g H G h2 hM cL (cR a) (V 0) (μ a) (hμ a)
    (fun r => wo a r 0 0) (fun r => u a r 0 0) (fun r => hh a r 0 0) (fun r => nn a r 0 0)
    (fun r => hL a r 0 0) (fun r => hR a r 0 0) (fun r => hVu a r 0 0 hM)
    (fun r => betaL a r)).resolve_right hrel
  -- `α`: the digits are in the table.
  have dig := (extract_alpha P (ch 0 0 0 0) g H G h2 hchar cO cL α hα hpole
    (fun a => wo a 0 0 0) (fun a => hO a 0 0 0) (fun a => hL a 0 0 0)
    (fun a => hSrow a 0 0) (fun a => (rhoL a).2.1)).resolve_right hrel
  -- Output (38): the digits off `C_L` and the blindings off the `H_0`-coordinates.
  choose! dg hdg using dig
  have hslot : ∀ i < P.M, ∀ t < P.D, i * P.D + t < P.Nd := fun i hi t ht => by
    have := Nat.mul_le_mul_right P.D (show i + 1 ≤ P.M by omega)
    have : (i + 1) * P.D = i * P.D + P.D := by ring
    simp only [Params.Nd]
    omega
  refine ⟨fun i => ∑ t ∈ range P.D, 16 ^ t * dg (i * P.D + t), fun i => hh 0 0 0 i 0,
    fun i hi => ⟨digits_lt _ _ fun t ht => (hdg _ (hslot i hi t ht)).1, ?_⟩⟩
  rw [hVu 0 0 0 i hi, commit_plane P g H G _ _ _ (hh0 0 0 0 i hi) (hn0 0 0 0 i hi)]
  congr 2
  have hu : u 0 0 0 i = ∑ t ∈ range P.D, 16 ^ t * (wo 0 0 0 0).nL (i * P.D + t) := by
    rcases Nat.eq_zero_or_pos i with rfl | hi1
    · simpa using (rhoL 0).1
    · exact hlink 0 0 0 i hi1 hi
  rw [hu]
  push_cast
  exact sum_congr rfl fun t ht => by rw [(hdg _ (hslot i hi t (mem_range.1 ht))).2]

end Bppp.Spec
