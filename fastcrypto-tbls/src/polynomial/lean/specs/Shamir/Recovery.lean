/-
Recovery: `recover_c0` on `t` shares of a dealing returns the dealt secret, whichever `t` shares
are used.
-/
import Shamir.Interpolation

namespace Shamir

open ShamirModel

/-- What `Poly::rand_fixed_c0(d, s)` returns when its random coefficients are `c`: the polynomial
`s + c₀X + ⋯ + c_{d-1}X^d`. -/
def deal (d : ℕ) (s : F) (c : Fin d → F) : Poly := (s :: List.ofFn c).toArray

lemma deal_toList (d : ℕ) (s : F) (c : Fin d → F) : (deal d s c).toList = s :: List.ofFn c := rfl

lemma size_deal (d : ℕ) (s : F) (c : Fin d → F) : (deal d s c).size = d + 1 := by
  simp [deal]

lemma c0_deal (d : ℕ) (s : F) (c : Fin d → F) : c0 (deal d s c) = s := by
  simp [c0_eq, deal_toList, coeff_toPoly]

variable [Fact r.Prime]

/-- **Recovery.** Let `t > 0`. For every secret `s`, coefficients `c` and list `idx` of exactly `t`
distinct share indices, `recover_c0` on the shares at `idx` of the dealing of `s` with degree
`t - 1` returns `Ok(s)`. -/
theorem recover_deal {t : ℕ} (ht : 0 < t) (s : F) (c : Fin (t - 1) → F) (idx : List ℕ)
    (hidx : ∀ i ∈ idx, 0 < i ∧ i < 2 ^ 16) (hnodup : idx.Nodup) (hlen : idx.length = t) :
    recover_c0 t (idx.map (ShamirModel.eval (deal (t - 1) s c))) = .ok s := by
  rw [recover_c0_eval _ t idx hidx hnodup hlen (by rw [size_deal]; omega), c0_deal]

/-- **Agreement.** Any two lists of exactly `t` distinct share indices recover the same secret. -/
theorem recover_agrees {t : ℕ} (ht : 0 < t) (s : F) (c : Fin (t - 1) → F) (idx idx' : List ℕ)
    (hidx : ∀ i ∈ idx, 0 < i ∧ i < 2 ^ 16) (hidx' : ∀ i ∈ idx', 0 < i ∧ i < 2 ^ 16)
    (h : idx.Nodup ∧ idx.length = t) (h' : idx'.Nodup ∧ idx'.length = t) :
    recover_c0 t (idx.map (ShamirModel.eval (deal (t - 1) s c))) =
      recover_c0 t (idx'.map (ShamirModel.eval (deal (t - 1) s c))) := by
  rw [recover_deal ht s c idx hidx h.1 h.2, recover_deal ht s c idx' hidx' h'.1 h'.2]

end Shamir
