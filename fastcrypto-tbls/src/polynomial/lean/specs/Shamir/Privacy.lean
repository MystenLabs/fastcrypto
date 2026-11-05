/-
Privacy: fewer than `t` shares reveal nothing about the secret.
-/
import Shamir.Steps

namespace Shamir

variable {F : Type} [Field F] {A : Api F}

/-- **Privacy.** For every list `idx` of fewer than `t` share indices and any two secrets `s`,
`s'`: the joint distribution of the shares at `idx` of `rand_fixed_c0(t - 1, s)` equals that of
`rand_fixed_c0(t - 1, s')`. So fewer than `t` shares reveal nothing about the secret
(information-theoretically). -/
theorem shares_independent_of_secret (hA : Contracts A) {t : ℕ} (s s' : F)
    (idx : List ShareIndex) (hlen : idx.length < t) :
    (A.randFixedC0 (t - 1) s).map (fun p => idx.map (A.eval p)) =
      (A.randFixedC0 (t - 1) s').map (fun p => idx.map (A.eval p)) := by
  -- Shift the dealing of `s` by a polynomial with constant term `s' - s` that is zero at `idx`:
  -- this gives the dealing of `s'` and leaves the shares at `idx` unchanged.
  obtain ⟨q, hqdeg, hqc0, hqzero⟩ := hA.vanishing_exists t (s' - s) idx hlen
  have hshift := hA.rand_shift (t - 1) s q hqdeg
  have hs : s + (s' - s) = s' := by ring
  rw [hqc0, hs] at hshift
  rw [← hshift, PMF.map_comp]
  congr 1
  funext p
  refine List.map_congr_left fun i hi => ?_
  ext
  · rw [hA.eval_index, hA.eval_index]
  · rw [hA.add_eval, hqzero i hi, add_zero]

end Shamir
