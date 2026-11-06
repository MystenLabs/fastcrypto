/-
Privacy: fewer than `t` shares reveal nothing about the secret.
-/
import Shamir.Recovery

namespace Shamir

open ShamirModel Polynomial Finset

variable [Fact r.Prime]

/-- Shifting the coefficients of a dealing of `s` by the higher coefficients of `Q` gives a
dealing of `s + Q(0)` whose polynomial is the old one plus `Q`, if `Q` has degree at most `d`. -/
lemma toPoly_deal_shift {d : ℕ} (s : F) (c : Fin d → F) (Q : F[X])
    (hQ : Q.degree < ((d + 1 : ℕ) : WithBot ℕ)) :
    toPoly (deal d (s + Q.coeff 0) (c + fun k : Fin d => Q.coeff (k.val + 1))).toList =
      toPoly (deal d s c).toList + Q := by
  refine Polynomial.ext fun m => ?_
  rw [coeff_add, coeff_toPoly, coeff_toPoly, deal_toList, deal_toList]
  cases m with
  | zero => simp
  | succ k =>
    by_cases hk : k < d
    · simp [List.getD_eq_getElem?_getD, hk]
    · have h0 : Q.coeff (k + 1) = 0 :=
        coeff_eq_zero_of_degree_lt (lt_of_lt_of_le hQ (by exact_mod_cast (show d + 1 ≤ k + 1 by omega)))
      simp [List.getD_eq_getElem?_getD, hk, h0]

/-- **Privacy.** Let `idx` be a list of fewer than `t` share indices. For any two secrets `s` and
`s'` and any share values `v`, exactly as many coefficient vectors `c` give the shares `v` at `idx`
for the dealing of `s` as for the dealing of `s'`. Since `rand_fixed_c0` draws `c` uniformly, the
shares at `idx` have the same distribution for every secret. -/
theorem shares_independent_of_secret {t : ℕ} (s s' : F) (idx : List ℕ)
    (hidx : ∀ i ∈ idx, 0 < i ∧ i < 2 ^ 16) (hlen : idx.length < t) (v : List ShamirModel.Eval) :
    (univ.filter fun c : Fin (t - 1) → F => idx.map (ShamirModel.eval (deal (t - 1) s c)) = v).card =
      (univ.filter fun c : Fin (t - 1) → F =>
        idx.map (ShamirModel.eval (deal (t - 1) s' c)) = v).card := by
  -- `Q` is `s' - s` at zero and zero at every index in `idx`.
  let nodes := insert 0 idx.toFinset
  have hinj : Set.InjOn (fun n : ℕ => (n : F)) nodes := cast_injOn.mono fun n hn => by
    rcases mem_insert.mp hn with rfl | hn
    · simp
    · exact (hidx n (List.mem_toFinset.mp hn)).2
  let Q := Lagrange.interpolate nodes (fun n : ℕ => (n : F)) fun n => if n = 0 then s' - s else 0
  have hQi : ∀ i ∈ idx, Q.eval (i : F) = 0 := fun i hi => by
    rw [Lagrange.eval_interpolate_at_node _ hinj (mem_insert_of_mem (List.mem_toFinset.mpr hi))]
    simp [(hidx i hi).1.ne']
  have hQ0 : Q.coeff 0 = s' - s := by
    rw [coeff_zero_eq_eval_zero, show (0 : F) = ((0 : ℕ) : F) by simp,
      Lagrange.eval_interpolate_at_node _ hinj (mem_insert_self 0 _)]
    simp
  have hQdeg : Q.degree < ((t - 1 + 1 : ℕ) : WithBot ℕ) := by
    refine (Lagrange.degree_interpolate_lt _ hinj).trans_le ?_
    have : nodes.card ≤ idx.length + 1 :=
      (card_insert_le _ _).trans (by simpa using List.toFinset_card_le idx)
    exact_mod_cast (show nodes.card ≤ t - 1 + 1 by omega)
  let q : Fin (t - 1) → F := fun k => Q.coeff (k.val + 1)
  -- Shifting by `q` turns a dealing of `s` into one of `s'` with the same shares at `idx`.
  have hshares : ∀ c, idx.map (ShamirModel.eval (deal (t - 1) s' (c + q))) =
      idx.map (ShamirModel.eval (deal (t - 1) s c)) := fun c => by
    have h := toPoly_deal_shift s c Q hQdeg
    rw [hQ0, add_sub_cancel] at h
    refine List.map_congr_left fun i hi => ?_
    show ShamirModel.Eval.mk i (ShamirModel.eval _ i).value = ShamirModel.Eval.mk i
      (ShamirModel.eval _ i).value
    rw [eval_eq, eval_eq, h, eval_add, hQi i hi, add_zero]
  exact card_equiv (Equiv.addRight q) fun c => by simp [hshares]

end Shamir
