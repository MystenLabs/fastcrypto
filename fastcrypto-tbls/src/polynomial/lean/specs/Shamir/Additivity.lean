/-
Additivity: adding the shares of several sharings, index by index, gives shares of the sum of the
secrets.
-/
import Shamir.Recovery

namespace Shamir

open ShamirModel Polynomial

/-- The sum `p₀ + p₁ + ⋯` of polynomials, computed left to right with `add`. -/
def sumPolys (p : Poly) (rest : List Poly) : Poly := rest.foldl ShamirModel.add p

lemma toPoly_sumPolys (p : Poly) (rest : List Poly) :
    toPoly (sumPolys p rest).toList = toPoly p.toList + (rest.map fun q => toPoly q.toList).sum := by
  induction rest generalizing p with
  | nil => simp [sumPolys]
  | cons q rest ih =>
    simp only [sumPolys, List.foldl_cons] at ih ⊢
    rw [ih, toPoly_add, List.map_cons, List.sum_cons, add_assoc]

lemma size_sumPolys {n : ℕ} (p : Poly) (rest : List Poly) (hp : p.size = n)
    (hrest : ∀ q ∈ rest, q.size = n) : (sumPolys p rest).size = n := by
  induction rest generalizing p with
  | nil => simpa [sumPolys]
  | cons q rest ih =>
    simp only [sumPolys, List.foldl_cons] at ih ⊢
    exact ih _ (by rw [size_add, hp, hrest q List.mem_cons_self, max_self])
      fun q' hq' => hrest q' (List.mem_cons_of_mem _ hq')

variable [Fact r.Prime]

/-- **Additivity.** Let `t > 0` and let `sharings` be a nonempty list of dealings `(sₖ, cₖ)` with
degree `t - 1`. For every list `idx` of exactly `t` distinct share indices, `recover_c0` on the
summed shares `Σₖ pₖ.eval(i).value` (one per `i` in `idx`, with index `i`) returns `Ok(Σₖ sₖ)`. -/
theorem recover_sum {t : ℕ} (ht : 0 < t) (sharings : List (F × (Fin (t - 1) → F)))
    (hne : sharings ≠ []) (idx : List ℕ) (hidx : ∀ i ∈ idx, 0 < i ∧ i < 2 ^ 16)
    (hnodup : idx.Nodup) (hlen : idx.length = t) :
    recover_c0 t (idx.map fun i =>
        ⟨i, (sharings.map fun d => (ShamirModel.eval (deal (t - 1) d.1 d.2) i).value).sum⟩) =
      .ok (sharings.map Prod.fst).sum := by
  obtain ⟨d, rest, rfl⟩ := List.exists_cons_of_ne_nil hne
  let P := sumPolys (deal (t - 1) d.1 d.2) (rest.map fun d => deal (t - 1) d.1 d.2)
  have hP : toPoly P.toList = ((d :: rest).map fun d => toPoly (deal (t - 1) d.1 d.2).toList).sum := by
    simp [P, toPoly_sumPolys, List.map_map, Function.comp_def]
  have hshares : (idx.map fun i => (⟨i, ((d :: rest).map fun d =>
      (ShamirModel.eval (deal (t - 1) d.1 d.2) i).value).sum⟩ : ShamirModel.Eval)) =
      idx.map (ShamirModel.eval P) := by
    refine List.map_congr_left fun i _ => ?_
    show _ = ShamirModel.Eval.mk i (ShamirModel.eval P i).value
    rw [eval_eq, hP, eval_listSum]
    simp [List.map_map, Function.comp_def, eval_eq]
  have hsize : P.size = t :=
    size_sumPolys _ _ (by rw [size_deal]; omega) fun q hq => by
      obtain ⟨d', _, rfl⟩ := List.mem_map.mp hq
      rw [size_deal]; omega
  have hc0 : c0 P = ((d :: rest).map Prod.fst).sum := by
    rw [c0_eq, hP, ← lcoeff_apply, map_list_sum]
    simp [List.map_map, Function.comp_def, ← c0_eq, c0_deal]
  rw [hshares, recover_c0_eval P t idx hidx hnodup hlen hsize.le, hc0]

end Shamir
