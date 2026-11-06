/-
Additivity: adding the shares of several sharings, index by index, gives shares of the sum of the
secrets.
-/
import Shamir.Steps

namespace Shamir

variable {F : Type} [Field F] {A : Api F}

/-- The sum `p₀ + p₁ + ⋯` of polynomials, computed left to right with `add`. -/
def sumPolys (A : Api F) (p : A.Poly) (rest : List A.Poly) : A.Poly :=
  rest.foldl A.add p

lemma sumPolys_eval {A : Api F} (hadd : ∀ p q i,
    (A.eval (A.add p q) i).value = (A.eval p i).value + (A.eval q i).value)
    (p : A.Poly) (rest : List A.Poly) (i : ShareIndex) :
    (A.eval (sumPolys A p rest) i).value =
      (A.eval p i).value + (rest.map (fun q => (A.eval q i).value)).sum := by
  induction rest generalizing p with
  | nil => simp [sumPolys]
  | cons q rest ih =>
    simp only [sumPolys, List.foldl_cons] at ih ⊢
    rw [ih, hadd, List.map_cons, List.sum_cons, add_assoc]

lemma sumPolys_c0 (hA : Contracts A) (p : A.Poly) (rest : List A.Poly) :
    A.c0 (sumPolys A p rest) = A.c0 p + (rest.map A.c0).sum := by
  induction rest generalizing p with
  | nil => simp [sumPolys]
  | cons q rest ih =>
    simp only [sumPolys, List.foldl_cons] at ih ⊢
    rw [ih, hA.add_c0, List.map_cons, List.sum_cons, add_assoc]

lemma sumPolys_degree (hA : Contracts A) {d : ℕ} (p : A.Poly) (rest : List A.Poly)
    (hp : A.degreeBound p = d) (hrest : ∀ q ∈ rest, A.degreeBound q = d) :
    A.degreeBound (sumPolys A p rest) = d := by
  induction rest generalizing p with
  | nil => simpa [sumPolys]
  | cons q rest ih =>
    simp only [sumPolys, List.foldl_cons] at ih ⊢
    apply ih
    · rw [hA.add_degree, hp, hrest q List.mem_cons_self, max_self]
    · exact fun q' hq' => hrest q' (List.mem_cons_of_mem _ hq')

/-- **Additivity.** Let `t > 0` and let `sharings` be a nonempty list of pairs `(sₖ, pₖ)`, where
each `pₖ` is a polynomial that `rand_fixed_c0(t - 1, sₖ)` can return. For every list `idx` of exactly
`t` distinct share indices, `recover_c0` on the summed shares `Σₖ pₖ.eval(i).value` (one per `i` in
`idx`, with index `i`) returns `Ok(Σₖ sₖ)`. -/
theorem recover_sum (hA : Contracts A) {t : ℕ} (ht : 0 < t)
    (sharings : List (F × A.Poly)) (hne : sharings ≠ [])
    (hshared : ∀ d ∈ sharings, d.2 ∈ (A.randFixedC0 (t - 1) d.1).support)
    (idx : List ShareIndex) (hnodup : idx.Nodup) (hlen : idx.length = t) :
    A.recoverC0 t (idx.map fun i =>
        ⟨i, (sharings.map fun d => (A.eval d.2 i).value).sum⟩) =
      .ok (sharings.map Prod.fst).sum := by
  obtain ⟨d, rest, rfl⟩ := List.exists_cons_of_ne_nil hne
  let P := sumPolys A d.2 (rest.map Prod.snd)
  -- The summed shares are the shares of the summed polynomial.
  have hshares : (idx.map fun i =>
      (⟨i, ((d :: rest).map fun d => (A.eval d.2 i).value).sum⟩ : Eval F)) =
      idx.map (A.eval P) := by
    refine List.map_congr_left fun i _ => ?_
    ext
    · rw [hA.eval_index]
    · simp only [P, sumPolys_eval hA.add_eval, List.map_cons, List.sum_cons, List.map_map,
        Function.comp_def]
  have hdeg : A.degreeBound P = t - 1 :=
    sumPolys_degree hA _ _ (hA.rand_degree _ _ _ (hshared d List.mem_cons_self))
      (fun q hq => by
        obtain ⟨d', hd', rfl⟩ := List.mem_map.mp hq
        exact hA.rand_degree _ _ _ (hshared d' (List.mem_cons_of_mem _ hd')))
  have hc0 : A.c0 P = ((d :: rest).map Prod.fst).sum := by
    simp only [P, sumPolys_c0 hA, List.map_map, List.map_cons, List.sum_cons]
    rw [hA.rand_c0 _ _ _ (hshared d List.mem_cons_self)]
    congr 1
    refine congrArg List.sum (List.map_congr_left fun d' hd' => ?_)
    exact hA.rand_c0 _ _ _ (hshared d' (List.mem_cons_of_mem _ hd'))
  rw [hshares, hA.recover_c0 t P idx (by omega) hnodup hlen, hc0]

end Shamir
