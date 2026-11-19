/-
`recover_c0` is Lagrange interpolation at zero: on `t` shares with distinct indices of a polynomial
with at most `t` coefficients, it returns the constant term.
-/
import Shamir.Basic

namespace Shamir

open ShamirModel Polynomial Finset

lemma mapM_ok {α β : Type} (f : α → Except String β) (g : α → β) (l : List α)
    (h : ∀ a ∈ l, f a = .ok (g a)) : l.mapM f = .ok (l.map g) := by
  induction l with
  | nil => rfl
  | cons a l ih =>
    simp only [List.mapM_cons, List.map_cons, h a List.mem_cons_self,
      ih fun b hb => h b (List.mem_cons_of_mem _ hb)]
    rfl

variable [Fact r.Prime]

lemma pow_eq (x : F) (e : ℕ) : ShamirModel.pow x e = x ^ e := by
  induction e using Nat.strong_induction_on generalizing x with
  | _ e ih =>
    rw [ShamirModel.pow]
    by_cases h0 : e = 0
    · simp [h0]
    · simp only [h0, ite_false]
      rw [ih _ (by omega), ← pow_two, ← pow_mul]
      conv_rhs => rw [← Nat.div_add_mod e 2]
      rcases Nat.mod_two_eq_zero_or_one e with h | h <;> simp [h, pow_succ']

lemma inverse_eq {x : F} (hx : x ≠ 0) : ShamirModel.inverse x = .ok x⁻¹ := by
  simp only [ShamirModel.inverse, hx, ite_false, pow_eq]
  congr 1
  have hr : 2 ≤ r := (Fact.out : r.Prime).two_le
  have h1 : x ^ (r - 2) * x = 1 := by
    rw [← pow_succ, show r - 2 + 1 = r - 1 by omega]
    exact ZMod.pow_card_sub_one_eq_one (p := r) hx
  exact eq_inv_of_mul_eq_one_left h1

/-- Share indices are below `2^16 < r`, so distinct indices are distinct scalars. -/
lemma cast_injOn : Set.InjOn (fun n : ℕ => (n : F)) {n | n < 2 ^ 16} := by
  intro a ha b hb h
  have hr : 2 ^ 16 < r := by decide
  have := (ZMod.natCast_eq_natCast_iff' a b r).mp h
  rwa [Nat.mod_eq_of_lt (by simp at ha; omega), Nat.mod_eq_of_lt (by simp at hb; omega)] at this

/-- The product over `l.filter (· ≠ i)` is the product over `l.toFinset.erase i`. -/
lemma foldr_filter_eq_prod (l : List ℕ) (hl : l.Nodup) (i : ℕ) (f : ℕ → F) :
    ((l.filter (· ≠ i)).map f).foldr (· * ·) 1 = ∏ j ∈ l.toFinset.erase i, f j := by
  rw [← List.prod_eq_foldr, ← List.prod_toFinset _ (hl.filter _), List.toFinset_filter]
  congr 1
  ext j; simp [and_comm]

/-- Lagrange interpolation at zero, in the form `recover_c0` computes it. -/
lemma lagrange_at_zero (P : F[X]) (idx : List ℕ) (hnodup : idx.Nodup)
    (hidx : ∀ i ∈ idx, i < 2 ^ 16) (hdeg : P.degree < idx.length) :
    ∑ i ∈ idx.toFinset, P.eval (i : F) *
        ((∏ j ∈ idx.toFinset.erase i, (j : F)) * (∏ j ∈ idx.toFinset.erase i, ((j : F) - i))⁻¹) =
      P.eval 0 := by
  set s := idx.toFinset
  have hinj : Set.InjOn (fun n : ℕ => (n : F)) s :=
    cast_injOn.mono fun n hn => hidx n (List.mem_toFinset.mp hn)
  have hcard : s.card = idx.length := List.toFinset_card_of_nodup hnodup
  conv_rhs => rw [Lagrange.eq_interpolate (f := P) hinj (by rwa [hcard])]
  rw [Lagrange.interpolate_apply, eval_finsetSum]
  refine sum_congr rfl fun i hi => ?_
  rw [eval_mul, eval_C, Lagrange.basis, eval_prod, ← prod_inv_distrib, ← prod_mul_distrib]
  congr 1
  refine prod_congr rfl fun j hj => ?_
  rw [Lagrange.basisDivisor, eval_mul, eval_C, eval_sub, eval_X, eval_C, zero_sub,
    ← neg_sub, inv_neg]
  ring

lemma lagrange_eq (idx : List ℕ) (hnodup : idx.Nodup) (hlt : ∀ i ∈ idx, i < 2 ^ 16) {i : ℕ}
    (hi : i ∈ idx) :
    lagrange idx i = .ok ((∏ j ∈ idx.toFinset.erase i, (j : F)) *
      (∏ j ∈ idx.toFinset.erase i, ((j : F) - i))⁻¹) := by
  have hden0 : ∏ j ∈ idx.toFinset.erase i, ((j : F) - i) ≠ 0 :=
    prod_ne_zero_iff.mpr fun j hj => sub_ne_zero.mpr fun h => (mem_erase.mp hj).1
      (cast_injOn (hlt j (List.mem_toFinset.mp (mem_erase.mp hj).2)) (hlt i hi) h)
  have hnum := foldr_filter_eq_prod idx hnodup i (fun j => (j : F))
  have hden := foldr_filter_eq_prod idx hnodup i (fun j => (j : F) - i)
  have hof : ∀ j : ℕ, Fin.ofNat r j = ((j : ℕ) : F) := fun _ => rfl
  unfold lagrange
  simp only [hof, List.map_map, Function.comp_def]
  rw [hden, inverse_eq hden0]
  exact congrArg (fun a => Except.ok (a * _)) hnum

/-- **Recovery from shares.** If `p` has at most `t` coefficients and `idx` is a list of exactly
`t` distinct share indices, `recover_c0(t, [p.eval(i) for i in idx])` returns `Ok(p.c0())`. -/
theorem recover_c0_eval (p : Poly) (t : ℕ) (idx : List ℕ) (hidx : ∀ i ∈ idx, 0 < i ∧ i < 2 ^ 16)
    (hnodup : idx.Nodup) (hlen : idx.length = t) (hsize : p.size ≤ t) :
    recover_c0 t (idx.map (ShamirModel.eval p)) = .ok (c0 p) := by
  have hindex : (idx.map (ShamirModel.eval p)).map (·.index) = idx := by
    simp [List.map_map, Function.comp_def, eval_index]
  have hzero : idx.contains 0 = false := by
    simpa using fun h => (hidx 0 h).1.false
  have hlt : ∀ i ∈ idx, i < 2 ^ 16 := fun i hi => (hidx i hi).2
  unfold recover_c0
  simp only [hindex, hnodup, hlen, hzero]
  simp only [decide_true, Bool.not_true, ne_eq, not_true_eq_false, decide_false, Bool.or_self,
    Bool.false_eq_true, ite_false]
  rw [mapM_ok _ (fun sh => sh.value *
    ((∏ j ∈ idx.toFinset.erase sh.index, (j : F)) *
      (∏ j ∈ idx.toFinset.erase sh.index, ((j : F) - sh.index))⁻¹))]
  · show Except.ok (List.foldr _ 0 _) = _
    congr 1
    have hdeg : (toPoly p.toList).degree < idx.length :=
      (degree_toPoly_lt _).trans_le (by rw [Array.length_toList]; exact_mod_cast hlen ▸ hsize)
    rw [← List.sum_eq_foldr, List.map_map, ← List.sum_toFinset _ hnodup, c0_eq,
      coeff_zero_eq_eval_zero, ← lagrange_at_zero _ idx hnodup hlt hdeg]
    refine sum_congr rfl fun i _ => ?_
    simp [eval_eq, eval_index]
  · intro sh hsh
    obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hsh
    rw [eval_index, lagrange_eq idx hnodup hlt hi]
    rfl
