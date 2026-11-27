-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.Util

/-!
# Lemmas about `util.rs`

A list `v` stands for the vector `k ↦ v.getD k 0`.
-/

open Finset

namespace Bppp

section Lists

variable {α β M : Type*} [AddCommMonoid M]

lemma sum_zipWith (f : α → β → M) (a : List α) (b : List β) (da : α) (db : β) :
    (List.zipWith f a b).sum =
      ∑ k ∈ range (min a.length b.length), f (a.getD k da) (b.getD k db) := by
  induction a generalizing b with
  | nil => simp
  | cons x a ih =>
    cases b with
    | nil => simp
    | cons y b =>
      simp only [List.zipWith_cons_cons, List.sum_cons, ih, List.length_cons,
        Nat.add_min_add_right, sum_range_succ', List.getD_cons_succ, List.getD_cons_zero]
      rw [add_comm]

lemma foldl_add (g : α → M) (l : List α) (init : M) :
    l.foldl (fun acc x => acc + g x) init = init + (l.map g).sum := by
  induction l generalizing init with
  | nil => simp
  | cons x l ih => simp only [List.foldl_cons, ih, List.map_cons, List.sum_cons, add_assoc]

lemma foldl_zip_add (g : α → β → M) (a : List α) (b : List β) (da : α) (db : β) (init : M) :
    (List.zip a b).foldl (fun acc (x, y) => acc + g x y) init =
      init + ∑ k ∈ range (min a.length b.length), g (a.getD k da) (b.getD k db) := by
  induction a generalizing b init with
  | nil => simp
  | cons x a ih =>
    cases b with
    | nil => simp
    | cons y b =>
      simp only [List.zip_cons_cons, List.foldl_cons, ih, List.length_cons,
        Nat.add_min_add_right, sum_range_succ', List.getD_cons_succ, List.getD_cons_zero]
      rw [add_assoc, add_comm (g x y)]

lemma getElem_eq_getD' {α : Type*} (l : List α) {k : ℕ} (h : k < l.length) (d : α) :
    l[k] = l.getD k d := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h, Option.getD_some]

lemma getD_eq_zero_of_le {R : Type*} [Zero R] {v : List R} {k : ℕ} (h : v.length ≤ k) :
    v.getD k 0 = 0 := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_eq_none h]

end Lists

variable {F : Type} [Field F] [DecidableEq F]

set_option linter.unusedSectionVars false

lemma inner_product_eq (a b : List F) :
    inner_product a b = ∑ k ∈ range (min a.length b.length), a.getD k 0 * b.getD k 0 := by
  rw [inner_product, foldl_zip_add (fun x y : F => x * y) a b 0 0, zero_add]

lemma weighted_inner_product_eq (a b : List F) (mu : F) :
    weighted_inner_product a b mu =
      ∑ k ∈ range (min a.length b.length), a.getD k 0 * b.getD k 0 * mu ^ (k + 1) := by
  -- The loop from `(w, r)` ends at `r + Σ_k a_k b_k w μ^k`.
  have key : ∀ (a b : List F) (w r : F),
      ((List.zip a b).foldl (fun (weight, result) (x, y) => (weight * mu, result + x * y * weight))
        (w, r)).2 = r + ∑ k ∈ range (min a.length b.length), a.getD k 0 * b.getD k 0 * (w * mu ^ k) := by
    intro a
    induction a with
    | nil => simp
    | cons x a ih =>
      intro b w r
      cases b with
      | nil => simp
      | cons y b =>
        simp only [List.zip_cons_cons, List.foldl_cons, ih, List.length_cons, Nat.add_min_add_right,
          sum_range_succ', List.getD_cons_succ, List.getD_cons_zero, pow_zero, mul_one, pow_succ]
        rw [add_assoc]; congr 1; rw [add_comm]; congr 1
        exact sum_congr rfl fun k _ => by ring
  rw [weighted_inner_product, key, zero_add]
  exact sum_congr rfl fun k _ => by ring

lemma weighted_norm_eq (n : List F) (mu : F) :
    weighted_norm n mu = ∑ k ∈ range n.length, n.getD k 0 * n.getD k 0 * mu ^ (k + 1) := by
  rw [weighted_norm, weighted_inner_product_eq, min_self]

lemma power_vector_eq (x : F) (n : ℕ) : power_vector x n = (List.range n).map (x ^ ·) := by
  have key : ∀ (n : ℕ) (v : List F) (cur : F), ((List.range n).foldl
      (fun (v, cur) _ => (v ++ [cur], cur * x)) (v, cur)) =
      (v ++ (List.range n).map (cur * x ^ ·), cur * x ^ n) := by
    intro n
    induction n with
    | zero => simp
    | succ n ih =>
      intro v cur
      rw [List.range_succ, List.foldl_append, ih]
      simp only [List.foldl_cons, List.foldl_nil, List.map_append, List.map_cons, List.map_nil,
        List.append_assoc, pow_succ, mul_assoc]
  rw [power_vector, key]; simp [one]

lemma length_vec_add (a b : List F) : (vec_add a b).length = min a.length b.length := by
  simp [vec_add]

lemma getD_vec_add {a b : List F} (h : a.length = b.length) (k : ℕ) :
    (vec_add a b).getD k 0 = a.getD k 0 + b.getD k 0 := by
  simp only [vec_add, List.getD_eq_getElem?_getD, List.getElem?_zipWith]
  rcases lt_or_ge k a.length with hk | hk
  · rw [List.getElem?_eq_getElem hk, List.getElem?_eq_getElem (h ▸ hk)]; rfl
  · rw [List.getElem?_eq_none hk, List.getElem?_eq_none (h ▸ hk)]; simp

lemma length_vec_scalar_mul (s : F) (a : List F) : (vec_scalar_mul s a).length = a.length := by
  simp [vec_scalar_mul]

lemma getD_vec_scalar_mul (s : F) (a : List F) (k : ℕ) :
    (vec_scalar_mul s a).getD k 0 = s * a.getD k 0 := by
  simp only [vec_scalar_mul, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases a[k]? <;> simp

lemma length_hadamard (a b : List F) : (hadamard a b).length = min a.length b.length := by
  simp [hadamard]

lemma getD_hadamard {a b : List F} (k : ℕ) (hk : k < b.length) :
    (hadamard a b).getD k 0 = a.getD k 0 * b.getD k 0 := by
  simp only [hadamard, List.getD_eq_getElem?_getD, List.getElem?_zipWith,
    List.getElem?_eq_getElem hk]
  cases a[k]? <;> simp

lemma length_to_scalars (xs : List ℕ) : (to_scalars xs : List F).length = xs.length := by
  simp [to_scalars]

lemma getD_to_scalars (xs : List ℕ) (k : ℕ) :
    (to_scalars xs : List F).getD k 0 = (xs.getD k 0 : F) := by
  rw [to_scalars, List.getD_eq_getElem?_getD, List.getElem?_map, List.getD_eq_getElem?_getD]
  cases xs[k]? <;> simp

lemma length_pad_to (v : List F) (n : ℕ) : (pad_to v n).length = n := by
  simp only [pad_to, List.length_take, List.length_append, List.length_replicate]; omega

lemma getD_pad_to (v : List F) (n k : ℕ) :
    (pad_to v n).getD k 0 = if k < n then v.getD k 0 else 0 := by
  simp only [pad_to, List.getD_eq_getElem?_getD, List.getElem?_take, List.getElem?_append,
    List.getElem?_replicate]
  split_ifs <;> first | rfl | simp [List.getElem?_eq_none (by omega : v.length ≤ k)]

/-- The running products `p, p*x_0, p*x_0*x_1, ...` before each entry of `xs`. -/
def prefixes (p : F) : List F → List F
  | [] => []
  | x :: xs => p :: prefixes (p * x) xs

/-- `batch_invert` inverts every entry when none is zero. -/
lemma batch_invert_eq (inputs : List F) (h : ∀ x ∈ inputs, x ≠ 0) :
    batch_invert inputs = .ok (inputs.map (·⁻¹)) := by
  have hpre : ∀ (xs pre : List F) (p : F), xs.foldl (fun (pre, acc) x => (pre ++ [acc], acc * x))
      (pre, p) = (pre ++ prefixes p xs, p * xs.prod) := by
    intro xs
    induction xs with
    | nil => simp [prefixes]
    | cons x xs ih =>
      intro pre p
      rw [List.foldl_cons, ih]
      simp [prefixes, mul_assoc]
  have hsuf : ∀ (xs : List F) (p : F), p ≠ 0 → (∀ x ∈ xs, x ≠ 0) →
      (List.zip xs (prefixes p xs)).foldr
        (fun (x, q) (out, suffix_inv) => (suffix_inv * q :: out, suffix_inv * x))
        ([], (p * xs.prod)⁻¹) = (xs.map (·⁻¹), p⁻¹) := by
    intro xs
    induction xs with
    | nil => simp [prefixes]
    | cons x xs ih =>
      intro p hp hxs
      have hx : x ≠ 0 := hxs x (by simp)
      have hrest := ih (p * x) (mul_ne_zero hp hx) fun y hy => hxs y (by simp [hy])
      simp only [prefixes, List.zip_cons_cons, List.foldr_cons, List.prod_cons, ← mul_assoc, hrest,
        List.map_cons, Prod.mk.injEq, List.cons.injEq, and_true]
      constructor <;> field_simp
  have hprod : inputs.prod ≠ 0 := List.prod_ne_zero (fun h0 => h 0 h0 rfl)
  have := hsuf inputs 1 one_ne_zero h
  simp only [one_mul] at this
  simp only [batch_invert, hpre, List.nil_append, one, one_mul, inverse, hprod, if_false,
    bind, Except.bind, pure, Except.pure, this]

lemma to_digits_eq (value d : ℕ) :
    to_digits value d = (List.range d).map fun t => value / 16 ^ t % 16 := by
  simp only [to_digits]
  congr 1; funext t
  rw [show Nat.log2 BASE = 4 from rfl, show BASE - 1 = 2 ^ 4 - 1 from rfl,
    Nat.and_two_pow_sub_one_eq_mod, Nat.shiftRight_eq_div_pow, pow_mul]
  rfl

lemma getD_modify (l : List ℕ) (i j : ℕ) (f : ℕ → ℕ) :
    (l.modify i f).getD j 0 = if i = j ∧ j < l.length then f (l.getD j 0) else l.getD j 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_modify]
  rcases lt_or_ge j l.length with hj | hj
  · rw [List.getElem?_eq_getElem hj]; by_cases hij : i = j <;> simp [hij, hj]
  · rw [List.getElem?_eq_none hj]; simp; omega

/-- `multiplicities` counts each digit `j = 1..15`. -/
lemma multiplicities_eq (digits : List ℕ) (h : ∀ d ∈ digits, d < 16) :
    multiplicities digits = (List.range 15).map fun j => digits.count (j + 1) := by
  have key : ∀ (ds : List ℕ) (m : List ℕ), (∀ d ∈ ds, d < 16) → m.length = 15 →
      (ds.foldl (fun m d => if d > 0 then m.modify (d - 1) (· + 1) else m) m).length = 15 ∧
      ∀ j, (ds.foldl (fun m d => if d > 0 then m.modify (d - 1) (· + 1) else m) m).getD j 0 =
        m.getD j 0 + if j < 15 then ds.count (j + 1) else 0 := by
    intro ds
    induction ds with
    | nil => intro m _ hm; simp [hm]
    | cons d ds ih =>
      intro m hds hm
      have hd := hds d (by simp)
      have hlen : (if d > 0 then m.modify (d - 1) (· + 1) else m).length = 15 := by
        split_ifs <;> simp [hm]
      obtain ⟨h1, h2⟩ := ih _ (fun x hx => hds x (by simp [hx])) hlen
      refine ⟨by rw [List.foldl_cons]; exact h1, fun j => ?_⟩
      rw [List.foldl_cons, h2, List.count_cons]
      by_cases hd0 : d > 0
      · rw [if_pos hd0, getD_modify, hm]
        by_cases hj : j < 15
        · by_cases hdj : d - 1 = j
          · obtain rfl : d = j + 1 := by omega
            simp [hj]; ring
          · have : ¬ d = j + 1 := by omega
            simp [hdj, hj, this]
        · simp [hj]
      · rw [if_neg hd0]
        have : ¬ d = j + 1 := by omega
        by_cases hj : j < 15 <;> simp [hj, this]
  obtain ⟨h1, h2⟩ := key digits (List.replicate (BASE - 1) 0) h (by simp [BASE])
  rw [multiplicities]
  apply List.ext_getElem (by rw [h1]; simp)
  intro i hi1 hi2
  simp only [List.length_map, List.length_range] at hi2
  have := h2 i
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hi1, Option.getD_some] at this
  rw [this, if_pos hi2, List.getD_eq_getElem?_getD, List.getElem?_replicate,
    if_pos (by simp [BASE]; omega)]
  simp

end Bppp
