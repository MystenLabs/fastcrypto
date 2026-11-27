-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.NormLinear
import bulletproofspp.Proofs.Model.Util
import bulletproofspp.Proofs.Spec.NormLinearCompleteness

/-!
# Lemmas about `Weights`, `split_even_odd` and `interleave`

`Weights::contract` with weights `w` maps `P` to `contract' w P`, entry `i` of which is
`Σ_r w_r P_{i|w|+r}` (`getD_contract'`). Folding the weights folds the contracted points
(`contract'_tensor_pair`), and an MSM with tensored coefficients is an MSM over the contracted
points (`msm_tensor`).
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E]

set_option linter.unusedSectionVars false

namespace NormLinear

/-! ## `chunks` -/

lemma chunks_nil {α : Type} (n : ℕ) : chunks n ([] : List α) = [] := by
  rw [chunks]; simp

lemma chunks_cons {α : Type} {n : ℕ} (hn : 0 < n) {l : List α} (hl : l ≠ []) :
    chunks n l = l.take n :: chunks n (l.drop n) := by
  rw [chunks, dif_neg (by rintro (h | h) <;> [omega; exact hl h])]

lemma ceil_div_step {a n : ℕ} (ha : 0 < a) (hn : 0 < n) :
    (a + n - 1) / n = (a - n + n - 1) / n + 1 := by
  rcases Nat.lt_or_ge n a with h | h
  · rw [show a + n - 1 = (a - n + n - 1) + n by omega, Nat.add_div_right _ hn]
  · rw [show a + n - 1 = (a - 1) + n by omega, Nat.add_div_right _ hn,
      Nat.div_eq_of_lt (by omega : a - 1 < n), show a - n + n - 1 = n - 1 by omega,
      Nat.div_eq_of_lt (by omega : n - 1 < n)]

lemma length_chunks {α : Type} {n : ℕ} (hn : 0 < n) :
    ∀ l : List α, (chunks n l).length = (l.length + n - 1) / n := by
  intro l
  induction h : l.length using Nat.strong_induction_on generalizing l with
  | _ k ih =>
    rcases l with _ | ⟨x, xs⟩
    · subst h; rw [chunks_nil]; simp [Nat.div_eq_of_lt (by omega : n - 1 < n)]
    · subst h
      rw [chunks_cons hn (by simp), List.length_cons,
        ih _ (by rw [List.length_drop]; simp; omega) _ rfl, List.length_drop,
        ceil_div_step (a := (x :: xs).length) (by simp) hn]

/-! ## `contract` -/

/-- Entry `i` of the contraction: `Σ_{r<|w|} w_r P_{i|w|+r}`. -/
def contractAt (w : List F) (P : List E) (i : ℕ) : E :=
  ∑ r ∈ range w.length, w.getD r 0 • P.getD (i * w.length + r) 0

/-- `Weights::contract` without the error. -/
def contract' (w : List F) (P : List E) : List E :=
  (chunks w.length P).map fun chunk => (List.zipWith (· • ·) (w.take chunk.length) chunk).sum

lemma length_contract' {w : List F} (hw : 0 < w.length) (P : List E) :
    (contract' w P).length = (P.length + w.length - 1) / w.length := by
  rw [contract', List.length_map, length_chunks hw]

lemma length_le_of_mem_chunks {α : Type} {n : ℕ} (hn : 0 < n) :
    ∀ (l : List α), ∀ ch ∈ chunks n l, ch.length ≤ n := by
  intro l
  induction h : l.length using Nat.strong_induction_on generalizing l with
  | _ k ih =>
    rcases l with _ | ⟨x, xs⟩
    · simp [chunks_nil]
    · rw [chunks_cons hn (by simp)]
      intro ch hch
      rcases List.mem_cons.1 hch with rfl | hch
      · simp
      · subst h; exact ih _ (by rw [List.length_drop]; simp; omega) _ rfl ch hch

lemma contract_eq {W : Weights F} (hw : 0 < W.w.length) (P : List E) :
    W.contract P = .ok (contract' W.w P) := by
  unfold Weights.contract contract'
  simp only [Weights.len]
  have hle := length_le_of_mem_chunks hw P
  generalize chunks W.w.length P = cs at hle
  induction cs with
  | nil => rfl
  | cons ch cs ih =>
    rw [List.mapM_cons, ih fun c hc => hle c (by simp [hc])]
    have : (W.w.take ch.length).length = ch.length := by
      rw [List.length_take]; exact min_eq_left (hle ch (by simp))
    simp [multi_scalar_mul, this, bind, Except.bind, pure, Except.pure]

lemma contractAt_nil (w : List F) (i : ℕ) : contractAt w ([] : List E) i = 0 := by
  simp [contractAt]

lemma getD_drop' {α : Type} (l : List α) (n k : ℕ) (d : α) :
    (l.drop n).getD k d = l.getD (n + k) d := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_drop]

lemma getD_take' {α : Type} (l : List α) {n k : ℕ} (h : k < n) (d : α) :
    (l.take n).getD k d = l.getD k d := by
  simp [List.getD_eq_getElem?_getD, h]

lemma getD_append_lt {α : Type} (l₁ l₂ : List α) {k : ℕ} (h : k < l₁.length) (d : α) :
    (l₁ ++ l₂).getD k d = l₁.getD k d := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_append_left h]

lemma getD_append_ge {α : Type} (l₁ l₂ : List α) {k : ℕ} (h : l₁.length ≤ k) (d : α) :
    (l₁ ++ l₂).getD k d = l₂.getD (k - l₁.length) d := by
  simp [List.getD_eq_getElem?_getD, List.getElem?_append_right h]

/-- A zipped sum, extended by terms that vanish. -/
lemma sum_zipWith_ext {α β M : Type*} [AddCommMonoid M] (f : α → β → M) (a : List α)
    (b : List β) (da : α) (db : β) (N : ℕ) (hN : min a.length b.length ≤ N)
    (hz : ∀ k, min a.length b.length ≤ k → k < N → f (a.getD k da) (b.getD k db) = 0) :
    (List.zipWith f a b).sum = ∑ k ∈ range N, f (a.getD k da) (b.getD k db) := by
  rw [sum_zipWith f a b da db]
  refine sum_subset (range_subset_range.2 hN) fun k hk hk' => ?_
  simp only [mem_range, not_lt] at hk hk'
  exact hz k hk' hk

lemma contractAt_drop (w : List F) (P : List E) (i : ℕ) :
    contractAt w (P.drop w.length) i = contractAt w P (i + 1) := by
  refine sum_congr rfl fun r _ => ?_
  rw [getD_drop']
  congr 2; ring

lemma getD_contract' {w : List F} (hw : 0 < w.length) (P : List E) (i : ℕ) :
    (contract' w P).getD i 0 = contractAt w P i := by
  induction h : P.length using Nat.strong_induction_on generalizing P i with
  | _ k ih =>
    rcases P with _ | ⟨x, xs⟩
    · simp [contract', chunks_nil, contractAt_nil]
    · subst h
      have hc : contract' w (x :: xs) = (List.zipWith (· • ·) (w.take ((x :: xs).take w.length).length)
          ((x :: xs).take w.length)).sum :: contract' w ((x :: xs).drop w.length) := by
        rw [contract', chunks_cons hw (by simp)]; rfl
      rw [hc]
      rcases i with _ | i
      · rw [List.getD_cons_zero, contractAt]
        rw [sum_zipWith_ext _ _ _ 0 0 w.length (by simp)]
        · refine sum_congr rfl fun r hr => ?_
          simp only [mem_range] at hr
          rw [getD_take' _ hr, zero_mul, zero_add]
          by_cases hr' : r < ((x :: xs).take w.length).length
          · rw [getD_take' _ (by simpa using hr')]
          · have hP : (x :: xs).length ≤ r := by simp only [List.length_take] at hr'; omega
            rw [getD_eq_zero_of_le hP, smul_zero, smul_zero]
        · intro k hk _
          rw [getD_eq_zero_of_le (show ((x :: xs).take w.length).length ≤ k by
            simp only [List.length_take] at hk ⊢; omega), smul_zero]
      · rw [List.getD_cons_succ, ih _ (by rw [List.length_drop]; simp; omega) _ _ rfl,
          contractAt_drop]

/-! ## `tensor` -/

lemma sparse_mul_eq (a b : F) : sparse_mul a b = a * b := by
  unfold sparse_mul; split_ifs with h <;> simp [h]

lemma tensor_cons (W : Weights F) (c : F) (cs : List F) :
    W.tensor (c :: cs) = W.w.map (c * ·) ++ W.tensor cs := by
  simp [Weights.tensor, sparse_mul_eq]

lemma length_tensor (W : Weights F) (cs : List F) : (W.tensor cs).length = cs.length * W.w.length := by
  induction cs with
  | nil => simp [Weights.tensor]
  | cons c cs ih => rw [tensor_cons, List.length_append, ih, List.length_map]; simp; ring

/-- An MSM with coefficients `cs ⊗ w` over `P` is an MSM with coefficients `cs` over the contracted
points. -/
lemma msm_tensor (W : Weights F) (cs : List F) (P : List E) (hP : P.length ≤ cs.length * W.w.length) :
    (List.zipWith (· • ·) ((W.tensor cs).take P.length) P).sum =
      ∑ i ∈ range cs.length, cs.getD i 0 • contractAt W.w P i := by
  -- Both are `Σ_{j < |cs||w|} (cs ⊗ w)_j P_j`.
  have key : ∀ (cs : List F) (P : List E), ∑ j ∈ range (cs.length * W.w.length),
      (W.tensor cs).getD j 0 • P.getD j 0 =
      ∑ i ∈ range cs.length, cs.getD i 0 • contractAt W.w P i := by
    intro cs
    induction cs with
    | nil => simp
    | cons c cs ih =>
      intro P
      rw [List.length_cons, add_mul, one_mul, add_comm (cs.length * W.w.length), sum_range_add,
        sum_range_succ']
      simp only [List.getD_cons_succ, List.getD_cons_zero, ← contractAt_drop]
      rw [← ih (P.drop W.w.length), add_comm (∑ i ∈ range (cs.length * W.w.length), _)]
      congr 1
      · rw [contractAt, smul_sum]
        refine sum_congr rfl fun r hr => ?_
        simp only [mem_range] at hr
        rw [tensor_cons, getD_append_lt _ _ (by simpa using hr), List.getD_eq_getElem?_getD,
          List.getElem?_map, List.getD_eq_getElem?_getD (l := W.w),
          List.getElem?_eq_getElem hr]
        simp [mul_smul]
      · refine sum_congr rfl fun j hj => ?_
        rw [tensor_cons, getD_append_ge _ _ (by simp), List.length_map,
          Nat.add_sub_cancel_left, getD_drop']
  rw [sum_zipWith _ _ _ 0 0, ← key]
  simp only [List.length_take, length_tensor, min_eq_left hP, min_self]
  refine (sum_subset (range_subset_range.2 hP) ?_).symm.trans (sum_congr rfl fun j hj => ?_) |>.symm
  · intro j _ hj
    simp only [mem_range, not_lt] at hj
    rw [getD_eq_zero_of_le hj, smul_zero]
  · simp only [mem_range] at hj
    rw [getD_take' _ hj]

lemma tensor_pair_w (W : Weights F) (f0 f1 : F) :
    (W.tensor_pair f0 f1).w = W.w.map (f0 * ·) ++ W.w.map (f1 * ·) := by
  simp [Weights.tensor_pair, Weights.tensor, sparse_mul_eq]

/-- Folding the weights folds the contracted points. -/
lemma contractAt_tensor_pair (W : Weights F) (f0 f1 : F) (P : List E) (i : ℕ) :
    contractAt (W.tensor_pair f0 f1).w P i =
      f0 • contractAt W.w P (2 * i) + f1 • contractAt W.w P (2 * i + 1) := by
  rw [contractAt, tensor_pair_w]
  simp only [List.length_append, List.length_map]
  rw [sum_range_add, contractAt, contractAt, smul_sum, smul_sum]
  congr 1
  · refine sum_congr rfl fun r hr => ?_
    simp only [mem_range] at hr
    rw [getD_append_lt _ _ (by simpa using hr), List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getD_eq_getElem?_getD (l := W.w), List.getElem?_eq_getElem hr]
    simp only [Option.map_some, Option.getD_some, mul_smul]
    congr 3; ring
  · refine sum_congr rfl fun r hr => ?_
    simp only [mem_range] at hr
    rw [getD_append_ge _ _ (by simp), List.length_map, Nat.add_sub_cancel_left,
      List.getD_eq_getElem?_getD, List.getElem?_map, List.getD_eq_getElem?_getD (l := W.w),
      List.getElem?_eq_getElem hr]
    simp only [Option.map_some, Option.getD_some, mul_smul]
    congr 3; ring

lemma length_tensor_pair (W : Weights F) (f0 f1 : F) :
    (W.tensor_pair f0 f1).w.length = 2 * W.w.length := by
  rw [tensor_pair_w]; simp; ring

lemma ceil_div_two {a n : ℕ} (hn : 0 < n) :
    (a + 2 * n - 1) / (2 * n) = ((a + n - 1) / n + 1) / 2 := by
  rw [← Nat.add_div_right _ hn, Nat.div_div_eq_div_mul, mul_comm n 2]
  congr 1; omega

lemma length_contract'_tensor_pair {W : Weights F} (hw : 0 < W.w.length) (f0 f1 : F) (P : List E) :
    (contract' (W.tensor_pair f0 f1).w P).length =
      ((contract' W.w P).length + 1) / 2 := by
  rw [length_contract' (by rw [length_tensor_pair]; omega), length_contract' hw,
    length_tensor_pair, ceil_div_two hw]

lemma contract'_one (P : List E) : contract' [(1 : F)] P = P := by
  apply List.ext_getElem (by rw [length_contract' (by simp)]; simp)
  intro i h1 h2
  have := getD_contract' (w := [(1 : F)]) (by simp) P i
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h1, Option.getD_some] at this
  rw [this, contractAt]
  simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h2]

/-! ## `split_even_odd`, `interleave`, `odd_only` -/

lemma getD_unzip_pairs {α : Type} (d : α) : ∀ (v : List α), v.length % 2 = 0 → ∀ i,
    (unzip_pairs v).1.getD i d = v.getD (2 * i) d ∧ (unzip_pairs v).2.getD i d = v.getD (2 * i + 1) d
  | [], _, i => by simp [unzip_pairs]
  | [_], h, _ => by simp at h
  | x :: y :: rest, h, i => by
    have ih := getD_unzip_pairs d rest (by simp at h; omega)
    rcases i with _ | i
    · simp [unzip_pairs]
    · simp only [unzip_pairs, List.getD_cons_succ]
      rw [(ih i).1, (ih i).2, show 2 * (i + 1) = 2 * i + 1 + 1 by ring]
      simp

lemma getD_append_zero (v : List F) (k : ℕ) : (v ++ [0]).getD k 0 = v.getD k 0 := by
  rcases lt_or_ge k v.length with hk | hk
  · rw [getD_append_lt _ _ hk]
  · rw [getD_append_ge _ _ hk, getD_eq_zero_of_le hk]
    rcases (show k - v.length = 0 ∨ 1 ≤ k - v.length by omega) with h0 | h0
    · rw [h0]; rfl
    · exact getD_eq_zero_of_le (by simpa using h0)

lemma getD_split_even_odd (v : List F) (i : ℕ) :
    (split_even_odd v).1.getD i 0 = v.getD (2 * i) 0 ∧ (split_even_odd v).2.getD i 0 = v.getD (2 * i + 1) 0 := by
  unfold split_even_odd
  split_ifs with h
  · obtain ⟨h1, h2⟩ := getD_unzip_pairs (0 : F) (v ++ [0]) (by simp; omega) i
    rw [h1, h2, getD_append_zero, getD_append_zero]; exact ⟨rfl, rfl⟩
  · exact getD_unzip_pairs (0 : F) v (by omega) i

lemma length_interleave (a b : List F) : (interleave a b).length = 2 * min a.length b.length := by
  induction a generalizing b with
  | nil => simp [interleave]
  | cons x a ih =>
    cases b with
    | nil => simp [interleave]
    | cons y b =>
      have := ih b
      simp only [interleave, List.zip_cons_cons, List.flatMap_cons] at this ⊢
      simp only [List.length_append, this, List.length_cons, List.length_nil]; omega

lemma getD_interleave (a b : List F) (h : a.length = b.length) (j : ℕ) :
    (interleave a b).getD (2 * j) 0 = a.getD j 0 ∧
      (interleave a b).getD (2 * j + 1) 0 = b.getD j 0 := by
  induction a generalizing b j with
  | nil => cases b <;> simp_all [interleave]
  | cons x a ih =>
    cases b with
    | nil => simp at h
    | cons y b =>
      have hfh : interleave (x :: a) (y :: b) = x :: y :: interleave a b := by
        simp [interleave]
      rw [hfh]
      rcases j with _ | j
      · simp
      · rw [show 2 * (j + 1) = 2 * j + 1 + 1 by ring]
        simp only [List.getD_cons_succ]
        exact ih b (by simpa using h) j

/-- An MSM with coefficients `interleave a b` over `Q` pairs `a` with the even points and `b`
with the odd ones. -/
lemma msm_interleave (a b : List F) (Q : List E) (h : a.length = b.length) :
    (List.zipWith (· • ·) (interleave a b) Q).sum =
      ∑ j ∈ range a.length, (a.getD j 0 • Q.getD (2 * j) 0 + b.getD j 0 • Q.getD (2 * j + 1) 0) := by
  rw [sum_zipWith_ext _ _ _ 0 0 (2 * a.length) (by rw [length_interleave, h, min_self]; omega)
    (fun k hk _ => by
      rw [getD_eq_zero_of_le (show Q.length ≤ k by rw [length_interleave] at hk; omega),
        smul_zero]),
    Spec.NormLinear.sum_range_two_mul]
  refine sum_congr rfl fun j _ => ?_
  rw [(getD_interleave a b h j).1, (getD_interleave a b h j).2]

lemma odd_only_eq (b : List F) : odd_only b = interleave (List.replicate b.length 0) b := by
  induction b with
  | nil => simp [odd_only, interleave]
  | cons y b ih =>
    simp only [odd_only, List.flatMap_cons, List.length_cons, List.replicate_succ,
      interleave, List.zip_cons_cons] at ih ⊢
    rw [ih]

end NormLinear

end Bppp
