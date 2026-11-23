-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Weights

/-!
# Lemmas about `LazyBases`

`LazyBases` stands for the current bases `cur_h`, `cur_g`: its points contracted with its
weights. Folding folds them (`cur_h_fold`), and `LazyBases::msm` is an MSM over them that leaves
them unchanged (`msm_eq`), whether or not it materializes the folds.
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E]

set_option linter.unusedSectionVars false

namespace NormLinear

/-- The fold `f0 [Q]_0 + f1 [Q]_1` of the points `Q`. -/
def foldPts (f0 f1 : F) (Q : List E) : List E :=
  (List.range ((Q.length + 1) / 2)).map fun i => f0 • Q.getD (2 * i) 0 + f1 • Q.getD (2 * i + 1) 0

lemma length_foldPts (f0 f1 : F) (Q : List E) : (foldPts f0 f1 Q).length = (Q.length + 1) / 2 := by
  simp [foldPts]

lemma getD_foldPts (f0 f1 : F) (Q : List E) (i : ℕ) :
    (foldPts f0 f1 Q).getD i 0 =
      if i < (Q.length + 1) / 2 then f0 • Q.getD (2 * i) 0 + f1 • Q.getD (2 * i + 1) 0 else 0 := by
  unfold foldPts
  split_ifs with h
  · rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range h]; rfl
  · rw [getD_eq_zero_of_le (by simp; omega)]

lemma contract'_tensor_pair {W : Weights F} (hw : 0 < W.w.length) (f0 f1 : F) (P : List E) :
    contract' (W.tensor_pair f0 f1).w P = foldPts f0 f1 (contract' W.w P) := by
  apply List.ext_getElem (by rw [length_contract'_tensor_pair hw, length_foldPts])
  intro i h1 h2
  have h2' : i < ((contract' W.w P).length + 1) / 2 := by rwa [length_foldPts] at h2
  rw [getElem_eq_getD' _ h1 0, getElem_eq_getD' _ h2 0,
    getD_contract' (by rw [length_tensor_pair]; omega), contractAt_tensor_pair, getD_foldPts,
    if_pos h2', getD_contract' hw, getD_contract' hw]

namespace LazyBases

variable (lb : LazyBases F E)

/-- The base `G`. -/
def g0 : E := lb.points'.1

/-- The current bases `H`. -/
def cur_h : List E := contract' lb.w_h.w lb.points'.2.1

/-- The current bases `G_vec`. -/
def cur_g : List E := contract' lb.w_g.w lb.points'.2.2

/-- Both weight vectors are nonempty. -/
def Pos : Prop := 0 < lb.w_h.w.length ∧ 0 < lb.w_g.w.length

lemma pos_fold {lb : LazyBases F E} (h : lb.Pos) (rho gamma : F) : (lb.fold rho gamma).Pos := by
  simp only [Pos, fold, length_tensor_pair] at h ⊢
  constructor <;> omega

@[simp] lemma points'_fold (rho gamma : F) : (lb.fold rho gamma).points' = lb.points' := rfl

lemma cur_h_fold (h : lb.Pos) (rho gamma : F) :
    (lb.fold rho gamma).cur_h = foldPts one gamma lb.cur_h := by
  rw [cur_h, points'_fold]; exact contract'_tensor_pair h.1 _ _ _

lemma cur_g_fold (h : lb.Pos) (rho gamma : F) :
    (lb.fold rho gamma).cur_g = foldPts rho gamma lb.cur_g := by
  rw [cur_g, points'_fold]; exact contract'_tensor_pair h.2 _ _ _

@[simp] lemma g0_fold (rho gamma : F) : (lb.fold rho gamma).g0 = lb.g0 := rfl

lemma ceil_le {a n c : ℕ} (hn : 0 < n) (h : (a + n - 1) / n ≤ c) : a ≤ c * n := by
  have : (a + n - 1) / n < c + 1 := by omega
  rw [Nat.div_lt_iff_lt_mul hn, add_mul, one_mul] at this
  generalize c * n = m at *
  omega

/-- The MSM over the current bases with coefficients `cs`, for `|cur| ≤ |cs|`. -/
lemma msm_tensor_cur (W : Weights F) (hw : 0 < W.w.length) (cs : List F) (P : List E)
    (h : (contract' W.w P).length ≤ cs.length) :
    (List.zipWith (· • ·) ((W.tensor cs).take P.length) P).sum =
      ∑ i ∈ range cs.length, cs.getD i 0 • (contract' W.w P).getD i 0 := by
  rw [msm_tensor W cs P (ceil_le hw (by rwa [length_contract' hw] at h))]
  exact sum_congr rfl fun i _ => by rw [getD_contract' hw]

lemma length_take_tensor (W : Weights F) (hw : 0 < W.w.length) (cs : List F) (P : List E)
    (h : (contract' W.w P).length ≤ cs.length) : ((W.tensor cs).take P.length).length = P.length := by
  rw [List.length_take, length_tensor]
  exact min_eq_left (ceil_le hw (by rwa [length_contract' hw] at h))

lemma sum_filter_unzip (L : List (F × E)) :
    multi_scalar_mul (L.filter fun x => decide (x.1 ≠ 0)).unzip.1
      (L.filter fun x => decide (x.1 ≠ 0)).unzip.2 = .ok (L.map fun x => x.1 • x.2).sum := by
  unfold multi_scalar_mul
  rw [List.unzip_fst, List.unzip_snd, if_neg (by simp)]
  congr 1
  induction L with
  | nil => rfl
  | cons x L ih =>
    obtain ⟨s, p⟩ := x
    by_cases hs : s = 0 <;> simp_all

lemma sum_map_zip (a : List F) (b : List E) :
    ((List.zip a b).map fun (s, p) => s • p).sum = (List.zipWith (· • ·) a b).sum := by
  rw [List.map_zip_eq_zipWith]; rfl

lemma new_w : (Weights.new : Weights F).w = [1] := rfl

/-- `LazyBases::msm` is an MSM over the current bases, and leaves them unchanged. -/
lemma msm_eq (lb : LazyBases F E) (hp : lb.Pos) (v : F) (hc gc : List F)
    (hh : lb.cur_h.length ≤ hc.length) (hg : lb.cur_g.length ≤ gc.length) :
    ∃ lb', lb.msm v hc gc = .ok (v • lb.g0 + ∑ i ∈ range hc.length, hc.getD i 0 • lb.cur_h.getD i 0 +
        ∑ i ∈ range gc.length, gc.getD i 0 • lb.cur_g.getD i 0, lb') ∧
      lb'.Pos ∧ lb'.cur_h = lb.cur_h ∧ lb'.cur_g = lb.cur_g ∧ lb'.g0 = lb.g0 := by
  have hsum : ∀ (W : Weights F), 0 < W.w.length → ∀ (cs : List F) (P : List E),
      (contract' W.w P).length ≤ cs.length →
      ((List.zip ((W.tensor cs).take P.length) P).map fun x => x.1 • x.2).sum =
        ∑ i ∈ range cs.length, cs.getD i 0 • (contract' W.w P).getD i 0 := fun W hw cs P h => by
    rw [sum_map_zip]; exact msm_tensor_cur W hw cs P h
  unfold LazyBases.msm
  by_cases hm : lb.w_h.len = 2 ^ FOLD_BATCH_ROUNDS
  · rw [if_pos hm]
    simp only [contract_eq hp.1, contract_eq hp.2, bind, Except.bind, pure, Except.pure]
    rw [sum_filter_unzip]
    refine ⟨⟨.Folded lb.points'.1 (contract' lb.w_h.w lb.points'.2.1)
      (contract' lb.w_g.w lb.points'.2.2), .new, .new⟩, ?_, by simp [Pos, new_w], ?_, ?_, rfl⟩
    · simp only [len, points', List.map_cons, List.map_append, List.sum_cons, List.sum_append]
      rw [hsum _ (by simp [new_w]) hc _ (by rw [new_w, contract'_one]; exact hh),
        hsum _ (by simp [new_w]) gc _ (by rw [new_w, contract'_one]; exact hg), new_w,
        contract'_one, contract'_one]
      simp only [g0, cur_h, cur_g, points', add_assoc]
    · simp only [cur_h, points', new_w]; exact contract'_one _
    · simp only [cur_g, points', new_w]; exact contract'_one _
  · rw [if_neg hm]
    cases hpts : lb.points with
    | Crs gens =>
      simp only [pure, Except.pure, bind, Except.bind, len, points', hpts]
      have hh' : (contract' lb.w_h.w gens.h_vec).length ≤ hc.length := by
        simpa [cur_h, points', hpts] using hh
      have hg' : (contract' lb.w_g.w gens.g_vec).length ≤ gc.length := by
        simpa [cur_g, points', hpts] using hg
      have l1 := length_take_tensor lb.w_h hp.1 hc gens.h_vec hh'
      have l2 := length_take_tensor lb.w_g hp.2 gc gens.g_vec hg'
      simp only [Generators.msm, mixed_multi_scalar_mul]
      rw [if_neg (by simp [l1, l2])]
      simp only [List.cons_append, List.zipWith_cons_cons, List.zipWith_append l1, List.sum_cons,
        List.sum_append, List.zipWith_nil_left, List.sum_nil, add_zero]
      refine ⟨lb, ?_, hp, rfl, rfl, rfl⟩
      rw [msm_tensor_cur _ hp.1 _ _ hh', msm_tensor_cur _ hp.2 _ _ hg']
      simp only [g0, cur_h, cur_g, points', hpts, add_assoc]
    | Folded g hv gv =>
      simp only [pure, Except.pure, bind, Except.bind, len, points', hpts]
      rw [sum_filter_unzip]
      refine ⟨lb, ?_, hp, rfl, rfl, rfl⟩
      simp only [List.map_cons, List.map_append, List.sum_cons, List.sum_append]
      have h1 := hsum lb.w_h hp.1 hc hv (by simpa [cur_h, points', hpts] using hh)
      have h2 := hsum lb.w_g hp.2 gc gv (by simpa [cur_g, points', hpts] using hg)
      rw [h1, h2]
      simp only [g0, cur_h, cur_g, points', hpts, add_assoc]

end LazyBases

end NormLinear

end Bppp
