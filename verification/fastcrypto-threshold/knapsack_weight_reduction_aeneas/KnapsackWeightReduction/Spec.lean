/-
Copyright (c) 2022, Mysten Labs, Inc.
SPDX-License-Identifier: Apache-2.0

Definitions used to state the soundness theorem, and the pure lemmas about them. Nothing here
depends on the translated code. See README.md for what is proved.
-/
import Aeneas
import Mathlib.Algebra.BigOperators.Group.Finset.Basic

open Aeneas Std

namespace KnapsackWeightReduction

/-! ## Subsets and their weights

A subset `S` of the parties is a predicate `s : ℕ → Bool`: party `i` is in `S` iff `s i`. The
corollary `verify_reduction_sound_finset` restates the main theorem with `Finset`s. -/

/-- `∑ { ws[i] : i < k, s i = b }`: the weight of the subset `s` (if `b`) or of its complement
(if `!b`), restricted to the first `k` parties. -/
def wsum (ws : List U16) (s : ℕ → Bool) (b : Bool) : ℕ → ℕ
  | 0 => 0
  | k + 1 => wsum ws s b k + if s k = b then ws[k]!.val else 0

/-- `∑ { ws[i] : i < k }`. -/
def total (ws : List U16) : ℕ → ℕ
  | 0 => 0
  | k + 1 => total ws k + ws[k]!.val

/-- The four guarantees for the subset `s`, where `w(S)` is the original and `w'(S)` the reduced
weight of `S`, and `(t', f')` are the reduced thresholds. -/
def ReductionPropertiesHold (weights : List U16) (t f delta : ℕ) (reduced : List U16)
    (t' f' : ℕ) (s : ℕ → Bool) : Prop :=
  let w := wsum weights s true weights.length
  let w' := wsum reduced s true weights.length
  (w < t → w' < t') ∧                       -- (P) privacy
  (t + f + delta ≤ w → t' + f' ≤ w') ∧      -- (L1) liveness
  (w ≤ f → w' ≤ f') ∧                       -- (L2) Byzantine bound
  (t + delta ≤ w → t' ≤ w')                 -- (L3) liveness

/-! ## Lemmas about `wsum` and `total` -/

@[simp] theorem wsum_zero (ws : List U16) (s : ℕ → Bool) (b : Bool) : wsum ws s b 0 = 0 := rfl

theorem wsum_succ (ws : List U16) (s : ℕ → Bool) (b : Bool) (k : ℕ) :
    wsum ws s b (k + 1) = wsum ws s b k + if s k = b then ws[k]!.val else 0 := rfl

@[simp] theorem total_zero (ws : List U16) : total ws 0 = 0 := rfl

theorem total_succ (ws : List U16) (k : ℕ) : total ws (k + 1) = total ws k + ws[k]!.val := rfl

/-- A subset and its complement partition the parties. -/
theorem wsum_complement (ws : List U16) (s : ℕ → Bool) (k : ℕ) :
    wsum ws s true k + wsum ws s false k = total ws k := by
  induction k with
  | zero => rfl
  | succ k ih =>
    rw [wsum_succ, wsum_succ, total_succ]
    cases s k <;> simp <;> omega

/-- A subset weighs at most the total. -/
theorem wsum_le_total (ws : List U16) (s : ℕ → Bool) (b : Bool) (k : ℕ) :
    wsum ws s b k ≤ total ws k := by
  induction k with
  | zero => rfl
  | succ k ih =>
    rw [wsum_succ, total_succ]
    split <;> omega

/-- `total` is non-decreasing. -/
theorem total_mono (ws : List U16) {j k : ℕ} (h : j ≤ k) : total ws j ≤ total ws k := by
  induction k with
  | zero => simp_all
  | succ k ih =>
    rcases Nat.lt_or_eq_of_le h with h | h
    · rw [total_succ]; have := ih (by omega); omega
    · rw [h]

/-- Each weight is at most `65535`, so `k` of them sum to at most `65535 * k`. -/
theorem total_le (ws : List U16) (k : ℕ) : total ws k ≤ 65535 * k := by
  induction k with
  | zero => rfl
  | succ k ih =>
    rw [total_succ]
    have : ws[k]!.val ≤ 65535 := by scalar_tac
    omega

/-! ## The relaxation step of the knapsack table

`relax old q w u` is entry `u` of the table after the inner loop of `knapsack_min_original`
processes a party with original weight `w` and reduced weight `q`, starting from `old`. -/

def relax (old : List U32) (q w u : ℕ) : ℕ :=
  if q ≤ u ∧ old[u - q]!.val ≠ U32.max ∧ old[u - q]!.val + w < old[u]!.val then
    old[u - q]!.val + w
  else
    old[u]!.val

theorem relax_le_old (old : List U32) (q w u : ℕ) : relax old q w u ≤ old[u]!.val := by
  unfold relax; split <;> omega

theorem relax_le_shifted (old : List U32) (q w u : ℕ) (hq : q ≤ u)
    (h : old[u - q]!.val ≠ U32.max) : relax old q w u ≤ old[u - q]!.val + w := by
  unfold relax; split <;> simp_all

/-- A relaxed entry is either the old one or the shifted candidate. -/
theorem relax_cases (old : List U32) (q w u : ℕ) :
    relax old q w u = old[u]!.val ∨
      (q ≤ u ∧ old[u - q]!.val ≠ U32.max ∧ relax old q w u = old[u - q]!.val + w) := by
  unfold relax; split <;> simp_all

/-! ## From the checks to the guarantees

`verify_reduction` computes the table and four values of `max_reduced_weight`, and compares them
with the reduced thresholds. This lemma derives (P), (L1), (L2) and (L3) from the facts the proof
of `verify_reduction` establishes about those values. -/

theorem properties_of_checks
    (ws red : List U16)
    (t f delta t' f' : ℕ) (ht' : 1 ≤ t') (htfd : t + f + delta ≤ total ws ws.length)
    (tbl : ℕ → ℕ)
    -- The knapsack table bounds the original weight of every subset and of its complement.
    (htbl : ∀ s b, tbl (wsum red s b ws.length) ≤ wsum ws s b ws.length)
    -- `gP`, `g2`, `g3` and `g1` are the largest reduced weights whose table entry is at most
    -- `t - 1`, `f`, `W - (t + delta)` and `W - (t + f + delta)`.
    (gP g2 g3 g1 : ℕ)
    (hgP : ∀ u, u ≤ total red ws.length → tbl u ≤ t - 1 → u ≤ gP)
    (hg2 : ∀ u, u ≤ total red ws.length → tbl u ≤ f → u ≤ g2)
    (hg3 : ∀ u, u ≤ total red ws.length → tbl u ≤ total ws ws.length - (t + delta) → u ≤ g3)
    (hg1 : ∀ u, u ≤ total red ws.length → tbl u ≤ total ws ws.length - (t + f + delta) →
      u ≤ g1)
    -- The four checks in `verify_reduction` passed.
    (hP : gP ≤ t' - 1) (hL2 : g2 ≤ f')
    (hL3 : t' ≤ total red ws.length - g3) (hL1 : t' + f' ≤ total red ws.length - g1)
    (s : ℕ → Bool) :
    ReductionPropertiesHold ws t f delta red t' f' s := by
  have hc := wsum_complement ws s ws.length
  have hc' := wsum_complement red s ws.length
  have hin_le := wsum_le_total red s true ws.length
  have hout_le := wsum_le_total red s false ws.length
  have hin := htbl s true
  have hout := htbl s false
  refine ⟨?_, ?_, ?_, ?_⟩
  · -- (P)
    intro h
    have := hgP _ hin_le (by omega)
    omega
  · -- (L1)
    intro h
    have := hg1 _ hout_le (by omega)
    omega
  · -- (L2)
    intro h
    have := hg2 _ hin_le (by omega)
    omega
  · -- (L3)
    intro h
    have := hg3 _ hout_le (by omega)
    omega

/-! ## Subsets as `Finset`s -/

/-- `wsum` of the subset `S` is the `Finset` sum of the weights of its members. -/
theorem wsum_eq_sum (ws : List U16) (S : Finset ℕ) (k : ℕ) :
    wsum ws (fun i => decide (i ∈ S)) true k =
      ∑ i ∈ (Finset.range k).filter (· ∈ S), ws[i]!.val := by
  induction k with
  | zero => simp
  | succ k ih =>
    rw [wsum_succ, ih, Finset.range_add_one, Finset.filter_insert]
    by_cases hk : k ∈ S
    · simp [hk, Finset.sum_insert (by simp : k ∉ (Finset.range k).filter (· ∈ S))]
      omega
    · simp [hk]

end KnapsackWeightReduction
