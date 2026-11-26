-- THIS FILE IS AI-ONLY
import merkle.Proofs.Model

/-!
What a path of any length can open to in a tree built by `MerkleTree`, the fact that
`MerkleProof::verify_for_trusted_tree` and the non-inclusion proofs rest on:

* `trusted_opening`: if hashing `leaf_hash(x)` up a path `ps` with index `i` gives the root of the
  tree over the leaf hashes of `ys`, then `ps` has the depth of the tree, `i < ys.len()`,
  `x = ys[i]` and `ps` has the bytes of the honest path, or `H` has a collision or hashes some input
  to 32 zero bytes (`ZeroHash`), the bytes of `Node::Empty`.
* `right_most`: on the honest path of a leaf that is not the last one, some left child has a
  sibling that is a hash.
-/

open Aeneas Aeneas.Std
open fastcrypto

namespace MerkleProofs

variable (H : List U8 → Array U8 32#usize)

/-- A node that is the hash of something. -/
def IsHash (a : Node) : Prop := ∃ x, a = .Digest (H x)

lemma digest_eq {x y : List U8} (h : (H x).val = (H y).val) : H x = H y :=
  (Aeneas.Std.Array.eq_iff _ _).mpr h

lemma innerN_bytes_inj (a b a' b' : Node) (h : bytesOf (innerN H a b) = bytesOf (innerN H a' b')) :
    (bytesOf a = bytesOf a' ∧ bytesOf b = bytesOf b') ∨ Collision H :=
  innerN_inj H a b a' b' (congrArg merkle.Node.Digest (digest_eq H h))

lemma leafN_bytes_inj (x y : List U8) (h : bytesOf (leafN H x) = bytesOf (leafN H y)) :
    x = y ∨ Collision H :=
  leafN_inj H x y (congrArg merkle.Node.Digest (digest_eq H h))

lemma leaf_inner (x : List U8) (a b : Node) (h : bytesOf (leafN H x) = bytesOf (innerN H a b)) :
    Collision H :=
  ⟨_, _, by simp, digest_eq H h⟩

lemma isHash_innerN (a b : Node) : IsHash H (innerN H a b) := ⟨_, rfl⟩

lemma isHash_leafN (x : List U8) : IsHash H (leafN H x) := ⟨_, rfl⟩

lemma zeroHash_of_isHash (a : Node) (ha : IsHash H a) (h : bytesOf a = bytesOf .Empty) :
    ZeroHash H := by
  obtain ⟨x, rfl⟩ := ha; exact ⟨x, h⟩

lemma getD_pad (l : List Node) (i : Nat) : (pad l).getD i .Empty = l.getD i .Empty := by
  unfold pad
  split
  · simp only [List.getD_eq_getElem?_getD, List.getElem?_append, List.getElem?_cons]
    split
    · rfl
    · rename_i h
      split <;> simp_all
  · rfl

lemma getD_up (l : List Node) (j : Nat) (hj : j < (up H l).length) :
    (up H l).getD j .Empty = innerN H (l.getD (2 * j) .Empty) (l.getD (2 * j + 1) .Empty) := by
  have hp := length_pad l
  rw [length_up] at hj
  have hj' : j < (pad l).length / 2 := by rw [hp]; exact hj
  rw [List.getD_eq_getElem _ _ (by rw [length_up]; exact hj)]
  simp only [up]
  rw [getElem_parents H (pad l) j hj', ← getD_pad l (2 * j), ← getD_pad l (2 * j + 1),
    List.getD_eq_getElem _ _ (by omega), List.getD_eq_getElem _ _ (by omega)]

lemma isHash_up (l : List Node) : ∀ a ∈ up H l, IsHash H a := by
  intro a ha
  obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem ha
  rw [← List.getD_eq_getElem _ .Empty hj, getD_up H l j hj]
  exact isHash_innerN H _ _

lemma up_ne_nil (l : List Node) (h : ¬ l.length ≤ 1) : up H l ≠ [] := by
  intro he; have := congrArg List.length he; rw [length_up] at this; simp at this; omega

lemma depth_up (l : List Node) (h : ¬ l.length ≤ 1) :
    depth l.length = depth (up H l).length + 1 := by
  rw [depth, length_up]; simp [h]

lemma rootOf_up (l : List Node) (h : ¬ l.length ≤ 1) : rootOf H l = rootOf H (up H l) := by
  rw [rootOf]; simp [h]

lemma pathOf_up (l : List Node) (i : Nat) (h : ¬ l.length ≤ 1) :
    pathOf H l i = l.getD (if i % 2 = 0 then i + 1 else i - 1) .Empty :: pathOf H (up H l) (i / 2) := by
  rw [pathOf, dite_eq_right h, getD_pad]

lemma rootOf_isHash (l : List Node) (hl : l ≠ []) (h : ∀ a ∈ l, IsHash H a) :
    IsHash H (rootOf H l) := by
  by_cases h1 : l.length ≤ 1
  · rw [rootOf]
    rw [dite_eq_left h1]
    obtain ⟨a, rfl⟩ : ∃ a, l = [a] := by
      match l, h1 with
      | [a], _ => exact ⟨a, rfl⟩
      | [], _ => exact absurd rfl hl
    exact h a (by simp)
  · rw [rootOf_up H l h1]
    exact rootOf_isHash (up H l) (up_ne_nil H l h1) (isHash_up H l)
termination_by l.length
decreasing_by exact length_up_lt H l h1

/-- A path of the depth of the tree from `c` with index `i` to the root: `i` is a leaf, `c` and the
path have the bytes of that leaf and its honest path, or `c` has the bytes of an `Empty` leaf, or
`H` has a collision or a zero output. -/
lemma fold_eq_depth (l : List Node) (hl : l ≠ []) (c : Node) (ps : List Node) (i : Nat)
    (hlen : ps.length = depth l.length) (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H c ps i) = bytesOf (rootOf H l)) :
    Collision H ∨ ZeroHash H ∨ bytesOf c = bytesOf .Empty ∨
      (i < l.length ∧ bytesOf c = bytesOf (l.getD i .Empty) ∧
        ps.map bytesOf = (pathOf H l i).map bytesOf) := by
  by_cases h1 : l.length ≤ 1
  · have hd : depth l.length = 0 := by rw [depth]; simp [h1]
    rw [hd] at hlen
    obtain rfl : ps = [] := List.eq_nil_of_length_eq_zero hlen
    obtain rfl : i = 0 := by simp at hi; omega
    obtain ⟨a, rfl⟩ : ∃ a, l = [a] := by
      match l, h1 with
      | [a], _ => exact ⟨a, rfl⟩
      | [], _ => exact absurd rfl hl
    right; right; right
    refine ⟨by simp, ?_, ?_⟩
    · simpa [fold, rootOf] using h
    · simp [pathOf]
  · rw [rootOf_up H l h1] at h
    have hd := depth_up H l h1
    cases ps with
    | nil => simp at hlen; omega
    | cons s ps =>
      simp only [fold] at h
      have hlen' : ps.length = depth (up H l).length := by simp at hlen; omega
      have hi' : i / 2 < 2 ^ ps.length := by
        simp only [List.length_cons, Nat.pow_succ] at hi; omega
      rcases fold_eq_depth (up H l) (up_ne_nil H l h1) (step H c s i) ps (i / 2) hlen' hi' h with
        hc | hz | hz | ⟨hu, hb, hp⟩
      · exact Or.inl hc
      · exact Or.inr (Or.inl hz)
      · right; left
        exact zeroHash_of_isHash H _ (by unfold step; split <;> exact isHash_innerN H _ _) hz
      · rw [getD_up H l (i / 2) hu] at hb
        have hlu := length_up H l
        have hil : i < l.length + l.length % 2 := by omega
        unfold step at hb
        split at hb
        · rename_i he
          have e1 : 2 * (i / 2) = i := by omega
          rw [e1] at hb
          rcases innerN_bytes_inj H _ _ _ _ hb with ⟨hc1, hs1⟩ | hcol
          · by_cases hil' : i < l.length
            · right; right; right
              refine ⟨hil', hc1, ?_⟩
              rw [pathOf_up H l i h1]
              simp only [List.map_cons, he, ite_true, hs1, hp]
            · right; right; left
              rw [hc1, List.getD_eq_default _ _ (by omega)]
          · exact Or.inl hcol
        · rename_i he
          have e1 : 2 * (i / 2) + 1 = i := by omega
          have e2 : 2 * (i / 2) = i - 1 := by omega
          rw [e1, e2] at hb
          rcases innerN_bytes_inj H _ _ _ _ hb with ⟨hs1, hc1⟩ | hcol
          · by_cases hil' : i < l.length
            · right; right; right
              refine ⟨hil', hc1, ?_⟩
              rw [pathOf_up H l i h1]
              simp only [List.map_cons, he, ite_false, hs1, hp]
            · right; right; left
              rw [hc1, List.getD_eq_default _ _ (by omega)]
          · exact Or.inl hcol
termination_by l.length
decreasing_by exact length_up_lt H l h1

/-- A path shorter than the depth of the tree: `c` has the bytes of an inner node or of `Empty`, or
`H` has a collision or a zero output. -/
lemma fold_short (l : List Node) (c : Node) (ps : List Node) (i : Nat)
    (hlen : ps.length < depth l.length) (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H c ps i) = bytesOf (rootOf H l)) :
    Collision H ∨ ZeroHash H ∨ bytesOf c = bytesOf .Empty ∨
      ∃ a b, bytesOf c = bytesOf (innerN H a b) := by
  have h1 : ¬ l.length ≤ 1 := by
    intro h1; rw [depth] at hlen; simp [h1] at hlen
  rw [rootOf_up H l h1] at h
  have hd := depth_up H l h1
  by_cases he : ps.length = depth (up H l).length
  · rcases fold_eq_depth H (up H l) (up_ne_nil H l h1) c ps i he hi h with
      hc | hz | hz | ⟨hu, hb, -⟩
    · exact Or.inl hc
    · exact Or.inr (Or.inl hz)
    · exact Or.inr (Or.inr (Or.inl hz))
    · rw [getD_up H l i hu] at hb
      exact Or.inr (Or.inr (Or.inr ⟨_, _, hb⟩))
  · exact fold_short (up H l) c ps i (by omega) hi h
termination_by l.length
decreasing_by exact length_up_lt H l h1

lemma fold_append : ∀ (c : Node) (ps qs : List Node) (i : Nat),
    fold H c (ps ++ qs) i = fold H (fold H c ps i) qs (i / 2 ^ ps.length)
  | c, [], qs, i => by simp [fold]
  | c, s :: ps, qs, i => by
    simp only [List.cons_append, fold, List.length_cons]
    rw [fold_append (step H c s i) ps qs (i / 2), Nat.div_div_eq_div_mul, Nat.pow_succ,
      Nat.mul_comm]

lemma fold_inner : ∀ (c : Node) (ps : List Node) (i : Nat), (∃ a b, c = innerN H a b) →
    ∃ a b, fold H c ps i = innerN H a b
  | c, [], _, h => h
  | c, s :: ps, i, _ => fold_inner (step H c s i) ps (i / 2)
      (by unfold step; split <;> exact ⟨_, _, rfl⟩)

/-- A path longer than the depth of a tree over leaf hashes: `H` has a collision or a zero
output. -/
lemma fold_long (l : List Node) (hl : l ≠ []) (hleaf : ∀ a ∈ l, ∃ x, a = leafN H x) (c : Node)
    (ps : List Node) (i : Nat) (hlen : depth l.length < ps.length) (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H c ps i) = bytesOf (rootOf H l)) :
    Collision H ∨ ZeroHash H := by
  set k := ps.length - depth l.length with hk
  have hsplit : ps = ps.take k ++ ps.drop k := (List.take_append_drop k ps).symm
  rw [hsplit, fold_append] at h
  have htk : (ps.take k).length = k := by simp; omega
  rw [htk] at h
  obtain ⟨a, b, hab⟩ : ∃ a b, fold H c (ps.take k) i = innerN H a b := by
    obtain ⟨s, rest, hsr⟩ : ∃ s rest, ps.take k = s :: rest := by
      cases hc : ps.take k with
      | nil => rw [hc] at htk; simp at htk; omega
      | cons s rest => exact ⟨s, rest, rfl⟩
    rw [hsr]; simp only [fold]
    exact fold_inner H _ rest _ (by unfold step; split <;> exact ⟨_, _, rfl⟩)
  rw [hab] at h
  have hdl : (ps.drop k).length = depth l.length := by simp; omega
  have hi' : i / 2 ^ k < 2 ^ (ps.drop k).length := by
    rw [hdl, Nat.div_lt_iff_lt_mul (by positivity), ← Nat.pow_add]
    have : depth l.length + k = ps.length := by omega
    rw [this]; exact hi
  rcases fold_eq_depth H l hl _ _ _ hdl hi' h with hc | hz | hz | ⟨hj, hb, -⟩
  · exact Or.inl hc
  · exact Or.inr hz
  · exact Or.inr (zeroHash_of_isHash H _ (isHash_innerN H a b) hz)
  · rw [List.getD_eq_getElem _ _ hj] at hb
    obtain ⟨x, hx⟩ := hleaf _ (List.getElem_mem hj)
    rw [hx] at hb
    exact Or.inl (leaf_inner H x a b hb.symm)

/-- Hashing `leaf_hash(x)` up a path of any length with index `i` to the root of the tree over the
leaf hashes of `ys`: the path has the depth of the tree, `i < ys.len()`, `x = ys[i]` and the path
has the bytes of the honest one, or `H` has a collision or a zero output. -/
lemma trusted_opening (ys : List (List U8)) (hy : ys ≠ []) (x : List U8) (ps : List Node) (i : Nat)
    (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H (leafN H x) ps i) = bytesOf (rootOf H (ys.map (leafN H)))) :
    Collision H ∨ ZeroHash H ∨
      (ps.length = depth ys.length ∧ i < ys.length ∧ x = ys.getD i [] ∧
        ps.map bytesOf = (pathOf H (ys.map (leafN H)) i).map bytesOf) := by
  have hl : ys.map (leafN H) ≠ [] := by simpa using hy
  have hleaf : ∀ a ∈ ys.map (leafN H), ∃ x, a = leafN H x := by
    intro a ha; obtain ⟨y, -, rfl⟩ := List.mem_map.mp ha; exact ⟨y, rfl⟩
  have hml : (ys.map (leafN H)).length = ys.length := List.length_map _
  rcases Nat.lt_trichotomy ps.length (depth ys.length) with hlt | heq | hgt
  · rw [← hml] at hlt
    rcases fold_short H _ _ ps i hlt hi h with hc | hz | hz | ⟨a, b, hb⟩
    · exact Or.inl hc
    · exact Or.inr (Or.inl hz)
    · exact Or.inr (Or.inl ⟨_, hz⟩)
    · exact Or.inl (leaf_inner H x a b hb)
  · rw [← hml] at heq
    rcases fold_eq_depth H _ hl _ ps i heq hi h with hc | hz | hz | ⟨hj, hb, hp⟩
    · exact Or.inl hc
    · exact Or.inr (Or.inl hz)
    · exact Or.inr (Or.inl ⟨_, hz⟩)
    · rw [hml] at hj heq
      rw [List.getD_eq_getElem _ _ (by rw [hml]; exact hj), List.getElem_map] at hb
      rcases leafN_bytes_inj H _ _ hb with hx | hc
      · right; right
        exact ⟨heq, hj, by rw [hx, List.getD_eq_getElem _ _ hj], hp⟩
      · exact Or.inl hc
  · rw [← hml] at hgt
    rcases fold_long H _ hl hleaf _ ps i hgt hi h with hc | hz
    · exact Or.inl hc
    · exact Or.inr (Or.inl hz)

/-- On the honest path of any leaf but the last, some left child has a sibling that is a hash. -/
lemma right_most (l : List Node) (hl : ∀ a ∈ l, IsHash H a) (i : Nat) (hi : i + 1 < l.length) :
    ∃ k < (pathOf H l i).length, (i / 2 ^ k) % 2 = 0 ∧ IsHash H ((pathOf H l i).getD k .Empty) := by
  have h1 : ¬ l.length ≤ 1 := by omega
  rw [pathOf_up H l i h1]
  by_cases he : i % 2 = 0
  · refine ⟨0, by simp, by simpa using he, ?_⟩
    simp only [he, ite_true, List.getD_cons_zero]
    rw [List.getD_eq_getElem _ _ hi]
    exact hl _ (List.getElem_mem hi)
  · have hlu := length_up H l
    obtain ⟨k, hk, hev, hh⟩ :=
      right_most (up H l) (isHash_up H l) (i / 2) (by rw [hlu]; omega)
    refine ⟨k + 1, by simp; omega, ?_, by simpa using hh⟩
    rw [Nat.pow_succ, Nat.mul_comm, ← Nat.div_div_eq_div_mul]; exact hev
termination_by l.length
decreasing_by exact length_up_lt H l h1

end MerkleProofs
