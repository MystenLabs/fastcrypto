-- THIS FILE IS AI-ONLY
import merkle.Proofs.Model

/-!
What a path of any length can open to in a tree built by `MerkleTree`, the fact that
`MerkleProof::verify_for_trusted_tree` and the non-inclusion proofs rest on:

* `trusted_opening`: if hashing `leaf_hash(x)` up a path `ps` with index `i` gives the root of the
  tree over the leaf hashes of `ys`, then `ps` has the depth of the tree, `i < ys.len()`,
  `x = ys[i]` and `ps` has the bytes of the honest path, or `H` has a collision or hashes to 32
  zero bytes, the bytes of `Node::Empty`, among the inputs of the path, the leaves and the tree.
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
    (bytesOf a = bytesOf a' ∧ bytesOf b = bytesOf b') ∨
      CollisionIn H [innerInput a b, innerInput a' b'] :=
  innerN_inj H a b a' b' (congrArg merkle.Node.Digest (digest_eq H h))

lemma leafN_bytes_inj (x y : List U8) (h : bytesOf (leafN H x) = bytesOf (leafN H y)) :
    x = y ∨ CollisionIn H [leafInput x, leafInput y] :=
  leafN_inj H x y (congrArg merkle.Node.Digest (digest_eq H h))

lemma leaf_inner (x : List U8) (a b : Node) (h : bytesOf (leafN H x) = bytesOf (innerN H a b)) :
    CollisionIn H [leafInput x, innerInput a b] :=
  collisionIn_pair (by simp) (by simp) (by simp [leafInput, innerInput]) (digest_eq H h)

/-- A node that is the hash of `x`, with the bytes of `Empty`, makes `x` a zero output. -/
lemma zeroHashIn_of (x : List U8) {xs : List (List U8)} (hx : x ∈ xs)
    (h : bytesOf (.Digest (H x)) = bytesOf .Empty) : ZeroHashIn H xs := ⟨x, hx, h⟩

lemma isHash_innerN (a b : Node) : IsHash H (innerN H a b) := ⟨_, rfl⟩

lemma isHash_leafN (x : List U8) : IsHash H (leafN H x) := ⟨_, rfl⟩

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

/-- A node that is the hash of one of the inputs `xs`. -/
def IsHashIn (xs : List (List U8)) (a : Node) : Prop := ∃ x ∈ xs, a = .Digest (H x)

lemma zeroHashIn_of_hashIn {xs : List (List U8)} {a : Node} (ha : IsHashIn H xs a)
    (h : bytesOf a = bytesOf .Empty) : ZeroHashIn H xs := by
  obtain ⟨x, hx, rfl⟩ := ha; exact ⟨x, hx, h⟩

lemma hashIn_up (l : List Node) {xs : List (List U8)} (hT : ∀ x ∈ treeInputs H l, x ∈ xs)
    (h1 : ¬ l.length ≤ 1) : ∀ a ∈ up H l, IsHashIn H xs a := by
  intro a ha
  rw [up_eq, List.mem_map] at ha
  obtain ⟨x, hx, rfl⟩ := ha
  exact ⟨x, hT x (by rw [treeInputs_up H l h1]; exact List.mem_append_left _ hx), rfl⟩

lemma treeInputs_up_sub (l : List Node) {xs : List (List U8)} (hT : ∀ x ∈ treeInputs H l, x ∈ xs)
    (h1 : ¬ l.length ≤ 1) : ∀ x ∈ treeInputs H (up H l), x ∈ xs := fun x hx =>
  hT x (by rw [treeInputs_up H l h1]; exact List.mem_append_right _ hx)

/-- The root of the tree over nodes that are hashes of inputs `xs` is the hash of one of `xs`,
when `xs` also has the inputs of the tree. -/
lemma rootOf_hashIn (l : List Node) (hl : l ≠ []) {xs : List (List U8)}
    (h : ∀ a ∈ l, IsHashIn H xs a) (hT : ∀ x ∈ treeInputs H l, x ∈ xs) :
    IsHashIn H xs (rootOf H l) := by
  by_cases h1 : l.length ≤ 1
  · rw [rootOf]
    rw [dite_eq_left h1]
    obtain ⟨a, rfl⟩ : ∃ a, l = [a] := by
      match l, h1 with
      | [a], _ => exact ⟨a, rfl⟩
      | [], _ => exact absurd rfl hl
    exact h a (by simp)
  · rw [rootOf_up H l h1]
    exact rootOf_hashIn (up H l) (up_ne_nil H l h1) (hashIn_up H l hT h1)
      (treeInputs_up_sub H l hT h1)
termination_by l.length
decreasing_by exact length_up_lt H l h1

/-- A path of the depth of the tree from `c` with index `i` to the root: `i` is a leaf, `c` and the
path have the bytes of that leaf and its honest path, or `c` has the bytes of an `Empty` leaf, or
`H` has a collision or a zero output among the inputs of the path and the tree. -/
lemma fold_eq_depth (l : List Node) (hl : l ≠ []) (c : Node) (ps : List Node) (i : Nat)
    (hlen : ps.length = depth l.length) (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H c ps i) = bytesOf (rootOf H l)) :
    CollisionIn H (pathInputs H c ps i ++ treeInputs H l) ∨
      ZeroHashIn H (pathInputs H c ps i ++ treeInputs H l) ∨ bytesOf c = bytesOf .Empty ∨
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
      rw [pathInputs_cons, treeInputs_up H l h1]
      have hsub : ∀ x ∈ pathInputs H (step H c s i) ps (i / 2) ++ treeInputs H (up H l),
          x ∈ stepInput c s i :: pathInputs H (step H c s i) ps (i / 2) ++
            (levelInputs l ++ treeInputs H (up H l)) := by
        intro x hx; simp at hx ⊢; tauto
      have hlen' : ps.length = depth (up H l).length := by simp at hlen; omega
      have hi' : i / 2 < 2 ^ ps.length := by
        simp only [List.length_cons, Nat.pow_succ] at hi; omega
      rcases fold_eq_depth (up H l) (up_ne_nil H l h1) (step H c s i) ps (i / 2) hlen' hi' h with
        hc | hz | hz | ⟨hu, hb, hp⟩
      · exact Or.inl (hc.mono hsub)
      · exact Or.inr (Or.inl (hz.mono hsub))
      · right; left
        rw [step_eq] at hz
        exact zeroHashIn_of H _ (by simp) hz
      · have hmem := innerInput_mem_levelInputs H l (i / 2) hu
        rw [getD_up H l (i / 2) hu] at hb
        have hlu := length_up H l
        have hil : i < l.length + l.length % 2 := by omega
        have hst := step_eq H c s i
        unfold step at hb
        unfold stepInput at hst
        split at hb
        · rename_i he
          simp only [he, if_true] at hst
          have e1 : 2 * (i / 2) = i := by omega
          rw [e1] at hb hmem
          rcases innerN_bytes_inj H _ _ _ _ hb with ⟨hc1, hs1⟩ | hcol
          · by_cases hil' : i < l.length
            · right; right; right
              refine ⟨hil', hc1, ?_⟩
              rw [pathOf_up H l i h1]
              simp only [List.map_cons, he, ite_true, hs1, hp]
            · right; right; left
              rw [hc1, List.getD_eq_default _ _ (by omega)]
          · left
            refine hcol.mono ?_
            intro x hx
            simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx
            rcases hx with rfl | rfl
            · simp [stepInput, he]
            · exact List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inl hmem)))
        · rename_i he
          simp only [he, if_false] at hst
          have e1 : 2 * (i / 2) + 1 = i := by omega
          have e2 : 2 * (i / 2) = i - 1 := by omega
          rw [e1, e2] at hb hmem
          rcases innerN_bytes_inj H _ _ _ _ hb with ⟨hs1, hc1⟩ | hcol
          · by_cases hil' : i < l.length
            · right; right; right
              refine ⟨hil', hc1, ?_⟩
              rw [pathOf_up H l i h1]
              simp only [List.map_cons, he, ite_false, hs1, hp]
            · right; right; left
              rw [hc1, List.getD_eq_default _ _ (by omega)]
          · left
            refine hcol.mono ?_
            intro x hx
            simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx
            rcases hx with rfl | rfl
            · simp [stepInput, he]
            · exact List.mem_append.mpr (Or.inr (List.mem_append.mpr (Or.inl hmem)))
termination_by l.length
decreasing_by exact length_up_lt H l h1

/-- A path shorter than the depth of the tree: `c` has the bytes of an inner node of the tree or of
`Empty`, or `H` has a collision or a zero output among the inputs of the path and the tree. -/
lemma fold_short (l : List Node) (c : Node) (ps : List Node) (i : Nat)
    (hlen : ps.length < depth l.length) (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H c ps i) = bytesOf (rootOf H l)) :
    CollisionIn H (pathInputs H c ps i ++ treeInputs H l) ∨
      ZeroHashIn H (pathInputs H c ps i ++ treeInputs H l) ∨ bytesOf c = bytesOf .Empty ∨
      ∃ a b, innerInput a b ∈ treeInputs H l ∧ bytesOf c = bytesOf (innerN H a b) := by
  have h1 : ¬ l.length ≤ 1 := by
    intro h1; rw [depth] at hlen; simp [h1] at hlen
  rw [rootOf_up H l h1] at h
  have hd := depth_up H l h1
  have ht := treeInputs_up H l h1
  have hsub : ∀ x ∈ pathInputs H c ps i ++ treeInputs H (up H l),
      x ∈ pathInputs H c ps i ++ treeInputs H l := by
    intro x hx; rw [ht]; simp at hx ⊢; tauto
  by_cases he : ps.length = depth (up H l).length
  · rcases fold_eq_depth H (up H l) (up_ne_nil H l h1) c ps i he hi h with
      hc | hz | hz | ⟨hu, hb, -⟩
    · exact Or.inl (hc.mono hsub)
    · exact Or.inr (Or.inl (hz.mono hsub))
    · exact Or.inr (Or.inr (Or.inl hz))
    · have hmem := innerInput_mem_levelInputs H l i hu
      rw [getD_up H l i hu] at hb
      exact Or.inr (Or.inr (Or.inr ⟨_, _, by rw [ht]; exact List.mem_append.mpr (Or.inl hmem), hb⟩))
  · rcases fold_short (up H l) c ps i (by omega) hi h with hc | hz | hz | ⟨a, b, hab, hb⟩
    · exact Or.inl (hc.mono hsub)
    · exact Or.inr (Or.inl (hz.mono hsub))
    · exact Or.inr (Or.inr (Or.inl hz))
    · exact Or.inr (Or.inr (Or.inr ⟨a, b, by rw [ht]; exact List.mem_append.mpr (Or.inr hab), hb⟩))
termination_by l.length
decreasing_by exact length_up_lt H l h1

lemma fold_append : ∀ (c : Node) (ps qs : List Node) (i : Nat),
    fold H c (ps ++ qs) i = fold H (fold H c ps i) qs (i / 2 ^ ps.length)
  | c, [], qs, i => by simp [fold]
  | c, s :: ps, qs, i => by
    simp only [List.cons_append, fold, List.length_cons]
    rw [fold_append (step H c s i) ps qs (i / 2), Nat.div_div_eq_div_mul, Nat.pow_succ,
      Nat.mul_comm]

lemma pathInputs_append : ∀ (c : Node) (ps qs : List Node) (i : Nat),
    pathInputs H c (ps ++ qs) i =
      pathInputs H c ps i ++ pathInputs H (fold H c ps i) qs (i / 2 ^ ps.length)
  | c, [], qs, i => by simp [fold, pathInputs]
  | c, s :: ps, qs, i => by
    simp only [List.cons_append, fold, List.length_cons]
    rw [pathInputs_cons, pathInputs_cons, pathInputs_append (step H c s i) ps qs (i / 2),
      Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm]
    rfl

/-- Hashing up a nonempty path ends at an inner node whose input is hashed on the way. -/
lemma fold_inner : ∀ (c : Node) (ps : List Node) (i : Nat), ps ≠ [] →
    ∃ a b, innerInput a b ∈ pathInputs H c ps i ∧ fold H c ps i = innerN H a b
  | _, [], _, h => absurd rfl h
  | c, [s], i, _ => by
    rw [pathInputs_cons]
    simp only [fold, pathInputs, List.mem_singleton]
    unfold step stepInput
    split
    · exact ⟨c, s, rfl, rfl⟩
    · exact ⟨s, c, rfl, rfl⟩
  | c, s :: s' :: ps, i, _ => by
    obtain ⟨a, b, hm, hf⟩ := fold_inner (step H c s i) (s' :: ps) (i / 2) (by simp)
    refine ⟨a, b, ?_, by simpa [fold] using hf⟩
    rw [pathInputs_cons]; exact List.mem_cons_of_mem _ hm

/-- A path longer than the depth of the tree over the leaf hashes of `ys`: `H` has a collision or a
zero output among the inputs of the path, the leaves and the tree. -/
lemma fold_long (ys : List (List U8)) (hy : ys ≠ []) (c : Node)
    (ps : List Node) (i : Nat) (hlen : depth ys.length < ps.length) (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H c ps i) = bytesOf (rootOf H (ys.map (leafN H)))) :
    CollisionIn H (pathInputs H c ps i ++ ys.map leafInput ++ treeInputs H (ys.map (leafN H))) ∨
      ZeroHashIn H (pathInputs H c ps i ++ ys.map leafInput ++ treeInputs H (ys.map (leafN H))) := by
  set l := ys.map (leafN H) with hl
  have hl0 : l ≠ [] := by simpa [hl] using hy
  have hml : l.length = ys.length := List.length_map _
  rw [← hml] at hlen
  set k := ps.length - depth l.length with hk
  have hsplit : ps = ps.take k ++ ps.drop k := (List.take_append_drop k ps).symm
  have hpi := pathInputs_append H c (ps.take k) (ps.drop k) i
  rw [← hsplit] at hpi
  rw [hsplit, fold_append] at h
  have htk : (ps.take k).length = k := by simp; omega
  rw [htk] at h hpi
  obtain ⟨a, b, hmab, hab⟩ := fold_inner H c (ps.take k) i (by
    intro he; rw [he] at htk; simp at htk; omega)
  rw [hab] at h
  simp only [hab] at hpi
  have hdl : (ps.drop k).length = depth l.length := by simp; omega
  have hi' : i / 2 ^ k < 2 ^ (ps.drop k).length := by
    rw [hdl, Nat.div_lt_iff_lt_mul (by positivity), ← Nat.pow_add]
    have : depth l.length + k = ps.length := by omega
    rw [this]; exact hi
  have hsub : ∀ x ∈ pathInputs H (innerN H a b) (ps.drop k) (i / 2 ^ k) ++ treeInputs H l,
      x ∈ pathInputs H c ps i ++ ys.map leafInput ++ treeInputs H l := by
    intro x hx; rw [hpi]; simp at hx ⊢; tauto
  have hmab' : innerInput a b ∈ pathInputs H c ps i ++ ys.map leafInput ++ treeInputs H l := by
    rw [hpi]; simp [hmab]
  rcases fold_eq_depth H l hl0 _ _ _ hdl hi' h with hc | hz | hz | ⟨hj, hb, -⟩
  · exact Or.inl (hc.mono hsub)
  · exact Or.inr (hz.mono hsub)
  · exact Or.inr (zeroHashIn_of H _ hmab' hz)
  · rw [List.getD_eq_getElem _ _ hj] at hb
    have hlj : l[i / 2 ^ k]'hj = leafN H (ys[i / 2 ^ k]'(by rw [← hml]; exact hj)) := by
      simp only [hl, List.getElem_map]
    rw [hlj] at hb
    left
    refine (leaf_inner H _ a b hb.symm).mono ?_
    intro x hx
    simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx
    rcases hx with rfl | rfl
    · simp only [List.mem_append, List.mem_map]
      exact Or.inl (Or.inr ⟨_, List.getElem_mem _, rfl⟩)
    · exact hmab'

/-- Hashing `leaf_hash(x)` up a path of any length with index `i` to the root of the tree over the
leaf hashes of `ys`: the path has the depth of the tree, `i < ys.len()`, `x = ys[i]` and the path
has the bytes of the honest one, or `H` has a collision or a zero output among the inputs of the
path, the leaves and the tree. -/
lemma trusted_opening (ys : List (List U8)) (hy : ys ≠ []) (x : List U8) (ps : List Node) (i : Nat)
    (hi : i < 2 ^ ps.length)
    (h : bytesOf (fold H (leafN H x) ps i) = bytesOf (rootOf H (ys.map (leafN H)))) :
    CollisionIn H (verifyInputs H x ps i ++ ys.map leafInput ++ treeInputs H (ys.map (leafN H))) ∨
      ZeroHashIn H (verifyInputs H x ps i ++ ys.map leafInput ++
        treeInputs H (ys.map (leafN H))) ∨
      (ps.length = depth ys.length ∧ i < ys.length ∧ x = ys.getD i [] ∧
        ps.map bytesOf = (pathOf H (ys.map (leafN H)) i).map bytesOf) := by
  have hl : ys.map (leafN H) ≠ [] := by simpa using hy
  have hml : (ys.map (leafN H)).length = ys.length := List.length_map _
  have hv : verifyInputs H x ps i = leafInput x :: pathInputs H (leafN H x) ps i := rfl
  have hx : leafInput x ∈ verifyInputs H x ps i ++ ys.map leafInput ++
      treeInputs H (ys.map (leafN H)) := by rw [hv]; simp
  have hsub : ∀ z ∈ pathInputs H (leafN H x) ps i ++ treeInputs H (ys.map (leafN H)),
      z ∈ verifyInputs H x ps i ++ ys.map leafInput ++ treeInputs H (ys.map (leafN H)) := by
    intro z hz; rw [hv]; simp at hz ⊢; tauto
  rcases Nat.lt_trichotomy ps.length (depth ys.length) with hlt | heq | hgt
  · rw [← hml] at hlt
    rcases fold_short H _ _ ps i hlt hi h with hc | hz | hz | ⟨a, b, hab, hb⟩
    · exact Or.inl (hc.mono hsub)
    · exact Or.inr (Or.inl (hz.mono hsub))
    · exact Or.inr (Or.inl (zeroHashIn_of H _ hx hz))
    · left
      refine (leaf_inner H x a b hb).mono ?_
      intro z hz
      simp only [List.mem_cons, List.mem_nil_iff, or_false] at hz
      rcases hz with rfl | rfl
      · exact hx
      · simp [hab]
  · rw [← hml] at heq
    rcases fold_eq_depth H _ hl _ ps i heq hi h with hc | hz | hz | ⟨hj, hb, hp⟩
    · exact Or.inl (hc.mono hsub)
    · exact Or.inr (Or.inl (hz.mono hsub))
    · exact Or.inr (Or.inl (zeroHashIn_of H _ hx hz))
    · rw [hml] at hj heq
      rw [List.getD_eq_getElem _ _ (by rw [hml]; exact hj), List.getElem_map] at hb
      rcases leafN_bytes_inj H _ _ hb with hxe | hc
      · right; right
        exact ⟨heq, hj, by rw [hxe, List.getD_eq_getElem _ _ hj], hp⟩
      · left
        refine hc.mono ?_
        intro z hz
        simp only [List.mem_cons, List.mem_nil_iff, or_false] at hz
        rcases hz with rfl | rfl
        · exact hx
        · simp only [List.mem_append, List.mem_map]
          exact Or.inl (Or.inr ⟨_, List.getElem_mem _, rfl⟩)
  · rcases fold_long H ys hy _ ps i hgt hi h with hc | hz
    · exact Or.inl (hc.mono (by
        intro z hz; rw [hv]; simp only [List.mem_append, List.mem_cons] at hz ⊢; tauto))
    · exact Or.inr (Or.inl (hz.mono (by
        intro z hz; rw [hv]; simp only [List.mem_append, List.mem_cons] at hz ⊢; tauto)))

/-- On the honest path of any leaf but the last, some left child has a sibling that is a hash of
one of the inputs `xs`, when the nodes are and `xs` has the inputs of the tree. -/
lemma right_most (l : List Node) {xs : List (List U8)} (hl : ∀ a ∈ l, IsHashIn H xs a)
    (hT : ∀ x ∈ treeInputs H l, x ∈ xs) (i : Nat) (hi : i + 1 < l.length) :
    ∃ k < (pathOf H l i).length, (i / 2 ^ k) % 2 = 0 ∧
      IsHashIn H xs ((pathOf H l i).getD k .Empty) := by
  have h1 : ¬ l.length ≤ 1 := by omega
  rw [pathOf_up H l i h1]
  by_cases he : i % 2 = 0
  · refine ⟨0, by simp, by simpa using he, ?_⟩
    simp only [he, ite_true, List.getD_cons_zero]
    rw [List.getD_eq_getElem _ _ hi]
    exact hl _ (List.getElem_mem hi)
  · have hlu := length_up H l
    obtain ⟨k, hk, hev, hh⟩ :=
      right_most (up H l) (hashIn_up H l hT h1) (treeInputs_up_sub H l hT h1) (i / 2)
        (by rw [hlu]; omega)
    refine ⟨k + 1, by simp; omega, ?_, by simpa using hh⟩
    rw [Nat.pow_succ, Nat.mul_comm, ← Nat.div_div_eq_div_mul]; exact hev
termination_by l.length
decreasing_by exact length_up_lt H l h1

end MerkleProofs
