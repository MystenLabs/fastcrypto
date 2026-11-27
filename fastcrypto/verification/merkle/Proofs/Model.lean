-- THIS FILE IS AI-ONLY
import merkle.Proofs.Hash

/-!
A model of `MerkleTree` as lists, and the two facts about it that the theorems on the generated
code rest on:

* `fold_pathOf`: hashing a leaf up the path that `pathOf` reads from the tree gives the root.
* `fold_binding`: two paths of the same length from different nodes to the same root give a
  collision of `H`.

The tree over the level `l` (the leaf hashes first): if `l` has more than one node, it is padded
with `Empty` to even length (`pad`), and the next level holds the hashes of consecutive pairs
(`parents`). `levels` lists the padded levels; `MerkleTree::nodes` is their concatenation.
-/

open Aeneas Aeneas.Std
open fastcrypto

namespace MerkleProofs

abbrev Node := merkle.Node

/-- The number of levels above the leaves of a tree with `n` leaves. The theorems state this as
`Nat.clog 2 n` (`depth_eq_clog`). -/
def depth (n : Nat) : Nat := if n ≤ 1 then 0 else depth ((n + n % 2) / 2) + 1
termination_by n
decreasing_by omega

instance : Inhabited Node := ⟨.Empty⟩

variable (H : List U8 → Array U8 32#usize)

/-- A level padded to even length. -/
def pad (l : List Node) : List Node := if l.length % 2 = 1 then l ++ [.Empty] else l

/-- The hashes of consecutive pairs. -/
def parents : List Node → List Node
  | a :: b :: r => innerN H a b :: parents r
  | _ => []

lemma length_pad (l : List Node) : (pad l).length = l.length + l.length % 2 := by
  unfold pad; split <;> simp <;> omega

lemma getElem_pad (l : List Node) (i : Nat) (h : i < l.length) :
    (pad l)[i]'(by rw [length_pad]; omega) = l[i] := by
  unfold pad; split <;> simp [List.getElem_append_left h]

lemma length_parents : ∀ l : List Node, (parents H l).length = l.length / 2
  | a :: b :: r => by simp [parents, length_parents r]; omega
  | [] => rfl
  | [_] => by simp [parents]

lemma getElem_parents : ∀ (l : List Node) (j : Nat) (h : j < l.length / 2),
    (parents H l)[j]'(by rw [length_parents]; exact h) =
      innerN H (l[2 * j]'(by omega)) (l[2 * j + 1]'(by omega))
  | a :: b :: r, 0, _ => by simp [parents]
  | a :: b :: r, j + 1, h => by
    simp only [parents, List.getElem_cons_succ]
    rw [getElem_parents r j (by simp at h; omega)]
    congr 1
  | [], _, h => by simp at h
  | [_], _, h => by simp at h

/-- The level above `l`. -/
def up (l : List Node) : List Node := parents H (pad l)

lemma length_up (l : List Node) : (up H l).length = (l.length + l.length % 2) / 2 := by
  simp [up, length_parents, length_pad]

lemma length_up_lt (l : List Node) (h : ¬ l.length ≤ 1) : (up H l).length < l.length := by
  rw [length_up]; omega

/-- The padded levels of the tree over `l`, from the leaves up. The last one is the root alone,
or empty if `l` is. -/
def levels (l : List Node) : List (List Node) :=
  if _h : l.length ≤ 1 then [l] else pad l :: levels (up H l)
termination_by l.length
decreasing_by exact length_up_lt H l _h

/-- The root of the tree over `l`. -/
def rootOf (l : List Node) : Node :=
  if _h : l.length ≤ 1 then l.headD .Empty else rootOf (up H l)
termination_by l.length
decreasing_by exact length_up_lt H l _h

/-- The siblings on the path from the `i`th node of `l` to the root. -/
def pathOf (l : List Node) (i : Nat) : List Node :=
  if h : l.length ≤ 1 then []
  else (pad l).getD (if i % 2 = 0 then i + 1 else i - 1) .Empty :: pathOf (up H l) (i / 2)
termination_by l.length
decreasing_by exact length_up_lt H l h

/-- One step up: `c` with its sibling `s`, where `i` is the index of `c` on its level. -/
def step (c s : Node) (i : Nat) : Node := if i % 2 = 0 then innerN H c s else innerN H s c

/-- Hashing `c`, the node at index `i`, up `path`. -/
def fold : Node → List Node → Nat → Node
  | c, [], _ => c
  | c, s :: ps, i => fold (step H c s i) ps (i / 2)

lemma fold_pathOf (l : List Node) (i : Nat) (hi : i < l.length) :
    fold H l[i] (pathOf H l i) i = rootOf H l := by
  rw [pathOf, rootOf]
  split
  · rename_i h
    obtain ⟨a, rfl⟩ : ∃ a, l = [a] := by
      match l, h with
      | [a], _ => exact ⟨a, rfl⟩
      | [], _ => simp at hi
    simp at hi; subst hi; rfl
  · rename_i h
    simp only [fold]
    have hp := length_pad l
    have hu : i / 2 < (up H l).length := by rw [length_up]; omega
    have hstep : step H l[i] ((pad l).getD (if i % 2 = 0 then i + 1 else i - 1) .Empty) i =
        (up H l)[i / 2] := by
      simp only [up]
      rw [getElem_parents H (pad l) (i / 2) (by rw [hp]; omega)]
      unfold step
      split
      · rename_i he
        have h1 : 2 * (i / 2) = i := by omega
        have h2 : i + 1 < (pad l).length := by omega
        simp only [List.getD_eq_getElem _ _ h2]
        congr 1
        · simp only [h1]; exact (getElem_pad l i hi).symm
        · congr 1; omega
      · rename_i he
        have h1 : 2 * (i / 2) + 1 = i := by omega
        have h2 : i - 1 < (pad l).length := by omega
        simp only [List.getD_eq_getElem _ _ h2]
        congr 1
        · congr 1; omega
        · simp only [h1]; exact (getElem_pad l i hi).symm
    rw [hstep]
    exact fold_pathOf (up H l) (i / 2) hu
termination_by l.length
decreasing_by apply length_up_lt; assumption

lemma length_pathOf (l : List Node) (i : Nat) : (pathOf H l i).length = depth l.length := by
  rw [pathOf, depth]
  split
  · simp_all
  · rename_i h
    rw [List.length_cons, length_pathOf (up H l) (i / 2), length_up]
termination_by l.length
decreasing_by apply length_up_lt; assumption

lemma lt_two_pow_depth (n : Nat) : n ≤ 2 ^ depth n := by
  rw [depth]
  split
  · simp; omega
  · have := lt_two_pow_depth ((n + n % 2) / 2)
    rw [Nat.pow_succ]; omega
termination_by n
decreasing_by omega

lemma depth_le (n k : Nat) (h : n ≤ 2 ^ k) : depth n ≤ k := by
  rw [depth]
  split
  · omega
  · cases k with
    | zero => simp at h; omega
    | succ k =>
      have := depth_le ((n + n % 2) / 2) k (by rw [Nat.pow_succ] at h; omega)
      omega
termination_by n
decreasing_by omega

lemma depth_eq_clog (n : Nat) : depth n = Nat.clog 2 n :=
  le_antisymm (depth_le n _ (Nat.le_pow_clog (by norm_num) n))
    (Nat.clog_le_of_le_pow (lt_two_pow_depth n))

/-- The nodes of `MerkleTree` hold at most `4 n` nodes for `n` leaves. -/
lemma length_flatten_levels (l : List Node) :
    (levels H l).flatten.length ≤ 4 * l.length := by
  rw [levels]
  split
  · simp; omega
  · rename_i h
    simp only [List.flatten_cons, List.length_append, length_pad]
    have := length_flatten_levels (up H l)
    rw [length_up] at this
    omega
termination_by l.length
decreasing_by apply length_up_lt; assumption

lemma getLast_flatten_levels (l : List Node) (hl : l ≠ []) :
    ∃ h, (levels H l).flatten.getLast h = rootOf H l := by
  rw [levels, rootOf]
  split
  · rename_i h
    obtain ⟨a, rfl⟩ : ∃ a, l = [a] := by
      match l, h with
      | [a], _ => exact ⟨a, rfl⟩
      | [], _ => exact absurd rfl hl
    simp
  · rename_i h
    have hu : up H l ≠ [] := by
      intro he; have := congrArg List.length he; rw [length_up] at this; simp at this; omega
    obtain ⟨h', e⟩ := getLast_flatten_levels (up H l) hu
    refine ⟨by simp [h'] , ?_⟩
    simp only [List.flatten_cons]
    rw [List.getLast_append_of_ne_nil _ h', e]
termination_by l.length
decreasing_by apply length_up_lt; assumption

/-! ## Binding -/

/-- The nodes that hashing produces. -/
def IsDigest : Node → Prop
  | .Digest _ => True
  | .Empty => False

lemma isDigest_step (c s : Node) (i : Nat) : IsDigest (step H c s i) := by
  unfold step innerN; split <;> trivial

lemma eq_of_bytesOf (c c' : Node) (hc : IsDigest c) (hc' : IsDigest c')
    (h : bytesOf c = bytesOf c') : c = c' := by
  cases c with
  | Empty => exact absurd hc id
  | Digest v =>
    cases c' with
    | Empty => exact absurd hc' id
    | Digest v' => simp only [bytesOf] at h; exact congrArg merkle.Node.Digest ((Aeneas.Std.Array.eq_iff _ _).mpr h)

lemma innerN_inj (a b a' b' : Node) (h : innerN H a b = innerN H a' b') :
    (bytesOf a = bytesOf a' ∧ bytesOf b = bytesOf b') ∨ Collision H := by
  simp only [innerN, merkle.Node.Digest.injEq] at h
  by_cases hx : (1#u8 :: (bytesOf a ++ bytesOf b)) = (1#u8 :: (bytesOf a' ++ bytesOf b'))
  · left
    simp only [List.cons.injEq, true_and] at hx
    exact List.append_inj hx (by rw [bytesOf_length, bytesOf_length])
  · exact Or.inr ⟨_, _, hx, h⟩

lemma step_inj (c s c' s' : Node) (i : Nat) (hc : IsDigest c) (hc' : IsDigest c')
    (h : step H c s i = step H c' s' i) : c = c' ∨ Collision H := by
  unfold step at h
  split at h
  · rcases innerN_inj H _ _ _ _ h with ⟨h1, _⟩ | h
    · exact Or.inl (eq_of_bytesOf c c' hc hc' h1)
    · exact Or.inr h
  · rcases innerN_inj H _ _ _ _ h with ⟨_, h1⟩ | h
    · exact Or.inl (eq_of_bytesOf c c' hc hc' h1)
    · exact Or.inr h

/-- Hashing two nodes up paths of the same length to the same root: the nodes are equal or `H`
has a collision. -/
lemma fold_binding : ∀ (ps ps' : List Node) (c c' : Node) (i : Nat),
    ps.length = ps'.length → IsDigest c → IsDigest c' →
    fold H c ps i = fold H c' ps' i → c = c' ∨ Collision H
  | [], [], c, c', i, _, _, _, h => Or.inl h
  | s :: ps, s' :: ps', c, c', i, hl, hc, hc', h => by
    simp only [fold] at h
    rcases fold_binding ps ps' _ _ (i / 2) (by simpa using hl) (isDigest_step H _ _ _)
      (isDigest_step H _ _ _) h with h | h
    · exact step_inj H c s c' s' i hc hc' h
    · exact Or.inr h
  | [], _ :: _, _, _, _, hl, _, _, _ => by simp at hl
  | _ :: _, [], _, _, _, hl, _, _, _ => by simp at hl

lemma leafN_inj (l l' : List U8) (h : leafN H l = leafN H l') : l = l' ∨ Collision H := by
  simp only [leafN, merkle.Node.Digest.injEq] at h
  by_cases hx : (0#u8 :: l) = (0#u8 :: l')
  · exact Or.inl (by simpa using hx)
  · exact Or.inr ⟨_, _, hx, h⟩

/-! ## Slice iterators -/

/-- `next` on a slice iterator yields the element at its index and advances, while the index is
in bounds. -/
@[step]
lemma slice_iter_next_spec {α : Type _} [Inhabited α] (it : core.slice.iter.Iter α) :
    core.slice.iter.IteratorSliceIter.next it ⦃ o it' =>
      (if it.i < it.slice.length then o = some it.slice.val[it.i]! ∧ it'.i = it.i + 1
       else o = none ∧ it'.i = it.i) ∧ it'.slice = it.slice ⦄ := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · rename_i h
    have h' : it.i < it.slice.length := by scalar_tac
    simp [h']
    rfl
  · rename_i h
    have h' : ¬ it.i < it.slice.length := by scalar_tac
    simp [h']

end MerkleProofs
