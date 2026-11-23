-- THIS FILE IS AI-ONLY
import merkle.Opening
import merkle.Verify
import merkle.Build
import merkle.Result

/-!
What the generated `MerkleProof::is_right_most`,
`MerkleProof::verify_for_trusted_tree_with_unserialized_leaf` and
`MerkleNonInclusionProof::verify_for_trusted_tree` compute.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

/-! ## `is_right_most` -/

/-- Every left child on the path from index `i` has a sibling with the bytes of `Node::Empty`. -/
def RightMost : List Node → Nat → Prop
  | [], _ => True
  | s :: ps, i => (i % 2 = 0 → bytesOf s = bytesOf .Empty) ∧ RightMost ps (i / 2)

lemma rightMost_getD : ∀ (ps : List Node) (i k : Nat), RightMost ps i → k < ps.length →
    (i / 2 ^ k) % 2 = 0 → bytesOf (ps.getD k .Empty) = bytesOf .Empty
  | [], _, _, _, hk, _ => by simp at hk
  | s :: ps, i, 0, ⟨h, _⟩, _, he => by simpa using h (by simpa using he)
  | s :: ps, i, k + 1, ⟨_, h⟩, hk, he => by
    simp only [List.getD_cons_succ]
    refine rightMost_getD ps (i / 2) k h (by simpa using hk) ?_
    rw [Nat.div_div_eq_div_mul, ← Nat.pow_succ']; exact he

lemma arr_ne (x y : Array U8 32#usize) :
    core.array.equality.PartialEqArray.ne core.cmp.PartialEqU8 x y = ok (decide (x ≠ y)) := by
  simp [core.array.equality.PartialEqArray.ne, arr_eq]

lemma bytes_ne_empty (n : Node) :
    (∃ a, merkle.Node.bytes n = ok a ∧ (a ≠ merkle.EMPTY_NODE ↔ bytesOf n ≠ bytesOf .Empty)) := by
  obtain ⟨a, ha, hv⟩ := bytes_eq n
  refine ⟨a, ha, ?_⟩
  rw [ne_eq, ne_eq, Aeneas.Std.Array.eq_iff, hv]
  simp [bytesOf, merkle.EMPTY_NODE]

lemma is_right_most_loop_spec (p : merkle.MerkleProof T) (li lvl : Usize)
    (hl : lvl.val ≤ p.path.length) :
    merkle.MerkleProof.is_right_most_loop p li lvl ⦃ b =>
      (b = true ↔ RightMost (p.path.val.drop lvl.val) li.val) ⦄ := by
  unfold merkle.MerkleProof.is_right_most_loop
  apply loop.spec_decr_nat (fun q => p.path.length - q.2.val)
    (fun q => q.2.val ≤ p.path.length ∧
      (RightMost (p.path.val.drop q.2.val) q.1.val ↔ RightMost (p.path.val.drop lvl.val) li.val))
  · rintro ⟨li', lvl'⟩ ⟨hl', heq⟩
    dsimp only at hl' heq ⊢
    unfold merkle.MerkleProof.is_right_most_loop.body
    by_cases hlt : lvl' < alloc.vec.Vec.len p.path
    · have hlt' : lvl'.val < p.path.length := by scalar_tac
      rw [List.drop_eq_getElem_cons hlt'] at heq
      simp only [hlt, ite_true]
      step*
      · obtain ⟨a, ha, hne⟩ := bytes_ne_empty n
        simp only [ha, arr_ne, bind_ok]
        split
        · rename_i hb
          simp only [WP.spec_ok, reduceCtorEq, false_iff]
          intro hr
          rw [← heq] at hr
          simp only [decide_eq_true_eq, hne] at hb
          apply hb
          rw [n_post] at *
          exact hr.1 (by scalar_tac)
        · rename_i hb
          step*
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          rw [← heq, level1_post, level_index1_post]
          simp only [decide_eq_true_eq, hne, not_not] at hb
          constructor
          · intro h; exact ⟨fun _ => by rw [← n_post]; exact hb, by simpa using h⟩
          · intro h; simpa using h.2
      · refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [← heq, level1_post, level_index1_post]
        constructor
        · intro h; exact ⟨fun he => by scalar_tac, by simpa using h⟩
        · intro h; simpa using h.2
    · simp only [hlt, ite_false, WP.spec_ok, true_iff]
      rw [← heq, List.drop_of_length_le (by scalar_tac)]
      trivial
  · exact ⟨hl, Iff.rfl⟩

/-- `is_right_most(i)` returns whether every left child on the path from `i` has an `Empty`
sibling. -/
lemma is_right_most_spec (p : merkle.MerkleProof T) (i : Usize) :
    merkle.MerkleProof.is_right_most inst p i ⦃ b => (b = true ↔ RightMost p.path.val i.val) ⦄ := by
  unfold merkle.MerkleProof.is_right_most
  exact is_right_most_loop_spec p i 0#usize (by simp)

/-! ## Leaves serialized with BCS -/

/-- `verify_for_trusted_tree_with_unserialized_leaf(root, l, i)` accepts only if `bcs::to_bytes(l)`
returns bytes that `verify_for_trusted_tree(root, _, i)` accepts. -/
lemma unserialized_ok {L : Type} (ser : serde_core.ser.Serialize L) (p : merkle.MerkleProof T)
    (root : Node) (l : L) (i : Usize)
    (h : merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser p root l i =
      ok (.Ok ())) :
    ∃ v, bcs.ser.to_bytes ser l = ok (.Ok v) ∧
      merkle.MerkleProof.verify_for_trusted_tree inst p root (alloc.vec.Vec.deref v) i =
        ok (.Ok ()) := by
  unfold merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf at h
  obtain ⟨r, hr, h⟩ := bind_eq_ok h
  obtain ⟨r1, hr1, h⟩ := bind_eq_ok h
  cases r with
  | Ok v =>
    simp only [core.result.Result.map_err, Result.ok_injective.eq_iff] at hr1
    subst hr1
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok] at h
    exact ⟨v, hr, h⟩
  | Err e =>
    simp only [core.result.Result.map_err] at hr1
    obtain ⟨m, -, hr1⟩ := bind_eq_ok hr1
    simp only [Result.ok_injective.eq_iff] at hr1
    subst hr1
    simp [core.result.Result.Insts.CoreOpsTry.branch, from_residual_eq] at h

/-! ## `MerkleNonInclusionProof::verify_for_trusted_tree` -/

lemma root_check (root : Node) :
    ∃ s, merkle.Node.Insts.CoreConvertAsRefSliceU8.as_ref root = ok s ∧
    ∃ s1, Array.Insts.CoreConvertAsRefSlice.as_ref merkle.EMPTY_NODE = ok s1 ∧
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 s s1 =
      ok (decide (bytesOf root = bytesOf .Empty)) := by
  have hs : ∀ a : Array U8 32#usize, ∃ s, Array.Insts.CoreConvertAsRefSlice.as_ref a = ok s ∧
      s.val = a.val := fun a => ⟨_, rfl, Slice.from_val _ _⟩
  obtain ⟨s1, h1, v1⟩ := hs merkle.EMPTY_NODE
  obtain ⟨s, h, v⟩ : ∃ s, merkle.Node.Insts.CoreConvertAsRefSliceU8.as_ref root = ok s ∧
      s.val = bytesOf root := by
    cases root with
    | Empty =>
      obtain ⟨s, h, v⟩ := hs merkle.EMPTY_NODE
      exact ⟨s, h, by rw [v]; simp [bytesOf, merkle.EMPTY_NODE]⟩
    | Digest a => obtain ⟨s, h, v⟩ := hs a; exact ⟨s, h, v⟩
  refine ⟨s, h, s1, h1, ?_⟩
  have hl : s.val.length = s1.val.length := by rw [v, v1, bytesOf_length]; simp
  unfold core.slice.cmp.PartialEqSlice.eq
  simp only [Slice.length, hl, ite_true]
  simp [liftFun2]
  rw [allM_eq _ _ hl, v, v1]
  simp only [Result.ok_injective.eq_iff]
  exact decide_eq_decide.mpr (by simp [bytesOf, merkle.EMPTY_NODE])

lemma checked_sub_one (x : Usize) :
    (∃ j, Usize.checked_sub x 1#usize = some j ∧ j.val + 1 = x.val) ∨
      (Usize.checked_sub x 1#usize = none ∧ x.val = 0) := by
  have := Usize.checked_sub_bv_spec x 1#usize
  split at this
  · rename_i j hj
    left; exact ⟨j, hj, by scalar_tac⟩
  · rename_i hj
    right; exact ⟨hj, by scalar_tac⟩

/-- The checks `MerkleNonInclusionProof::verify_for_trusted_tree(root, t)` passed if it accepted:
the root has the bytes of `Empty`, or the left neighbor at `index - 1` verifies and is less than
`t`, and either there is no right neighbor and the left one is right-most, or the right neighbor at
`index` verifies and is greater than `t`; or `index = 0` and the right neighbor at `0` verifies
and is greater than `t`. -/
lemma ni_accepts {L : Type} (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L)
    (pr : merkle.MerkleNonInclusionProof L T) (root : Node) (t : L)
    (h : merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root t =
      ok (.Ok ())) :
    bytesOf root = bytesOf .Empty ∨
    (∃ l lp j, pr.left_leaf = some (l, lp) ∧ j.val + 1 = pr.index.val ∧
      merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser lp root l j =
        ok (.Ok ()) ∧
      ord.partialOrdInst.ge l t = ok false ∧
      ((pr.right_leaf = none ∧ merkle.MerkleProof.is_right_most inst lp j = ok true) ∨
       (∃ r rp, pr.right_leaf = some (r, rp) ∧
        merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser rp root r
          pr.index = ok (.Ok ()) ∧
        ord.partialOrdInst.le r t = ok false))) ∨
    (pr.index.val = 0 ∧ ∃ r rp, pr.right_leaf = some (r, rp) ∧
      merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser rp root r
        pr.index = ok (.Ok ()) ∧
      ord.partialOrdInst.le r t = ok false) := by
  obtain ⟨s, hs, s1, hs1, heq⟩ := root_check root
  unfold merkle.MerkleNonInclusionProof.verify_for_trusted_tree at h
  simp only [hs, hs1, heq, bind_ok, merkle.MerkleNonInclusionProof.is_valid_neighbor,
    core.cmp.impls.PartialOrdShared.ge, core.cmp.impls.PartialOrdShared.le, lift] at h
  by_cases hr : bytesOf root = bytesOf .Empty
  · exact Or.inl hr
  right
  simp only [hr, decide_false, Bool.false_eq_true, ite_false] at h
  rcases checked_sub_one pr.index with ⟨j, hj, hjv⟩ | ⟨hj, h0⟩ <;> rw [hj] at h <;>
    simp only [bind_ok] at h <;>
    rcases hl : pr.left_leaf with _ | ⟨l, lp⟩ <;> simp only [hl, bind_ok, Std.uncurry_apply_pair] at h
  all_goals ok_inv at h
  all_goals simp only [bne_iff_ne, ne_eq, Decidable.not_not, Bool.not_eq_true,
    core.option.Option.is_none, Option.isNone_iff_eq_none] at *
  all_goals subst_vars
  all_goals first
    | (exfalso; scalar_tac)
    | (left; exact ⟨_, _, _, rfl, hjv, ‹_›, ‹_›, Or.inl ⟨‹_›, ‹_›⟩⟩)
    | (left; exact ⟨_, _, _, rfl, hjv, ‹_›, ‹_›, Or.inr ⟨_, _, ‹_›, ‹_›, ‹_›⟩⟩)
    | (right; exact ⟨h0, _, _, ‹_›, ‹_›, ‹_›⟩)

/-! ## Soundness of non-inclusion proofs -/

/-- `bcs::to_bytes` is injective on the values it serializes. -/
def BcsInjective {L : Type} (ser : serde_core.ser.Serialize L) : Prop :=
  ∀ a b v w, bcs.ser.to_bytes ser a = ok (.Ok v) → bcs.ser.to_bytes ser b = ok (.Ok w) →
    v.val = w.val → a = b

/-- Two laws of Rust's `PartialOrd`: `a >= b` is `b <= a`, and `a <= a`. -/
structure OrdModel {L : Type} (o : core.cmp.PartialOrd L L) : Prop where
  ge_eq_le : ∀ a b, o.ge a b = o.le b a
  le_refl : ∀ a, o.le a a = ok true

/-- `bcs::to_bytes` serializes the `j`th element of `ls` to `ys[j]`. -/
def Serializes {L : Type} (ser : serde_core.ser.Serialize L) (ls : List L) (ys : List (List U8)) :
    Prop :=
  ys.length = ls.length ∧ ∀ j (hj : j < ls.length), ∃ v, bcs.ser.to_bytes ser ls[j] = ok (.Ok v) ∧
    v.val = ys.getD j []

/-- `ls` is sorted by `<=`. -/
def SortedLe {L : Type} (o : core.cmp.PartialOrd L L) (ls : List L) : Prop :=
  ∀ j k (hjk : j < k) (hk : k < ls.length), o.le (ls[j]'(by omega)) ls[k] = ok true

lemma le_of_le {L : Type} {o : core.cmp.PartialOrd L L} (ho : OrdModel o) {ls : List L}
    (hs : SortedLe o ls) (j k : Nat) (hjk : j ≤ k) (hk : k < ls.length) :
    o.le (ls[j]'(by omega)) ls[k] = ok true := by
  rcases Nat.lt_or_eq_of_le hjk with h | rfl
  · exact hs j k h hk
  · exact ho.le_refl _

/-- If `ls[j] >= t` is false, no element up to `j` is `t`. -/
lemma ne_below {L : Type} {o : core.cmp.PartialOrd L L} (ho : OrdModel o) {ls : List L}
    (hs : SortedLe o ls) (t : L) (j : Nat) (hj : j < ls.length) (hge : o.ge ls[j] t = ok false)
    (k : Nat) (hk : k ≤ j) : ls[k]'(by omega) ≠ t := by
  intro e
  rw [← e, ho.ge_eq_le, le_of_le ho hs k j hk hj] at hge
  simp at hge

/-- If `ls[j] <= t` is false, no element from `j` on is `t`. -/
lemma ne_above {L : Type} {o : core.cmp.PartialOrd L L} (ho : OrdModel o) {ls : List L}
    (hs : SortedLe o ls) (t : L) (j : Nat) (hj : j < ls.length) (hle : o.le ls[j] t = ok false)
    (k : Nat) (hjk : j ≤ k) (hk : k < ls.length) : ls[k] ≠ t := by
  intro e
  rw [← e, le_of_le ho hs j k hjk hk] at hle
  simp at hle

lemma map_getD_eq {f : Node → List U8} {ps qs : List Node} (h : ps.map f = qs.map f) (k : Nat)
    (hk : k < ps.length) : f (ps.getD k .Empty) = f (qs.getD k .Empty) := by
  have hl : ps.length = qs.length := by simpa using congrArg List.length h
  have := List.getElem_of_eq h (by simpa using hk)
  simp only [List.getElem_map] at this
  rw [List.getD_eq_getElem _ _ hk, List.getD_eq_getElem _ _ (by omega)]
  exact this

/-- A path with the bytes of the honest path of leaf `i` passes `is_right_most` only if `i` is the
last leaf, or `H` has a zero output. -/
lemma right_most_sound (ys : List (List U8)) (ps : List Node) (i : Nat) (hi : i < ys.length)
    (hr : RightMost ps i) (hp : ps.map bytesOf = (pathOf H (ys.map (leafN H)) i).map bytesOf) :
    i + 1 = ys.length ∨ ZeroHash H := by
  by_cases he : i + 1 = ys.length
  · exact Or.inl he
  right
  have hhash : ∀ a ∈ ys.map (leafN H), IsHash H a := by
    intro a ha; obtain ⟨y, -, rfl⟩ := List.mem_map.mp ha; exact isHash_leafN H y
  obtain ⟨k, hk, hev, hh⟩ := right_most H _ hhash i (by simp; omega)
  have hl : ps.length = (pathOf H (ys.map (leafN H)) i).length := by
    simpa using congrArg List.length hp
  have h1 := rightMost_getD ps i k hr (by omega) hev
  rw [map_getD_eq hp k (by omega)] at h1
  exact zeroHash_of_isHash H _ hh h1

/-- A neighbor that `verify_for_trusted_tree_with_unserialized_leaf` accepts against the root of
the tree over `ys`, the serializations of `ls`, at index `i`: it is `ls[i]` and the proof has the
bytes of its honest path, or `H` has a collision or a zero output. -/
lemma neighbor_sound (hm : HashModel inst H) {L : Type} (ser : serde_core.ser.Serialize L)
    (hser : BcsInjective ser) (ls : List L) (ys : List (List U8)) (hs : Serializes ser ls ys)
    (hy : ys ≠ []) (p : merkle.MerkleProof T) (l : L) (i : Usize)
    (h : merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser p
      (rootOf H (ys.map (leafN H))) l i = ok (.Ok ())) :
    Collision H ∨ ZeroHash H ∨ ∃ hi : i.val < ls.length, l = ls[i.val] ∧
      p.path.val.map bytesOf = (pathOf H (ys.map (leafN H)) i.val).map bytesOf := by
  obtain ⟨v, hv, hver⟩ := unserialized_ok ser p _ l i h
  obtain ⟨-, hi, hfold⟩ := (spec_of_eq_ok (verify_for_trusted_tree_spec hm p _ _ i) hver).mp rfl
  rcases trusted_opening H ys hy _ _ _ hi (congrArg bytesOf hfold) with hc | hz | ⟨-, hi', hx, hp⟩
  · exact Or.inl hc
  · exact Or.inr (Or.inl hz)
  · right; right
    have hil : i.val < ls.length := by rw [← hs.1]; exact hi'
    obtain ⟨w, hw, hwv⟩ := hs.2 i.val hil
    refine ⟨hil, hser l _ v w hv hw ?_, hp⟩
    rw [hwv, ← hx]; simp [alloc.vec.Vec.deref]

/-- Soundness of `MerkleNonInclusionProof::verify_for_trusted_tree` against the root of the tree
over the leaf hashes of `ys`, the serializations of the sorted `ls`. -/
lemma ni_sound (hm : HashModel inst H) {L : Type} (ord : core.cmp.Ord L)
    (ser : serde_core.ser.Serialize L) (ho : OrdModel ord.partialOrdInst) (hser : BcsInjective ser)
    (ls : List L) (ys : List (List U8)) (hs : Serializes ser ls ys)
    (hsort : SortedLe ord.partialOrdInst ls) (pr : merkle.MerkleNonInclusionProof L T) (t : L)
    (h : merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr
      (rootOf H (ys.map (leafN H))) t = ok (.Ok ())) :
    t ∉ ls ∨ Collision H ∨ ZeroHash H := by
  by_cases hy : ys = []
  · left
    have : ls = [] := List.eq_nil_of_length_eq_zero (by rw [← hs.1, hy]; rfl)
    simp [this]
  have hne : ys.map (leafN H) ≠ [] := by simpa using hy
  have hhash : ∀ a ∈ ys.map (leafN H), IsHash H a := by
    intro a ha; obtain ⟨y, -, rfl⟩ := List.mem_map.mp ha; exact isHash_leafN H y
  have hn := hs.1
  rcases ni_accepts ord ser pr _ t h with hr | ⟨l, lp, j, -, hj, hvl, hge, hright⟩ |
      ⟨h0, r, rp, -, hvr, hle⟩
  · exact Or.inr (Or.inr (zeroHash_of_isHash H _ (rootOf_isHash H _ hne hhash) hr))
  · rcases neighbor_sound hm ser hser ls ys hs hy lp l j hvl with hc | hz | ⟨hjl, rfl, hp⟩
    · exact Or.inr (Or.inl hc)
    · exact Or.inr (Or.inr hz)
    rcases hright with ⟨-, hrm⟩ | ⟨r, rp, -, hvr, hle⟩
    · have hrm' := (spec_of_eq_ok (is_right_most_spec (inst := inst) lp j) hrm).mp rfl
      rcases right_most_sound ys lp.path.val j.val (by omega) hrm' hp with hlast | hz
      · left
        intro hmem
        obtain ⟨k, hk, rfl⟩ := List.mem_iff_getElem.mp hmem
        exact ne_below ho hsort _ j.val hjl hge k (by omega) rfl
      · exact Or.inr (Or.inr hz)
    · rcases neighbor_sound hm ser hser ls ys hs hy rp r pr.index hvr with hc | hz | ⟨hil, rfl, -⟩
      · exact Or.inr (Or.inl hc)
      · exact Or.inr (Or.inr hz)
      left
      intro hmem
      obtain ⟨k, hk, rfl⟩ := List.mem_iff_getElem.mp hmem
      by_cases hkj : k ≤ j.val
      · exact ne_below ho hsort _ j.val hjl hge k hkj rfl
      · exact ne_above ho hsort _ pr.index.val hil hle k (by omega) hk rfl
  · rcases neighbor_sound hm ser hser ls ys hs hy rp r pr.index hvr with hc | hz | ⟨hil, rfl, -⟩
    · exact Or.inr (Or.inl hc)
    · exact Or.inr (Or.inr hz)
    left
    intro hmem
    obtain ⟨k, hk, rfl⟩ := List.mem_iff_getElem.mp hmem
    exact ne_above ho hsort _ pr.index.val hil hle k (by omega) hk rfl

/-! ## Trees built by `MerkleTree` -/

/-- The root of the tree `build_from_leaf_hashes(hs)` is `rootOf hs`. -/
lemma tree_root (hm : HashModel inst H) (hs : alloc.vec.Vec Node) (hn : 4 * hs.length ≤ Usize.max)
    (t : merkle.MerkleTree T) (ht : merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t)
    (root : Node) (hr : merkle.MerkleTree.root inst t = ok root) : root = rootOf H hs.val := by
  obtain ⟨t', ht', hnodes, -⟩ := spec_eq_ok (build_spec hm hs hn)
  rw [ht] at ht'
  obtain rfl := Result.ok_injective ht'
  exact spec_of_eq_ok (p := fun r => r = rootOf H hs.val) (root_spec (inst := inst) hs.val t hnodes) hr

lemma exists_leaves (hm : HashModel inst H) : ∀ l : List Node,
    (∀ a ∈ l, ∃ y : Slice U8, merkle.leaf_hash inst y = ok a) →
    ∃ ys : List (List U8), l = ys.map (leafN H)
  | [], _ => ⟨[], rfl⟩
  | a :: l, h => by
    obtain ⟨y, hy⟩ := h a (by simp)
    rw [leaf_hash_eq hm] at hy
    obtain ⟨ys, hys⟩ := exists_leaves hm l (fun b hb => h b (by simp [hb]))
    exact ⟨y.val :: ys, by rw [← Result.ok_injective hy, hys]; rfl⟩

lemma exists_serialized (hm : HashModel inst H) {L : Type} (ser : serde_core.ser.Serialize L) :
    ∀ (ls : List L) (hl : List Node) (hlen : hl.length = ls.length),
    (∀ j (hj : j < ls.length), ∃ v, bcs.ser.to_bytes ser ls[j] = ok (.Ok v) ∧
      merkle.leaf_hash inst (alloc.vec.Vec.deref v) = ok (hl[j]'(by omega))) →
    ∃ ys, Serializes ser ls ys ∧ hl = ys.map (leafN H)
  | [], [], _, _ => ⟨[], ⟨rfl, fun j hj => by simp at hj⟩, rfl⟩
  | x :: ls, a :: hl, hlen, h => by
    obtain ⟨v, hv, ha⟩ := h 0 (by simp)
    rw [leaf_hash_eq hm] at ha
    simp only [List.getElem_cons_zero] at ha
    obtain ⟨ys, ⟨hyl, hys⟩, hm'⟩ := exists_serialized hm ser ls hl (by simpa using hlen)
      (fun j hj => by
        have := h (j + 1) (by simp; omega)
        simp only [List.getElem_cons_succ] at this
        exact this)
    refine ⟨v.val :: ys, ⟨by simp [hyl], ?_⟩, ?_⟩
    · intro j hj
      cases j with
      | zero => exact ⟨v, hv, rfl⟩
      | succ j => simpa using hys j (by simpa using hj)
    · simp only [List.map_cons, hm', List.cons.injEq, and_true]
      rw [← Result.ok_injective ha]; simp [alloc.vec.Vec.deref]
  | [], _ :: _, hlen, _ => by simp at hlen
  | _ :: _, [], hlen, _ => by simp at hlen

lemma isDigest_fold : ∀ (c : Node) (ps : List Node) (i : Nat), IsDigest c → IsDigest (fold H c ps i)
  | _, [], _, h => h
  | c, s :: ps, i, _ => isDigest_fold (step H c s i) ps (i / 2) (isDigest_step H c s i)

/-! ## No panics -/

/-- `bcs::to_bytes` returns, `Ok` or `Err`, on every value. -/
def BcsReturns {L : Type} (ser : serde_core.ser.Serialize L) : Prop :=
  ∀ a, ∃ r, bcs.ser.to_bytes ser a = ok r

lemma ret_bind {α β : Type _} {m : Result α} {f : α → Result β} (hm : ∃ x, m = ok x)
    (hf : ∀ x, ∃ y, f x = ok y) : ∃ y, (m >>= f) = ok y := by
  obtain ⟨x, rfl⟩ := hm
  simpa using hf x

lemma unserialized_returns (hm : HashModel inst H) {L : Type} (ser : serde_core.ser.Serialize L)
    (hb : BcsReturns ser) (p : merkle.MerkleProof T) (root : Node) (l : L) (i : Usize) :
    ∃ r, merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser p root l i =
      ok r := by
  unfold merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf
  obtain ⟨r, hr⟩ := hb l
  rw [hr, bind_ok]
  cases r with
  | Ok v =>
    obtain ⟨x, hx, -⟩ := spec_eq_ok (verify_for_trusted_tree_spec hm p root (alloc.vec.Vec.deref v) i)
    simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, hx]
  | Err e =>
    simp [core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch, from_residual_eq,
      merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf.closure.Insts.CoreOpsFunctionFnOnceTupleErrorFastCryptoError.call_once]

/-- `MerkleNonInclusionProof::verify_for_trusted_tree` returns on every input if `bcs::to_bytes`,
`<=` and `>=` do. -/
lemma ni_returns (hm : HashModel inst H) {L : Type} (ord : core.cmp.Ord L)
    (ser : serde_core.ser.Serialize L) (hb : BcsReturns ser)
    (hle : ∀ a b, ∃ r, ord.partialOrdInst.le a b = ok r)
    (hge : ∀ a b, ∃ r, ord.partialOrdInst.ge a b = ok r)
    (pr : merkle.MerkleNonInclusionProof L T) (root : Node) (t : L) :
    ∃ r, merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root t = ok r := by
  have hu := unserialized_returns hm ser hb
  have hrm : ∀ (p : merkle.MerkleProof T) j, ∃ r, merkle.MerkleProof.is_right_most inst p j = ok r :=
    fun p j => by obtain ⟨r, hr, -⟩ := spec_eq_ok (is_right_most_spec (inst := inst) p j); exact ⟨r, hr⟩
  have hbr : ∀ (w : core.result.Result Unit error.FastCryptoError),
      ∃ r, core.result.Result.Insts.CoreOpsTry.branch w = ok r := fun w => by
    cases w <;> exact ⟨_, rfl⟩
  obtain ⟨s, hs, s1, hs1, heq⟩ := root_check root
  unfold merkle.MerkleNonInclusionProof.verify_for_trusted_tree
  simp only [hs, hs1, heq, bind_ok, merkle.MerkleNonInclusionProof.is_valid_neighbor,
    core.cmp.impls.PartialOrdShared.ge, core.cmp.impls.PartialOrdShared.le, lift, from_residual_eq]
  rcases checked_sub_one pr.index with ⟨j, hj, -⟩ | ⟨hj, -⟩ <;> rw [hj] <;>
    simp only [bind_ok] <;>
    rcases hl : pr.left_leaf with _ | ⟨l, lp⟩ <;> simp only [bind_ok, Std.uncurry_apply_pair]
  all_goals repeat' (first
    | exact ⟨_, rfl⟩
    | exact hu _ _ _ _
    | exact hle _ _
    | exact hge _ _
    | exact hrm _ _
    | exact hbr _
    | apply ret_bind
    | intro _
    | split)

end MerkleProofs
