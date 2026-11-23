-- THIS FILE IS AI-ONLY
import merkle.GetProof
import merkle.Verify
import merkle.NonInclusion
import merkle.NonInclusionComplete
import merkle.Result

/-!
The theorems about `fastcrypto::merkle`, for any `HashFunction` that satisfies `HashModel` with
some `H`.

`MerkleProof::verify(root, leaf, i, n)`, for a tree with `n` leaves whose root is not trusted:
* `verify_complete`: a tree built from `n` leaf hashes gives, for every leaf, a proof that
  `verify` accepts against the tree's root.
* `verify_binding`: if `verify` accepts two proofs for the same `root`, index and `n`, they are
  for the same leaf, or `H` has a collision.
* `verify_no_panic`: `verify` returns, without panicking, on every input.

`MerkleProof::verify_for_trusted_tree(root, leaf, i)`, for a root built by `MerkleTree`:
* `verify_for_trusted_tree_complete`: as `verify_complete`, and the proof has `depth n`
  siblings.
* `verify_for_trusted_tree_sound`: against the root of a tree built by `MerkleTree`, it accepts
  a proof for index `i` only for the `i`th leaf, or `H` has a collision or a zero output.
* `verify_for_trusted_tree_no_panic`: as `verify_no_panic`.
* `verify_for_trusted_tree_with_unserialized_leaf_sound`: as `verify_for_trusted_tree_sound`, for
  leaves serialized with BCS.

`MerkleNonInclusionProof::verify_for_trusted_tree(root, target)`, for a root built by
`MerkleTree` over sorted leaves:
* `non_inclusion_sound`: if it accepts, `target` is not a leaf, or `H` has a collision or a zero
  output.
* `non_inclusion_complete`: for a `target` that is not a leaf, `compute_non_inclusion_proof`
  returns a proof that it accepts.
* `non_inclusion_no_panic`: it returns on every input.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

/-- Completeness of `verify_for_trusted_tree`. `build_from_leaf_hashes(hs)` returns a tree `t`, and
`t.root()` returns a node `root`, such that for every `i < hs.len()` and every `leaf` whose
`leaf_hash` is `hs[i]`, `t.get_proof(i)` returns a proof of length `depth(hs.len())` and
`verify_for_trusted_tree(root, leaf, i)` accepts it. -/
theorem verify_for_trusted_tree_complete (hm : HashModel inst H) (hs : alloc.vec.Vec Node)
    (hn : 4 * hs.length ≤ Usize.max) :
    ∃ t, merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t ∧
    ∃ root, merkle.MerkleTree.root inst t = ok root ∧
    ∀ (i : Usize) (leaf : Slice U8) (hi : i.val < hs.length),
      merkle.leaf_hash inst leaf = ok (hs.val[i.val]'hi) →
      ∃ p, merkle.MerkleTree.get_proof inst t i = ok (.Ok p) ∧
        p.path.length = depth hs.length ∧
        merkle.MerkleProof.verify_for_trusted_tree inst p root leaf i = ok (.Ok ()) := by
  obtain ⟨t, ht, hnodes, hleaves⟩ := spec_eq_ok (build_spec hm hs hn)
  obtain ⟨root, hr, hroot⟩ := spec_eq_ok (root_spec (inst := inst) hs.val t hnodes)
  refine ⟨t, ht, root, hr, ?_⟩
  intro i leaf hi hleaf
  obtain ⟨r, hget, p, rfl, hp⟩ :=
    spec_eq_ok (get_proof_spec (inst := inst) hs.val t hnodes hleaves i hi)
  have hlen : p.path.length = depth hs.length := by
    simp only [alloc.vec.Vec.length, hp, length_pathOf]
  refine ⟨p, hget, hlen, ?_⟩
  obtain ⟨v, hv, hvi⟩ := spec_eq_ok (verify_for_trusted_tree_spec hm p root leaf i)
  rw [hv, hvi.mpr]
  have hl : leafN H leaf.val = hs.val[i.val] := by
    rw [leaf_hash_eq hm] at hleaf; exact Result.ok_injective hleaf
  refine ⟨by rw [hlen]; exact depth_lt_numBits _ hn, ?_, ?_⟩
  · rw [hlen]
    exact lt_of_lt_of_le hi (lt_two_pow_depth _)
  · rw [hp, hl, fold_pathOf H hs.val i.val hi, hroot]

/-- Soundness of `verify_for_trusted_tree`. Let `hs` be leaf hashes, `root` the root of
`build_from_leaf_hashes(hs)`. If `verify_for_trusted_tree(root, leaf, i)` accepts a proof, of any
length, then `i < hs.len()` and `leaf_hash(leaf) = hs[i]`, or `H` has a collision or maps some
input to 32 zero bytes. -/
theorem verify_for_trusted_tree_sound (hm : HashModel inst H) (hs : alloc.vec.Vec Node)
    (hleaves : ∀ a ∈ hs.val, ∃ y : Slice U8, merkle.leaf_hash inst y = ok a)
    (hn : 4 * hs.length ≤ Usize.max) (t : merkle.MerkleTree T)
    (ht : merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t) (root : Node)
    (hr : merkle.MerkleTree.root inst t = ok root) (p : merkle.MerkleProof T) (leaf : Slice U8)
    (i : Usize) (h : merkle.MerkleProof.verify_for_trusted_tree inst p root leaf i = ok (.Ok ())) :
    (∃ hi : i.val < hs.length, merkle.leaf_hash inst leaf = ok (hs.val[i.val]'hi)) ∨
      Collision H ∨ ZeroHash H := by
  have hroot := tree_root hm hs hn t ht root hr
  obtain ⟨ys, hys⟩ := exists_leaves hm hs.val hleaves
  obtain ⟨-, hi, hfold⟩ := (spec_of_eq_ok (verify_for_trusted_tree_spec hm p root leaf i) h).mp rfl
  rw [hroot, hys] at hfold
  by_cases hy : ys = []
  · subst hy
    have := isDigest_fold (H := H) (leafN H leaf.val) p.path.val i.val trivial
    rw [hfold] at this
    simp [rootOf, IsDigest] at this
  rcases trusted_opening H ys hy _ _ _ hi (congrArg bytesOf hfold) with hc | hz | ⟨-, hi', hx, -⟩
  · exact Or.inr (Or.inl hc)
  · exact Or.inr (Or.inr hz)
  · left
    have hil : i.val < hs.length := by
      simp only [alloc.vec.Vec.length, hys, List.length_map]; exact hi'
    refine ⟨hil, ?_⟩
    rw [leaf_hash_eq hm]
    congr 1
    simp only [hys, List.getElem_map, hx, List.getD_eq_getElem _ _ hi']

/-- Completeness of `verify`. For leaf hashes `hs` with `4 · hs.len() ≤ usize::MAX`, the tree
built from them has a root `root` such that, for every `i < hs.len()` and every `leaf` whose `leaf_hash` is
`hs[i]`, `get_proof(i)` returns a proof `p` and `p.verify(root, leaf, i, hs.len())` returns
`Ok(())`. -/
theorem verify_complete (hm : HashModel inst H) (hs : alloc.vec.Vec Node)
    (hn : 4 * hs.length ≤ Usize.max) :
    ∃ t, merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t ∧
    ∃ root, merkle.MerkleTree.root inst t = ok root ∧
    ∀ (i : Usize) (leaf : Slice U8) (hi : i.val < hs.length),
      merkle.leaf_hash inst leaf = ok (hs.val[i.val]'hi) →
      ∃ p, merkle.MerkleTree.get_proof inst t i = ok (.Ok p) ∧
        merkle.MerkleProof.verify inst p root leaf i (alloc.vec.Vec.len hs) = ok (.Ok ()) := by
  obtain ⟨t, ht, root, hr, h⟩ := verify_for_trusted_tree_complete hm hs hn
  refine ⟨t, ht, root, hr, fun i leaf hi hleaf => ?_⟩
  obtain ⟨p, hp, hlen, hv⟩ := h i leaf hi hleaf
  refine ⟨p, hp, ?_⟩
  have htrusted := (spec_of_eq_ok (verify_for_trusted_tree_spec hm p root leaf i) hv).mp rfl
  obtain ⟨v, hv', hvi⟩ := spec_eq_ok (verify_spec hm p root leaf i (alloc.vec.Vec.len hs))
  rw [hv', hvi.mpr]
  simp only [alloc.vec.Vec.len_val]
  exact ⟨hi, hlen, htrusted⟩

/-- Binding of `verify`. For any `n`, any `root` and any index `i`, with no assumption on how
`root` or the proofs were made: if `verify(root, leaf, i, n)` and `verify(root, leaf', i, n)` both
return `Ok(())`, then `leaf = leaf'` or `H` has a collision. -/
theorem verify_binding (hm : HashModel inst H) (n : Usize) (root : Node) (i : Usize)
    (leaf leaf' : Slice U8) (p p' : merkle.MerkleProof T)
    (h : merkle.MerkleProof.verify inst p root leaf i n = ok (.Ok ()))
    (h' : merkle.MerkleProof.verify inst p' root leaf' i n = ok (.Ok ())) :
    leaf.val = leaf'.val ∨ Collision H := by
  obtain ⟨-, hl, -, -, e⟩ := (spec_of_eq_ok (verify_spec hm p root leaf i n) h).mp rfl
  obtain ⟨-, hl', -, -, e'⟩ := (spec_of_eq_ok (verify_spec hm p' root leaf' i n) h').mp rfl
  rcases fold_binding H p.path.val p'.path.val (leafN H leaf.val) (leafN H leaf'.val) i.val
      (hl.trans hl'.symm) trivial trivial (e.trans e'.symm) with hc | hc
  · exact leafN_inj H _ _ hc
  · exact Or.inr hc

/-- `verify` does not panic: for every proof, root, leaf, index and `n`, it returns `Ok(())` or
an error. -/
theorem verify_no_panic (hm : HashModel inst H) (p : merkle.MerkleProof T) (root : Node)
    (leaf : Slice U8) (i n : Usize) :
    ∃ r, merkle.MerkleProof.verify inst p root leaf i n = ok r := by
  obtain ⟨r, hr, -⟩ := spec_eq_ok (verify_spec hm p root leaf i n)
  exact ⟨r, hr⟩

/-- `verify_for_trusted_tree` does not panic: for every proof, root, leaf and index, it returns
`Ok(())` or an error. -/
theorem verify_for_trusted_tree_no_panic (hm : HashModel inst H) (p : merkle.MerkleProof T)
    (root : Node) (leaf : Slice U8) (i : Usize) :
    ∃ r, merkle.MerkleProof.verify_for_trusted_tree inst p root leaf i = ok r := by
  obtain ⟨r, hr, -⟩ := spec_eq_ok (verify_for_trusted_tree_spec hm p root leaf i)
  exact ⟨r, hr⟩

/-- Soundness of `MerkleNonInclusionProof::verify_for_trusted_tree`. Let `ls` be sorted by `L`'s
`<=`, `hs` the leaf hashes of their BCS serializations (as `build_from_unserialized(ls)` computes
them) and `root` the root of `build_from_leaf_hashes(hs)`. If `verify_for_trusted_tree(root,
target)` accepts a non-inclusion proof, then `target` is not in `ls`, or `H` has a collision or
maps some input to 32 zero bytes. -/
theorem non_inclusion_sound (hm : HashModel inst H) {L : Type} (ord : core.cmp.Ord L)
    (ser : serde_core.ser.Serialize L) (ho : OrdModel ord.partialOrdInst)
    (hser : BcsInjective ser) (ls : List L) (hsort : SortedLe ord.partialOrdInst ls)
    (hs : alloc.vec.Vec Node) (hlen : hs.val.length = ls.length)
    (hleaves : ∀ j (hj : j < ls.length), ∃ v, bcs.ser.to_bytes ser ls[j] = ok (.Ok v) ∧
      merkle.leaf_hash inst (alloc.vec.Vec.deref v) = ok (hs.val[j]'(by omega)))
    (hn : 4 * hs.length ≤ Usize.max) (t : merkle.MerkleTree T)
    (ht : merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t) (root : Node)
    (hr : merkle.MerkleTree.root inst t = ok root) (pr : merkle.MerkleNonInclusionProof L T)
    (target : L)
    (h : merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root target =
      ok (.Ok ())) :
    target ∉ ls ∨ Collision H ∨ ZeroHash H := by
  have hroot := tree_root hm hs hn t ht root hr
  obtain ⟨ys, hser', hys⟩ := exists_serialized hm ser ls hs.val hlen hleaves
  rw [hroot, hys] at h
  exact ni_sound hm ord ser ho hser ls ys hser' hsort pr target h

/-- Completeness of non-inclusion proofs. Let `leaves` be sorted by `L`'s `<=`, `hs` the leaf
hashes of their BCS serializations (as `build_from_unserialized(leaves)` computes them), with
`4 · hs.len() ≤ usize::MAX`, and `target` not in `leaves`. Then `build_from_leaf_hashes(hs)`
returns a tree `t` and `t.root()` a node `root` such that
`t.compute_non_inclusion_proof(leaves, target)` returns a proof that
`verify_for_trusted_tree(root, target)` accepts. -/
theorem non_inclusion_complete (hm : HashModel inst H) (hpp : PartitionPointSpec) {L : Type}
    (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L) (cl : core.clone.Clone L)
    (ho : OrdModel ord.partialOrdInst) (hlin : LinearOrd ord.partialOrdInst)
    (heqm : EqModel ord.eqInst.partialEqInst) (hcl : CloneIsId cl) (leaves : Slice L)
    (hsort : SortedLe ord.partialOrdInst leaves.val) (hs : alloc.vec.Vec Node)
    (hlen : hs.val.length = leaves.val.length)
    (hleaves : ∀ j (hj : j < leaves.val.length), ∃ v,
      bcs.ser.to_bytes ser leaves.val[j] = ok (.Ok v) ∧
      merkle.leaf_hash inst (alloc.vec.Vec.deref v) = ok (hs.val[j]'(by omega)))
    (hn : 4 * hs.length ≤ Usize.max) (target : L) (hnot : target ∉ leaves.val) :
    ∃ t, merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t ∧
    ∃ root, merkle.MerkleTree.root inst t = ok root ∧
    ∃ pr, merkle.MerkleTree.compute_non_inclusion_proof inst ord ser cl t leaves target =
      ok (.Ok pr) ∧
    merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root target =
      ok (.Ok ()) := by
  obtain ⟨ys, hser, hys⟩ := exists_serialized hm ser leaves.val hs.val hlen hleaves
  obtain ⟨t, ht, hnodes, hnl⟩ := spec_eq_ok (build_spec hm hs hn)
  obtain ⟨root, hr, hroot⟩ := spec_eq_ok (root_spec (inst := inst) hs.val t hnodes)
  refine ⟨t, ht, root, hr, ?_⟩
  have hyl : ys.length = hs.length := by
    simp only [alloc.vec.Vec.length, hys, List.length_map]
  rw [hroot, hys]
  rw [hys] at hnodes
  exact ni_complete hm hpp ord ser cl ho hlin heqm hcl leaves hsort ys hser (by omega) t hnodes
    (by rw [hnl, hyl]) target hnot

/-- `MerkleNonInclusionProof::verify_for_trusted_tree` does not panic: for every proof, root and
target, it returns `Ok(())` or an error. -/
theorem non_inclusion_no_panic (hm : HashModel inst H) {L : Type} (ord : core.cmp.Ord L)
    (ser : serde_core.ser.Serialize L) (hb : BcsReturns ser) (ho : OrdModel ord.partialOrdInst)
    (hlin : LinearOrd ord.partialOrdInst) (pr : merkle.MerkleNonInclusionProof L T) (root : Node)
    (target : L) :
    ∃ r, merkle.MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root target =
      ok r := by
  have hle : ∀ a b, ∃ r, ord.partialOrdInst.le a b = ok r := fun a b => by
    rcases hlin.le_ok a b with h | h <;> exact ⟨_, h⟩
  exact ni_returns hm ord ser hb hle (fun a b => by rw [ho.ge_eq_le]; exact hle b a) pr root target

/-- Soundness of `verify_for_trusted_tree_with_unserialized_leaf`. Let `hs` be the leaf hashes of
the BCS serializations of `ls` (as `build_from_unserialized(ls)` computes them), and `root` the
root of `build_from_leaf_hashes(hs)`. If `verify_for_trusted_tree_with_unserialized_leaf(root, l,
i)` accepts a proof, of any length, then `i < ls.len()` and `l = ls[i]`, or `H` has a collision or
a zero output. -/
theorem verify_for_trusted_tree_with_unserialized_leaf_sound (hm : HashModel inst H) {L : Type}
    (ser : serde_core.ser.Serialize L) (hser : BcsInjective ser) (ls : List L)
    (hs : alloc.vec.Vec Node) (hlen : hs.val.length = ls.length)
    (hleaves : ∀ j (hj : j < ls.length), ∃ v, bcs.ser.to_bytes ser ls[j] = ok (.Ok v) ∧
      merkle.leaf_hash inst (alloc.vec.Vec.deref v) = ok (hs.val[j]'(by omega)))
    (hn : 4 * hs.length ≤ Usize.max) (t : merkle.MerkleTree T)
    (ht : merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t) (root : Node)
    (hr : merkle.MerkleTree.root inst t = ok root) (p : merkle.MerkleProof T) (l : L) (i : Usize)
    (h : merkle.MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser p root l i =
      ok (.Ok ())) :
    (∃ hi : i.val < ls.length, l = ls[i.val]) ∨ Collision H ∨ ZeroHash H := by
  have hroot := tree_root hm hs hn t ht root hr
  obtain ⟨ys, hser', hys⟩ := exists_serialized hm ser ls hs.val hlen hleaves
  rw [hroot, hys] at h
  by_cases hy : ys = []
  · subst hy
    obtain ⟨v, -, hv⟩ := unserialized_ok ser p _ l i h
    obtain ⟨-, -, hfold⟩ :=
      (spec_of_eq_ok (verify_for_trusted_tree_spec hm p _ _ i) hv).mp rfl
    have := isDigest_fold (H := H) (leafN H (alloc.vec.Vec.deref v).val) p.path.val i.val trivial
    rw [hfold] at this
    simp [rootOf, IsDigest] at this
  rcases neighbor_sound hm ser hser ls ys hser' hy p l i h with hc | hz | ⟨hi, hl, -⟩
  · exact Or.inr (Or.inl hc)
  · exact Or.inr (Or.inr hz)
  · exact Or.inl ⟨hi, hl⟩

end MerkleProofs
