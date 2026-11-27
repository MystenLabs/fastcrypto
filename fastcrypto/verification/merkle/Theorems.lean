import merkle.Proofs.GetProof
import merkle.Proofs.Verify
import merkle.Proofs.NonInclusion
import merkle.Proofs.NonInclusionComplete
import merkle.Proofs.Result

/-!
The theorems about `fastcrypto::merkle`, for any `HashFunction` that satisfies `HashModel` with
some `H`. This file, `Definitions.lean`, with the definitions the theorems are stated with, and
`Assumptions.lean`, with the assumptions they take, are the claim of the proofs, so a reviewer
reads them in full. The files in `Proofs/` are lemmas, which
Lean checks.
-/

open Aeneas Aeneas.Std Result
open fastcrypto
open fastcrypto.merkle hiding Node

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

/-! ## `MerkleProof::verify` and `MerkleProof::verify_for_trusted_tree` -/

/-- Completeness. For leaf hashes `hs` with `4 · hs.len() ≤ usize::MAX`,
`build_from_leaf_hashes(hs)` returns a tree `t`, and `t.root()` returns a node `root`. For every
`i < hs.len()` and every `leaf` whose `leaf_hash` is `hs[i]`, `t.get_proof(i)` then returns a
proof with `⌈log₂ hs.len()⌉` siblings, which both `verify(root, leaf, i, hs.len())` and
`verify_for_trusted_tree(root, leaf, i)` accept. -/
theorem get_proof_complete (hm : HashModel inst H) (hs : alloc.vec.Vec Node)
    (hn : 4 * hs.length ≤ Usize.max) :
    ∃ t, MerkleTree.build_from_leaf_hashes inst hs = ok t ∧
    ∃ root, MerkleTree.root inst t = ok root ∧
    ∀ (i : Usize) (leaf : Slice U8) (hi : i.val < hs.length),
      leaf_hash inst leaf = ok (hs.val[i.val]'hi) →
      ∃ p, MerkleTree.get_proof inst t i = ok (.Ok p) ∧ p.path.length = Nat.clog 2 hs.length ∧
        MerkleProof.verify inst p root leaf i (alloc.vec.Vec.len hs) = ok (.Ok ()) ∧
        MerkleProof.verify_for_trusted_tree inst p root leaf i = ok (.Ok ()) := by
  obtain ⟨t, ht, hnodes, hleaves⟩ := spec_eq_ok (build_spec hm hs hn)
  obtain ⟨root, hr, hroot⟩ := spec_eq_ok (root_spec (inst := inst) hs.val t hnodes)
  refine ⟨t, ht, root, hr, ?_⟩
  intro i leaf hi hleaf
  obtain ⟨r, hget, p, rfl, hp⟩ :=
    spec_eq_ok (get_proof_spec (inst := inst) hs.val t hnodes hleaves i hi)
  have hlen : p.path.length = depth hs.length := by
    simp only [alloc.vec.Vec.length, hp, length_pathOf]
  have hl : leafN H leaf.val = hs.val[i.val] := by
    rw [leaf_hash_eq hm] at hleaf; exact Result.ok_injective hleaf
  have htr : MerkleProof.verify_for_trusted_tree inst p root leaf i = ok (.Ok ()) := by
    obtain ⟨v, hv, hvi⟩ := spec_eq_ok (verify_for_trusted_tree_spec hm p root leaf i)
    rw [hv, hvi.mpr]
    refine ⟨by rw [hlen]; exact depth_lt_numBits _ hn, ?_, ?_⟩
    · rw [hlen]
      exact lt_of_lt_of_le hi (lt_two_pow_depth _)
    · rw [hp, hl, fold_pathOf H hs.val i.val hi, hroot]
  refine ⟨p, hget, hlen.trans (depth_eq_clog _), ?_, htr⟩
  have htrusted := (spec_of_eq_ok (verify_for_trusted_tree_spec hm p root leaf i) htr).mp rfl
  obtain ⟨v, hv', hvi⟩ := spec_eq_ok (verify_spec hm p root leaf i (alloc.vec.Vec.len hs))
  rw [hv', hvi.mpr]
  simp only [alloc.vec.Vec.len_val]
  exact ⟨hi, hlen, htrusted⟩

/-- Binding of `verify`. For every proof `p`, root, leaf, index `i` and `n`,
`p.verify(root, leaf, i, n)` returns, without panicking. If it returns `Ok(())`, and another proof
`p'` verifies for a leaf `leaf'` with the same `root`, `i` and `n`, then `leaf = leaf'` or `H` has
a collision between two of the inputs that verifying the two proofs hashes. This holds for any
`root` and any proofs. -/
theorem verify_binding (hm : HashModel inst H) (p : MerkleProof T) (root : Node) (leaf : Slice U8)
    (i n : Usize) :
    MerkleProof.verify inst p root leaf i n ⦃ res => res = .Ok () →
      ∀ (p' : MerkleProof T) (leaf' : Slice U8),
        MerkleProof.verify inst p' root leaf' i n = ok (.Ok ()) →
        leaf.val = leaf'.val ∨ CollisionIn H (verifyInputs H leaf.val p.path.val i.val ++
          verifyInputs H leaf'.val p'.path.val i.val) ⦄ := by
  obtain ⟨r, h, -⟩ := spec_eq_ok (verify_spec hm p root leaf i n)
  rw [h, WP.spec_ok]
  rintro rfl p' leaf' h'
  obtain ⟨-, hl, -, -, e⟩ := (spec_of_eq_ok (verify_spec hm p root leaf i n) h).mp rfl
  obtain ⟨-, hl', -, -, e'⟩ := (spec_of_eq_ok (verify_spec hm p' root leaf' i n) h').mp rfl
  rcases fold_binding H p.path.val p'.path.val (leafN H leaf.val) (leafN H leaf'.val) i.val
      (hl.trans hl'.symm) trivial trivial (e.trans e'.symm) with hc | hc
  · exact (leafN_inj H _ _ hc).imp_right (CollisionIn.mono (by
      intro x hx; simp only [List.mem_cons, List.mem_nil_iff, or_false] at hx
      simp only [verifyInputs, List.mem_append, List.mem_cons]; tauto))
  · exact Or.inr (hc.mono (by
      intro x hx; simp only [List.mem_append] at hx
      simp only [verifyInputs, List.mem_append, List.mem_cons]; exact Or.imp Or.inr Or.inr hx))

/-- Soundness of `verify_for_trusted_tree`, which does not check the length of the proof. For every
proof `p`, root, leaf and index `i`, `p.verify_for_trusted_tree(root, leaf, i)` returns, without
panicking. If it returns `Ok(())` and `root` is the root of the tree over the leaf hashes `hs` of
`ys`, with `4 · hs.len() ≤ usize::MAX`, then `i < hs.len()` and `leaf_hash(leaf) = hs[i]`, or `H`
has a collision or maps one to 32 zero bytes among the inputs that verifying the proof and building
the tree hash. -/
theorem verify_for_trusted_tree_sound (hm : HashModel inst H) (p : MerkleProof T) (root : Node)
    (leaf : Slice U8) (i : Usize) :
    MerkleProof.verify_for_trusted_tree inst p root leaf i ⦃ res => res = .Ok () →
      ∀ (ys : List (Slice U8)) (hs : alloc.vec.Vec Node), 4 * hs.length ≤ Usize.max →
        LeafHashes inst ys hs → IsTreeRoot inst hs root →
        (∃ hi : i.val < hs.length, leaf_hash inst leaf = ok (hs.val[i.val]'hi)) ∨
          CollisionIn H (verifyInputs H leaf.val p.path.val i.val ++
            ys.map (fun y => leafInput y.val) ++ treeInputs H hs.val) ∨
          ZeroHashIn H (verifyInputs H leaf.val p.path.val i.val ++
            ys.map (fun y => leafInput y.val) ++ treeInputs H hs.val) ⦄ := by
  obtain ⟨r, h, -⟩ := spec_eq_ok (verify_for_trusted_tree_spec hm p root leaf i)
  rw [h, WP.spec_ok]
  rintro rfl ys0 hs hn ⟨hlen0, hleaf0⟩ ⟨t, ht, hr⟩
  have hroot := tree_root hm hs hn t ht root hr
  set ys := ys0.map (·.val) with hysd
  have hys : hs.val = ys.map (leafN H) := by
    apply List.ext_getElem (by simp [hysd, hlen0])
    intro j hj _
    have := hleaf0 j (by omega)
    rw [leaf_hash_eq hm] at this
    simp only [hysd, List.getElem_map]; exact (Result.ok_injective this).symm
  have hS : ys.map leafInput ++ treeInputs H (ys.map (leafN H)) =
      ys0.map (fun y => leafInput y.val) ++ treeInputs H hs.val := by
    rw [hys, hysd, List.map_map]; rfl
  obtain ⟨-, hi, hfold⟩ := (spec_of_eq_ok (verify_for_trusted_tree_spec hm p root leaf i) h).mp rfl
  rw [hroot, hys] at hfold
  by_cases hy : ys = []
  · rw [hy] at hfold
    have := isDigest_fold (H := H) (leafN H leaf.val) p.path.val i.val trivial
    rw [hfold] at this
    simp [rootOf, IsDigest] at this
  rcases trusted_opening H ys hy _ _ _ hi (congrArg bytesOf hfold) with hc | hz | ⟨-, hi', hx, -⟩
  · rw [List.append_assoc, hS, ← List.append_assoc] at hc; exact Or.inr (Or.inl hc)
  · rw [List.append_assoc, hS, ← List.append_assoc] at hz; exact Or.inr (Or.inr hz)
  · left
    have hil : i.val < hs.length := by
      simp only [alloc.vec.Vec.length, hys, List.length_map]; exact hi'
    refine ⟨hil, ?_⟩
    rw [leaf_hash_eq hm]
    congr 1
    simp only [hys, List.getElem_map, hx, List.getD_eq_getElem _ _ hi']

/-- Soundness of `verify_for_trusted_tree_with_unserialized_leaf`. Let `hs` be the leaf hashes of the
BCS serializations of `ls`, with `4 · hs.len() ≤ usize::MAX`, and `root` the root of the tree over
them. If `verify_for_trusted_tree_with_unserialized_leaf(root, l, i)` accepts a proof, of any
length, then `i < ls.len()` and `l = ls[i]`, or `H` has a collision or a zero output among the
inputs that verifying the proof and building the tree hash. -/
theorem verify_for_trusted_tree_with_unserialized_leaf_sound (hm : HashModel inst H) {L : Type}
    (ser : serde_core.ser.Serialize L) (hbcs : BcsModel ser) (ls : List L)
    (hs : alloc.vec.Vec Node) (hhs : SerializedLeafHashes inst ser ls hs)
    (hn : 4 * hs.length ≤ Usize.max) (root : Node) (hroot : IsTreeRoot inst hs root)
    (p : MerkleProof T) (l : L) (i : Usize)
    (h : MerkleProof.verify_for_trusted_tree_with_unserialized_leaf inst ser p root l i =
      ok (.Ok ())) :
    (∃ hi : i.val < ls.length, l = ls[i.val]) ∨
      CollisionIn H (verifyInputs H (bcsBytes ser l) p.path.val i.val ++
        ls.map (fun a => leafInput (bcsBytes ser a)) ++ treeInputs H hs.val) ∨
      ZeroHashIn H (verifyInputs H (bcsBytes ser l) p.path.val i.val ++
        ls.map (fun a => leafInput (bcsBytes ser a)) ++ treeInputs H hs.val) := by
  obtain ⟨hlen, hleaves⟩ := hhs
  obtain ⟨t, ht, hr⟩ := hroot
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
  have hS : treeS H ys = ls.map (fun a => leafInput (bcsBytes ser a)) ++ treeInputs H hs.val := by
    rw [treeS, hys, serializes_eq hser', List.map_map]; rfl
  rcases neighbor_sound hm ser hbcs.bcsInjective ls ys hser' hy p l i h with hc | hz | ⟨hi, hl, -⟩
  · rw [hS, ← List.append_assoc] at hc; exact Or.inr (Or.inl hc)
  · rw [hS, ← List.append_assoc] at hz; exact Or.inr (Or.inr hz)
  · exact Or.inl ⟨hi, hl⟩

/-! ## `MerkleNonInclusionProof::verify_for_trusted_tree` -/

/-- Soundness. Let `ls` be sorted by `L`'s `<=`, `hs` the leaf hashes of their BCS
serializations, with `4 · hs.len() ≤ usize::MAX`, and `root` the root of the tree over them. If
`verify_for_trusted_tree(root, target)` accepts a non-inclusion proof, then `target` is not in
`ls`, or `H` has a collision or maps one to 32 zero bytes among the inputs that verifying the
neighbors in the proof and building the tree hash. -/
theorem non_inclusion_sound (hm : HashModel inst H) {L : Type} [PartialOrder L]
    (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L) (cl : core.clone.Clone L)
    (hL : LeafModel ord cl) (hbcs : BcsModel ser) (ls : List L)
    (hsort : List.Pairwise (· ≤ ·) ls)
    (hs : alloc.vec.Vec Node) (hhs : SerializedLeafHashes inst ser ls hs)
    (hn : 4 * hs.length ≤ Usize.max) (root : Node) (hroot : IsTreeRoot inst hs root)
    (pr : MerkleNonInclusionProof L T) (target : L)
    (h : MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root target =
      ok (.Ok ())) :
    target ∉ ls ∨
      CollisionIn H (nonInclusionInputs H ser pr ++
        ls.map (fun a => leafInput (bcsBytes ser a)) ++ treeInputs H hs.val) ∨
      ZeroHashIn H (nonInclusionInputs H ser pr ++
        ls.map (fun a => leafInput (bcsBytes ser a)) ++ treeInputs H hs.val) := by
  obtain ⟨hlen, hleaves⟩ := hhs
  obtain ⟨t, ht, hr⟩ := hroot
  have hroot := tree_root hm hs hn t ht root hr
  obtain ⟨ys, hser', hys⟩ := exists_serialized hm ser ls hs.val hlen hleaves
  rw [hroot, hys] at h
  have hS : treeS H ys = ls.map (fun a => leafInput (bcsBytes ser a)) ++ treeInputs H hs.val := by
    rw [treeS, hys, serializes_eq hser', List.map_map]; rfl
  rcases ni_sound hm ord ser hL.ordModel hL.isPartialOrder hbcs.bcsInjective ls ys hser'
      (sortedLe_of_pairwise (hL.pairwise hsort)) pr target h with
    hn | hc | hz
  · exact Or.inl hn
  · rw [hS, ← List.append_assoc] at hc; exact Or.inr (Or.inl hc)
  · rw [hS, ← List.append_assoc] at hz; exact Or.inr (Or.inr hz)

/-- Completeness. Let `leaves` be sorted by `L`'s `<=`, `hs` the leaf hashes of their BCS
serializations, with `4 · hs.len() ≤ usize::MAX`, and `target` not in `leaves`. Then
`build_from_leaf_hashes(hs)` returns a tree `t`, `t.root()` returns a node `root`, and
`t.compute_non_inclusion_proof(leaves, target)` returns a proof that
`verify_for_trusted_tree(root, target)` accepts. -/
theorem non_inclusion_complete (hm : HashModel inst H) (hpp : PartitionPointSpec) {L : Type}
    [PartialOrder L] (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L)
    (cl : core.clone.Clone L) (hL : LeafModel ord cl) (leaves : Slice L)
    (hsort : List.Pairwise (· ≤ ·) leaves.val) (hs : alloc.vec.Vec Node)
    (hhs : SerializedLeafHashes inst ser leaves.val hs) (hn : 4 * hs.length ≤ Usize.max)
    (target : L) (hnot : target ∉ leaves.val) :
    ∃ t, MerkleTree.build_from_leaf_hashes inst hs = ok t ∧
    ∃ root, MerkleTree.root inst t = ok root ∧
    ∃ pr, MerkleTree.compute_non_inclusion_proof inst ord ser cl t leaves target = ok (.Ok pr) ∧
      MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root target =
        ok (.Ok ()) := by
  obtain ⟨hlen, hleaves⟩ := hhs
  obtain ⟨ys, hser, hys⟩ := exists_serialized hm ser leaves.val hs.val hlen hleaves
  obtain ⟨t, ht, hnodes, hnl⟩ := spec_eq_ok (build_spec hm hs hn)
  obtain ⟨root, hr, hroot⟩ := spec_eq_ok (root_spec (inst := inst) hs.val t hnodes)
  refine ⟨t, ht, root, hr, ?_⟩
  have hyl : ys.length = hs.length := by
    simp only [alloc.vec.Vec.length, hys, List.length_map]
  rw [hroot, hys]
  rw [hys] at hnodes
  exact ni_complete hm hpp ord ser cl hL.ordModel hL.isPartialOrder hL.eqModel hL.cloneIsId leaves
    (sortedLe_of_pairwise (hL.pairwise hsort)) ys hser (by omega) t hnodes
    (by rw [hnl, hyl]) target hnot

/-- `verify_for_trusted_tree` does not panic: for every proof, root and target, it returns
`Ok(())` or an error. -/
theorem non_inclusion_no_panic (hm : HashModel inst H) {L : Type} [PartialOrder L]
    (ord : core.cmp.Ord L) (ser : serde_core.ser.Serialize L) (cl : core.clone.Clone L)
    (hL : LeafModel ord cl) (hbcs : BcsModel ser)
    (pr : MerkleNonInclusionProof L T) (root : Node) (target : L) :
    MerkleNonInclusionProof.verify_for_trusted_tree inst ord ser pr root target ⦃ _ => True ⦄ := by
  have ho := hL.ordModel
  have hb := hbcs.bcsReturns
  have hle : ∀ a b, ∃ r, ord.partialOrdInst.le a b = ok r := fun a b => by
    obtain ⟨r, h, -⟩ := spec_eq_ok (ho.le_returns a b); exact ⟨r, h⟩
  obtain ⟨r, h⟩ :=
    ni_returns hm ord ser hb hle (fun a b => by rw [ho.ge_eq_le]; exact hle b a) pr root target
  rw [h, WP.spec_ok]; trivial

end MerkleProofs

#print axioms MerkleProofs.get_proof_complete
#print axioms MerkleProofs.verify_binding
#print axioms MerkleProofs.verify_for_trusted_tree_sound
#print axioms MerkleProofs.verify_for_trusted_tree_with_unserialized_leaf_sound
#print axioms MerkleProofs.non_inclusion_sound
#print axioms MerkleProofs.non_inclusion_complete
#print axioms MerkleProofs.non_inclusion_no_panic
