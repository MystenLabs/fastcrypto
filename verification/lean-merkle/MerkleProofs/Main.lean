-- THIS FILE IS AI-ONLY
import MerkleProofs.Proof
import MerkleProofs.Verify

/-!
The theorems about `fastcrypto::merkle`, for any `HashFunction` that satisfies `HashModel` with
some `H`.

`MerkleProof::verify(root, leaf, i, n)`, for a tree with `n` leaves whose root is not trusted:
* `verify_complete`: a tree built from `n` leaf hashes gives, for every leaf, a proof that
  `verify` accepts against the tree's root.
* `verify_binding`: if `verify` accepts two proofs for the same `root`, index and `n`, they are
  for the same leaf, or `H` has a collision.

`MerkleProof::verify_for_trusted_tree(root, leaf, i)`, for a root built by `MerkleTree`:
* `verify_for_trusted_tree_complete`: as `verify_complete`, and the proof has `depth n`
  siblings.
* `verify_for_trusted_tree_binding`: as `verify_binding`, for proofs of the same length.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

theorem spec_eq_ok {α : Type _} {m : Result α} {p : α → Prop} (h : m ⦃ x => p x ⦄) :
    ∃ x, m = ok x ∧ p x := by
  cases m with
  | ret a => exact ⟨a, rfl, (WP.spec_ok a).mp h⟩
  | vis e k => exact absurd h (by simp)
  | div => exact absurd h (by simp)

theorem spec_of_eq_ok {α : Type _} {m : Result α} {p : α → Prop} {x : α}
    (h : m ⦃ x => p x ⦄) (hm : m = ok x) : p x := by
  rw [hm] at h; exact (WP.spec_ok x).mp h

/-- With at most `usize::MAX / 4` leaves, the tree has fewer than `usize::BITS` levels. -/
theorem depth_lt_numBits (n : Nat) (hn : 4 * n ≤ Usize.max) :
    depth n < System.Platform.numBits := by
  have hmax : Usize.max = 2 ^ System.Platform.numBits - 1 := by
    simp [Usize.max, Usize.numBits]
  have h := depth_le n (System.Platform.numBits - 2) (by
    rcases System.Platform.numBits_eq with h | h <;> rw [h] at hmax ⊢ <;> omega)
  have : 2 ≤ System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> omega
  omega

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

/-- Binding of `verify_for_trusted_tree`, for proofs of the same length. If it accepts proofs `p`
and `p'` with `p.len() = p'.len()` for `root` and index `i`, for leaves `leaf` and `leaf'`, then
`leaf = leaf'` or `H` has a collision. -/
theorem verify_for_trusted_tree_binding (hm : HashModel inst H) (p p' : merkle.MerkleProof T)
    (root : Node) (leaf leaf' : Slice U8) (i : Usize) (hlen : p.path.length = p'.path.length)
    (h : merkle.MerkleProof.verify_for_trusted_tree inst p root leaf i = ok (.Ok ()))
    (h' : merkle.MerkleProof.verify_for_trusted_tree inst p' root leaf' i = ok (.Ok ())) :
    leaf.val = leaf'.val ∨ Collision H := by
  obtain ⟨-, -, e⟩ := (spec_of_eq_ok (verify_for_trusted_tree_spec hm p root leaf i) h).mp rfl
  obtain ⟨-, -, e'⟩ :=
    (spec_of_eq_ok (verify_for_trusted_tree_spec hm p' root leaf' i) h').mp rfl
  rcases fold_binding H p.path.val p'.path.val (leafN H leaf.val) (leafN H leaf'.val) i.val hlen
      trivial trivial (e.trans e'.symm)
    with hc | hc
  · exact leafN_inj H _ _ hc
  · exact Or.inr hc

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

end MerkleProofs
