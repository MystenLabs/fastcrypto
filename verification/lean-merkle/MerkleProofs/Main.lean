-- THIS FILE IS AI-ONLY
import MerkleProofs.Proof
import MerkleProofs.Verify

/-!
The two properties of `fastcrypto::merkle` proved here, for any `HashFunction` that satisfies
`HashModel` with some `H`:

* `inclusion_complete`: a tree built from leaf hashes gives, for every leaf, a proof of length
  `depth n` that `verify_proof` accepts against the tree's root.
* `inclusion_binding`: two proofs of the same length that `verify_proof` accepts for the same
  root and index are for the same leaf, or `H` has a collision.
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

theorem spec_of_eq_ok {α : Type _} {m : Result α} {p : α → Prop} {x : α} (h : m ⦃ x => p x ⦄)
    (hm : m = ok x) : p x := by
  rw [hm] at h; exact (WP.spec_ok x).mp h

/-- With at most `usize::MAX / 4` leaves, the tree has fewer than `usize::BITS` levels. -/
theorem depth_lt_numBits (n : Nat) (hn : 4 * n ≤ Usize.max) : depth n < System.Platform.numBits := by
  have hmax : Usize.max = 2 ^ System.Platform.numBits - 1 := by
    simp [Usize.max, Usize.numBits]
  have h := depth_le n (System.Platform.numBits - 2) (by
    rcases System.Platform.numBits_eq with h | h <;> rw [h] at hmax ⊢ <;> omega)
  have : 2 ≤ System.Platform.numBits := by
    rcases System.Platform.numBits_eq with h | h <;> omega
  omega

/-- Completeness of inclusion proofs. `build_from_leaf_hashes(hs)` returns a tree `t`, and
`t.root()` returns a node `root`, such that for every `i < hs.len()` and every `leaf` whose
`leaf_hash` is `hs[i]`, `t.get_proof(i)` returns a proof of length `depth(hs.len())` and
`verify_proof(root, leaf, i)` accepts it. -/
theorem inclusion_complete (hm : HashModel inst H) (hs : alloc.vec.Vec Node)
    (hn : 4 * hs.length ≤ Usize.max) :
    ∃ t, merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t ∧
    ∃ root, merkle.MerkleTree.root inst t = ok root ∧
    ∀ (i : Usize) (leaf : Slice U8) (hi : i.val < hs.length),
      merkle.leaf_hash inst leaf = ok (hs.val[i.val]'hi) →
      ∃ p, merkle.MerkleTree.get_proof inst t i = ok (.Ok p) ∧
        p.path.length = depth hs.length ∧
        merkle.MerkleProof.verify_proof inst p root leaf i = ok (.Ok ()) := by
  obtain ⟨t, ht, hnodes, hleaves⟩ := spec_eq_ok (build_spec hm hs hn)
  obtain ⟨root, hr, hroot⟩ := spec_eq_ok (root_spec (inst := inst) hs.val t hnodes)
  refine ⟨t, ht, root, hr, ?_⟩
  intro i leaf hi hleaf
  obtain ⟨r, hget, p, rfl, hp⟩ :=
    spec_eq_ok (get_proof_spec (inst := inst) hs.val t hnodes hleaves i hi)
  have hlen : p.path.length = depth hs.length := by
    simp only [alloc.vec.Vec.length, hp, length_pathOf]
  refine ⟨p, hget, hlen, ?_⟩
  obtain ⟨v, hv, hvi⟩ := spec_eq_ok (verify_proof_spec hm p root leaf i)
  rw [hv, hvi.mpr]
  have hl : leafN H leaf.val = hs.val[i.val] := by
    rw [leaf_hash_eq hm] at hleaf; exact Result.ok_injective hleaf
  refine ⟨by rw [hlen]; exact depth_lt_numBits _ hn, ?_, ?_⟩
  · rw [hlen]
    exact lt_of_lt_of_le hi (lt_two_pow_depth _)
  · rw [hp, hl, fold_pathOf H hs.val i.val hi, hroot]

/-- Binding of inclusion proofs. If `verify_proof` accepts proofs `p` and `p'` of the same length
for `root` and index `i`, for leaves `leaf` and `leaf'`, then `leaf = leaf'` or `H` has a
collision. -/
theorem inclusion_binding (hm : HashModel inst H) (p p' : merkle.MerkleProof T) (root : Node)
    (leaf leaf' : Slice U8) (i : Usize) (hlen : p.path.length = p'.path.length)
    (h : merkle.MerkleProof.verify_proof inst p root leaf i = ok (.Ok ()))
    (h' : merkle.MerkleProof.verify_proof inst p' root leaf' i = ok (.Ok ())) :
    leaf.val = leaf'.val ∨ Collision H := by
  obtain ⟨-, -, e⟩ := (spec_of_eq_ok (verify_proof_spec hm p root leaf i) h).mp rfl
  obtain ⟨-, -, e'⟩ := (spec_of_eq_ok (verify_proof_spec hm p' root leaf' i) h').mp rfl
  rcases fold_binding H p.path.val p'.path.val (leafN H leaf.val) (leafN H leaf'.val) i.val hlen
      trivial trivial (e.trans e'.symm)
    with hc | hc
  · exact leafN_inj H _ _ hc
  · exact Or.inr hc

end MerkleProofs
