import merkle.Generated.Funs

/-!
The assumptions that the theorems in `Theorems.lean` take, and the definitions they are stated
with. A reviewer reads this file and `Theorems.lean`; the files in `Proofs/` are
lemmas, which Lean checks.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

/-! ## The hash function

The generated code takes the `HashFunction` impl as a parameter `inst`, a structure of opaque
functions. `HashModel inst H` says that `inst` hashes the concatenation of what it was given to
`update` with `H`. The theorems conclude that `H` is not injective or has a zero output. -/

/-- `inst` hashes the concatenation of its inputs with `H`. -/
structure HashModel {T : Type} (inst : hash.HashFunction T 32#usize)
    (H : List U8 → Array U8 32#usize) where
  absorbed : T → List U8
  default_ok : inst.coredefaultDefaultInst.default ⦃ s => absorbed s = [] ⦄
  update_ok : ∀ {D : Type} (r : core.convert.AsRef D (Slice U8)) (s : T) (d : D) (bs : Slice U8),
    r.as_ref d = ok bs → inst.update r s d ⦃ s' => absorbed s' = absorbed s ++ bs.val ⦄
  finalize_ok : ∀ s, inst.finalize s = ok ⟨H (absorbed s)⟩

/-- The 32 bytes that represent a node in a hash: zeros for `Empty`. -/
def bytesOf : merkle.Node → List U8
  | .Empty => List.replicate 32 0#u8
  | .Digest v => v.val

/-- `H` maps some input to 32 zero bytes, the bytes of `Node::Empty`. -/
def ZeroHash (H : List U8 → Array U8 32#usize) : Prop := ∃ x, (H x).val = bytesOf .Empty

/-! ## The tree -/

/-- `root` is the root of the tree over the leaf hashes `hs`: `build_from_leaf_hashes(hs)` returns
a tree, and its `root()` returns `root`. -/
def IsTreeRoot {T : Type} (inst : hash.HashFunction T 32#usize) (hs : alloc.vec.Vec merkle.Node)
    (root : merkle.Node) : Prop :=
  ∃ t, merkle.MerkleTree.build_from_leaf_hashes inst hs = ok t ∧
    merkle.MerkleTree.root inst t = ok root

/-- `hs` are the leaf hashes of the BCS serializations of `ls`, as `build_from_unserialized(ls)`
computes them. -/
def SerializedLeafHashes {T L : Type} (inst : hash.HashFunction T 32#usize)
    (ser : serde_core.ser.Serialize L) (ls : List L) (hs : alloc.vec.Vec merkle.Node) : Prop :=
  ∃ hlen : hs.val.length = ls.length, ∀ j (hj : j < ls.length), ∃ v,
    bcs.ser.to_bytes ser ls[j] = ok (.Ok v) ∧
    merkle.leaf_hash inst (alloc.vec.Vec.deref v) = ok (hs.val[j]'(by omega))

/-! ## The leaf type and BCS, for the non-inclusion proofs -/

open Classical in
/-- `L`'s `<=` is a partial order `≤`, `>=` is its converse, `==` is `false` for different values,
and `clone` returns its argument. -/
structure LeafModel {L : Type} [PartialOrder L] (ord : core.cmp.Ord L) (cl : core.clone.Clone L) :
    Prop where
  le : ∀ a b, ord.partialOrdInst.le a b = ok (decide (a ≤ b))
  ge : ∀ a b, ord.partialOrdInst.ge a b = ok (decide (b ≤ a))
  eq_ne : ∀ a b, a ≠ b → ord.eqInst.partialEqInst.eq a b = ok false
  clone : ∀ a, cl.clone a = ok a

/-- `bcs::to_bytes` returns, `Ok` or `Err`, on every value, and is injective on the values it
serializes. -/
structure BcsModel {L : Type} (ser : serde_core.ser.Serialize L) : Prop where
  returns : ∀ a, bcs.ser.to_bytes ser a ⦃ _ => True ⦄
  injective : ∀ a b v w, bcs.ser.to_bytes ser a = ok (.Ok v) →
    bcs.ser.to_bytes ser b = ok (.Ok w) → v.val = w.val → a = b

/-! ## The standard library -/

/-- `<[A]>::partition_point(f)`, for a predicate `f` that is true exactly at the indices below
`p` and does not change its state, returns `p`. -/
def PartitionPointSpec : Prop :=
  ∀ {A P : Type} (f : core.ops.function.FnMut P A Bool) (s : Slice A) (c : P) (p : Nat),
    p ≤ s.length → (∀ k (hk : k < s.length), f.call_mut c (s.val[k]'hk) = ok (decide (k < p), c)) →
    core.slice.Slice.partition_point f s c ⦃ r => r.val = p ⦄

end MerkleProofs
