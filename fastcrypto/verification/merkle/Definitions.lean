import merkle.Generated.Funs

/-!
The definitions that the theorems in `Theorems.lean` are stated with: the inputs that verifying the
proofs and building the tree hash, and what the theorems conclude about them (`CollisionIn`,
`ZeroHashIn`), and the trees and leaves. A reviewer reads this file, `Assumptions.lean` and
`Theorems.lean`; the files in `Proofs/` are lemmas, which Lean checks.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

/-- The 32 bytes that represent a node in a hash: zeros for `Empty`. -/
def bytesOf : merkle.Node → List U8
  | .Empty => List.replicate 32 0#u8
  | .Digest v => v.val

/-- `H` has a collision among the inputs `xs`: two different ones with the same hash. -/
def CollisionIn (H : List U8 → Array U8 32#usize) (xs : List (List U8)) : Prop :=
  ∃ x ∈ xs, ∃ y ∈ xs, x ≠ y ∧ H x = H y

/-- `H` maps one of the inputs `xs` to 32 zero bytes, the bytes of `Node::Empty`. -/
def ZeroHashIn (H : List U8 → Array U8 32#usize) (xs : List (List U8)) : Prop :=
  ∃ x ∈ xs, (H x).val = bytesOf .Empty

/-! ## The inputs that are hashed -/

/-- The input that `leaf_hash(leaf)` hashes. -/
def leafInput (leaf : List U8) : List U8 := 0#u8 :: leaf

/-- The input that `inner_hash(l, r)` hashes. -/
def innerInput (l r : merkle.Node) : List U8 := 1#u8 :: (bytesOf l ++ bytesOf r)

/-- The input hashed one step up from node `c`, at index `i` on its level, with sibling `s`. -/
def stepInput (c s : merkle.Node) (i : Nat) : List U8 :=
  if i % 2 = 0 then innerInput c s else innerInput s c

/-- The inputs hashed from node `c`, at index `i` on its level, up the siblings `path`, from the
bottom. -/
def pathInputs (H : List U8 → Array U8 32#usize) : merkle.Node → List merkle.Node → Nat →
    List (List U8)
  | _, [], _ => []
  | c, s :: ps, i => stepInput c s i :: pathInputs H (.Digest (H (stepInput c s i))) ps (i / 2)

/-- The inputs that `verify` and `verify_for_trusted_tree` hash for `leaf`, index `i` and a proof
with siblings `path`: the leaf's, then one per sibling. -/
def verifyInputs (H : List U8 → Array U8 32#usize) (leaf : List U8) (path : List merkle.Node)
    (i : Nat) : List (List U8) :=
  leafInput leaf :: pathInputs H (.Digest (H (leafInput leaf))) path i

/-- The inputs hashed for the level above the nodes `l`, padded with `Empty` to even length. -/
def levelInputs : List merkle.Node → List (List U8)
  | a :: b :: r => innerInput a b :: levelInputs r
  | [a] => [innerInput a .Empty]
  | [] => []

/-- The inputs hashed for the levels above `l`, for at most `n` levels. -/
def treeInputsN (H : List U8 → Array U8 32#usize) : Nat → List merkle.Node → List (List U8)
  | 0, _ => []
  | n + 1, l => if l.length ≤ 1 then [] else
    levelInputs l ++ treeInputsN H n ((levelInputs l).map fun x => .Digest (H x))

/-- The inputs that `build_from_leaf_hashes(hs)` hashes to build the tree over `hs`, level by
level. -/
def treeInputs (H : List U8 → Array U8 32#usize) (hs : List merkle.Node) : List (List U8) :=
  treeInputsN H hs.length hs

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

/-- `hs` are the leaf hashes of `ys`: `leaf_hash(ys[j]) = hs[j]`. -/
def LeafHashes {T : Type} (inst : hash.HashFunction T 32#usize) (ys : List (Slice U8))
    (hs : alloc.vec.Vec merkle.Node) : Prop :=
  ∃ hlen : hs.val.length = ys.length, ∀ j (hj : j < ys.length),
    merkle.leaf_hash inst ys[j] = ok (hs.val[j]'(by omega))

open Classical in
/-- The bytes of `bcs::to_bytes(a)`, or none if it fails. -/
noncomputable def bcsBytes {L : Type} (ser : serde_core.ser.Serialize L) (a : L) : List U8 :=
  if h : ∃ v, bcs.ser.to_bytes ser a = ok (.Ok v) then h.choose.val else []

/-- The inputs that `MerkleNonInclusionProof::verify_for_trusted_tree` hashes for `pr`: those of
verifying each neighbor it has, the left one at `index - 1` and the right one at `index`. -/
noncomputable def nonInclusionInputs {L T : Type} (H : List U8 → Array U8 32#usize)
    (ser : serde_core.ser.Serialize L) (pr : merkle.MerkleNonInclusionProof L T) :
    List (List U8) :=
  (match pr.left_leaf with
    | some (l, p) => verifyInputs H (bcsBytes ser l) p.path.val (pr.index.val - 1)
    | none => []) ++
  (match pr.right_leaf with
    | some (r, p) => verifyInputs H (bcsBytes ser r) p.path.val pr.index.val
    | none => [])

end MerkleProofs
