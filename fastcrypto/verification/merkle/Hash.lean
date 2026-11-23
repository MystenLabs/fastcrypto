-- THIS FILE IS AI-ONLY
import merkle.Generated.Funs

/-!
The hash function. The generated code takes the `HashFunction` impl as a parameter `inst`, a
structure of opaque functions. `HashModel inst H` says that `inst` hashes the concatenation of
what it was given to `update` with `H`: there is a function `absorbed` from hasher states to the
bytes given so far such that `default` absorbed nothing, `update` appends the bytes of its
argument, and `finalize` returns `H` of the bytes absorbed. None of them fails.

Under this model, `leaf_hash` is `H (0 :: leaf)` and `inner_hash` is `H (1 :: left ++ right)`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

/-- `inst` hashes the concatenation of its inputs with `H`. -/
structure HashModel {T : Type} (inst : hash.HashFunction T 32#usize)
    (H : List U8 → Array U8 32#usize) where
  absorbed : T → List U8
  default_ok : ∃ s, inst.coredefaultDefaultInst.default = ok s ∧ absorbed s = []
  update_ok : ∀ {D : Type} (r : core.convert.AsRef D (Slice U8)) (s : T) (d : D) (bs : Slice U8),
    r.as_ref d = ok bs → ∃ s', inst.update r s d = ok s' ∧ absorbed s' = absorbed s ++ bs.val
  finalize_ok : ∀ s, inst.finalize s = ok ⟨H (absorbed s)⟩

/-- The 32 bytes that represent a node in a hash: zeros for `Empty`. -/
def bytesOf : merkle.Node → List U8
  | .Empty => List.replicate 32 0#u8
  | .Digest v => v.val

lemma bytes_eq (n : merkle.Node) : ∃ a, merkle.Node.bytes n = ok a ∧ a.val = bytesOf n := by
  cases n with
  | Empty =>
    refine ⟨_, rfl, ?_⟩
    simp [bytesOf, merkle.EMPTY_NODE]
  | Digest v => exact ⟨v, rfl, rfl⟩

lemma bytesOf_length (n : merkle.Node) : (bytesOf n).length = 32 := by
  cases n with
  | Empty => simp [bytesOf]
  | Digest v => simp [bytesOf]

variable {T : Type} {inst : hash.HashFunction T 32#usize} {H : List U8 → Array U8 32#usize}

/-- The leaf hash of `leaf`. -/
def leafN (H : List U8 → Array U8 32#usize) (leaf : List U8) : merkle.Node :=
  .Digest (H (0#u8 :: leaf))

/-- The hash of the inner node with children `l` and `r`. -/
def innerN (H : List U8 → Array U8 32#usize) (l r : merkle.Node) : merkle.Node :=
  .Digest (H (1#u8 :: (bytesOf l ++ bytesOf r)))

lemma leaf_hash_eq (hm : HashModel inst H) (leaf : Slice U8) :
    merkle.leaf_hash inst leaf = ok (leafN H leaf.val) := by
  obtain ⟨s0, h0, a0⟩ := hm.default_ok
  obtain ⟨s1, h1, a1⟩ := hm.update_ok (Array.Insts.CoreConvertAsRefSlice U8 1#usize) s0
    merkle.LEAF_PREFIX _ rfl
  obtain ⟨s2, h2, a2⟩ := hm.update_ok (Shared0T.Insts.CoreConvertAsRef
    (Slice.Insts.CoreConvertAsRefSlice U8)) s1 leaf leaf rfl
  simp only [merkle.leaf_hash, h0, h1, h2, hm.finalize_ok, bind_ok, core.convert.IntoFrom.into,
    merkle.Node.Insts.CoreConvertFromDigest32.from, leafN, a2, a1, a0]
  simp [merkle.LEAF_PREFIX]

lemma inner_hash_eq (hm : HashModel inst H) (l r : merkle.Node) :
    merkle.inner_hash inst l r = ok (innerN H l r) := by
  obtain ⟨s0, h0, a0⟩ := hm.default_ok
  obtain ⟨s1, h1, a1⟩ := hm.update_ok (Array.Insts.CoreConvertAsRefSlice U8 1#usize) s0
    merkle.INNER_PREFIX _ rfl
  obtain ⟨bl, hbl, vbl⟩ := bytes_eq l
  obtain ⟨br, hbr, vbr⟩ := bytes_eq r
  obtain ⟨s2, h2, a2⟩ := hm.update_ok (Array.Insts.CoreConvertAsRefSlice U8 32#usize) s1
    bl _ rfl
  obtain ⟨s3, h3, a3⟩ := hm.update_ok (Array.Insts.CoreConvertAsRefSlice U8 32#usize) s2
    br _ rfl
  simp only [merkle.inner_hash, h0, h1, h2, h3, hbl, hbr, hm.finalize_ok, bind_ok,
    core.convert.IntoFrom.into, merkle.Node.Insts.CoreConvertFromDigest32.from, innerN,
    a3, a2, a1, a0, Slice.from_val, vbl, vbr]
  simp [merkle.INNER_PREFIX]

end MerkleProofs
