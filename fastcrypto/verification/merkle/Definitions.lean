import merkle.Generated.Funs

/-!
The definitions that the theorems in `Spec.lean` are stated with: the assumptions they take, and
what they conclude. A reviewer reads this file and `Spec.lean`; the other files are lemmas, which
Lean checks.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace MerkleProofs

/-! ## The hash function

The generated code takes the `HashFunction` impl as a parameter `inst`, a structure of opaque
functions. `HashModel inst H` says that `inst` hashes the concatenation of what it was given to
`update` with `H`. The theorems conclude that `H` has a collision or a zero output. -/

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

section
variable (H : List U8 → Array U8 32#usize)

/-- `H` has a collision. -/
def Collision : Prop := ∃ x y, x ≠ y ∧ H x = H y

/-- `H` maps some input to 32 zero bytes, the bytes of `Node::Empty`. -/
def ZeroHash : Prop := ∃ x, (H x).val = bytesOf .Empty

end

/-! ## The tree -/

/-- The number of levels above the leaves of a tree with `n` leaves. -/
def depth (n : Nat) : Nat := if n ≤ 1 then 0 else depth ((n + n % 2) / 2) + 1
termination_by n
decreasing_by omega

/-! ## The leaf type and BCS, for the non-inclusion proofs -/

/-- Two laws of Rust's `PartialOrd`: `a >= b` is `b <= a`, and `a <= a`. -/
structure OrdModel {L : Type} (o : core.cmp.PartialOrd L L) : Prop where
  ge_eq_le : ∀ a b, o.ge a b = o.le b a
  le_refl : ∀ a, o.le a a = ok true

/-- `L`'s `<=` returns, and is transitive and antisymmetric. -/
structure LinearOrd {L : Type} (o : core.cmp.PartialOrd L L) : Prop where
  le_ok : ∀ a b, o.le a b = ok true ∨ o.le a b = ok false
  trans : ∀ a b c, o.le a b = ok true → o.le b c = ok true → o.le a c = ok true
  antisymm : ∀ a b, o.le a b = ok true → o.le b a = ok true → a = b

/-- `L`'s `==` is false for different values. -/
def EqModel {L : Type} (e : core.cmp.PartialEq L L) : Prop := ∀ a b, a ≠ b → e.eq a b = ok false

/-- `L`'s `clone` returns its argument. -/
def CloneIsId {L : Type} (c : core.clone.Clone L) : Prop := ∀ a, c.clone a = ok a

/-- `ls` is sorted by `<=`. -/
def SortedLe {L : Type} (o : core.cmp.PartialOrd L L) (ls : List L) : Prop :=
  ∀ j k (hjk : j < k) (hk : k < ls.length), o.le (ls[j]'(by omega)) ls[k] = ok true

/-- `bcs::to_bytes` is injective on the values it serializes. -/
def BcsInjective {L : Type} (ser : serde_core.ser.Serialize L) : Prop :=
  ∀ a b v w, bcs.ser.to_bytes ser a = ok (.Ok v) → bcs.ser.to_bytes ser b = ok (.Ok w) →
    v.val = w.val → a = b

/-- `bcs::to_bytes` returns, `Ok` or `Err`, on every value. -/
def BcsReturns {L : Type} (ser : serde_core.ser.Serialize L) : Prop :=
  ∀ a, ∃ r, bcs.ser.to_bytes ser a = ok r

/-! ## The standard library -/

/-- `<[A]>::partition_point(f)`, for a predicate `f` that is true exactly at the indices below
`p` and does not change its state, returns `p`. -/
def PartitionPointSpec : Prop :=
  ∀ {A P : Type} (f : core.ops.function.FnMut P A Bool) (s : Slice A) (c : P) (p : Nat),
    p ≤ s.length → (∀ k (hk : k < s.length), f.call_mut c (s.val[k]'hk) = ok (decide (k < p), c)) →
    ∃ r : Usize, core.slice.Slice.partition_point f s c = ok r ∧ r.val = p

end MerkleProofs
