-- THIS FILE IS AI-ONLY
import bulletproofspp.Generated.Funs
import Mathlib.Tactic

/-!
What the proofs assume about `RistrettoScalar`, whose functions are opaque in the translation.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

/-- `RistrettoScalar` as a field `F`: its operations return, and `φ` maps them to `F`'s. `==`
is equality in `F`, so `φ` is injective up to what the code can observe. -/
structure ScalarModel (F : Type) [Field F] [DecidableEq F] (φ : groups.ristretto255.RistrettoScalar → F) : Prop where
  zero : ∃ z, groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsGroupElement.zero = ok z ∧
    φ z = 0
  one : ∃ o, groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsGroupElement.generator =
    ok o ∧ φ o = 1
  add : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddRistrettoScalarRistrettoScalar.add
      a b = ok c ∧ φ c = φ a + φ b
  mul : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulRistrettoScalarRistrettoScalar.mul
      a b = ok c ∧ φ c = φ a * φ b
  add_assign : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddAssignRistrettoScalar.add_assign
      a b = ok c ∧ φ c = φ a + φ b
  mul_assign : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulAssignRistrettoScalar.mul_assign
      a b = ok c ∧ φ c = φ a * φ b
  add_ref : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddShared0RistrettoScalarRistrettoScalar.add
      a b = ok c ∧ φ c = φ a + φ b
  neg : ∀ a, ∃ c, groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithNegRistrettoScalar.neg a =
    ok c ∧ φ c = -φ a
  sub : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithSubRistrettoScalarRistrettoScalar.sub
      a b = ok c ∧ φ c = φ a - φ b
  eq : ∀ a b, groups.ristretto255.RistrettoScalar.Insts.CoreCmpPartialEqRistrettoScalar.eq a b =
    ok (decide (φ a = φ b))
  clone : ∀ a, groups.ristretto255.RistrettoScalar.Insts.CoreCloneClone.clone a = ok a
  from_u64 : ∀ x : U64, ∃ s, groups.ristretto255.RistrettoScalar.Insts.CoreConvertFrom.from
    curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64 x = ok s ∧ φ s = (x.val : F)
  inverse_zero : ∀ a, φ a = 0 →
    groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.inverse a =
      ok (.Err .InvalidInput)
  inverse : ∀ a, φ a ≠ 0 → ∃ b,
    groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.inverse a = ok (.Ok b) ∧
      φ b = (φ a)⁻¹

namespace ScalarModel

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F} (hs : ScalarModel F φ)

local notation "S" => groups.ristretto255.RistrettoScalar

/-- What `zero` returns. -/
noncomputable def z : S := hs.zero.choose
/-- What `generator` returns. -/
noncomputable def o : S := hs.one.choose
/-- What `a + b` returns. -/
noncomputable def addF (a b : S) : S := (hs.add a b).choose
/-- What `a * b` returns. -/
noncomputable def mulF (a b : S) : S := (hs.mul a b).choose
/-- What `a += b` returns. -/
noncomputable def addAF (a b : S) : S := (hs.add_assign a b).choose
/-- What `a *= b` returns. -/
noncomputable def mulAF (a b : S) : S := (hs.mul_assign a b).choose
/-- What `a + &b` returns. -/
noncomputable def addRF (a b : S) : S := (hs.add_ref a b).choose
/-- What `a - b` returns. -/
noncomputable def subF (a b : S) : S := (hs.sub a b).choose
/-- What `-a` returns. -/
noncomputable def negF (a : S) : S := (hs.neg a).choose
/-- What `RistrettoScalar::from(x)` returns. -/
noncomputable def fromF (x : U64) : S := (hs.from_u64 x).choose

include hs

lemma zero_eq : groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsGroupElement.zero =
    ok hs.z := hs.zero.choose_spec.1
@[simp] lemma φ_z : φ hs.z = 0 := hs.zero.choose_spec.2
lemma one_eq : groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsGroupElement.generator =
    ok hs.o := hs.one.choose_spec.1
@[simp] lemma φ_o : φ hs.o = 1 := hs.one.choose_spec.2
lemma add_eq (a b : S) :
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddRistrettoScalarRistrettoScalar.add
      a b = ok (hs.addF a b) := (hs.add a b).choose_spec.1
@[simp] lemma φ_addF (a b : S) : φ (hs.addF a b) = φ a + φ b := (hs.add a b).choose_spec.2
lemma mul_eq (a b : S) :
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulRistrettoScalarRistrettoScalar.mul
      a b = ok (hs.mulF a b) := (hs.mul a b).choose_spec.1
@[simp] lemma φ_mulF (a b : S) : φ (hs.mulF a b) = φ a * φ b := (hs.mul a b).choose_spec.2
lemma add_assign_eq (a b : S) :
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddAssignRistrettoScalar.add_assign
      a b = ok (hs.addAF a b) := (hs.add_assign a b).choose_spec.1
@[simp] lemma φ_addAF (a b : S) : φ (hs.addAF a b) = φ a + φ b :=
  (hs.add_assign a b).choose_spec.2
lemma mul_assign_eq (a b : S) :
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulAssignRistrettoScalar.mul_assign
      a b = ok (hs.mulAF a b) := (hs.mul_assign a b).choose_spec.1
@[simp] lemma φ_mulAF (a b : S) : φ (hs.mulAF a b) = φ a * φ b :=
  (hs.mul_assign a b).choose_spec.2
lemma add_ref_eq (a b : S) :
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddShared0RistrettoScalarRistrettoScalar.add
      a b = ok (hs.addRF a b) := (hs.add_ref a b).choose_spec.1
@[simp] lemma φ_addRF (a b : S) : φ (hs.addRF a b) = φ a + φ b := (hs.add_ref a b).choose_spec.2
lemma sub_eq (a b : S) :
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithSubRistrettoScalarRistrettoScalar.sub
      a b = ok (hs.subF a b) := (hs.sub a b).choose_spec.1
@[simp] lemma φ_subF (a b : S) : φ (hs.subF a b) = φ a - φ b := (hs.sub a b).choose_spec.2
lemma neg_eq (a : S) : groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithNegRistrettoScalar.neg
    a = ok (hs.negF a) := (hs.neg a).choose_spec.1
@[simp] lemma φ_negF (a : S) : φ (hs.negF a) = -φ a := (hs.neg a).choose_spec.2
lemma from_u64_eq (x : U64) :
    groups.ristretto255.RistrettoScalar.Insts.CoreConvertFrom.from
      curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64 x = ok (hs.fromF x) :=
  (hs.from_u64 x).choose_spec.1
@[simp] lemma φ_fromF (x : U64) : φ (hs.fromF x) = (x.val : F) := (hs.from_u64 x).choose_spec.2

end ScalarModel

end BpppProofs
