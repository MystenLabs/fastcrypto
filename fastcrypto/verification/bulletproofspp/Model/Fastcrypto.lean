-- THIS FILE IS AI-ONLY
import Mathlib.Tactic

/-!
# The parts of fastcrypto the BP++ modules use

Errors (`error.rs`), scalar inversion and multi-scalar multiplication (`groups`), Pedersen
commitments and ranges (`pedersen.rs`). Scalars are any field `F` and points any `F`-module `E`;
`Vec<T>` is `List T`, and `FastCryptoResult<T>` is `Result T`.
-/

namespace Bppp

/-- `FastCryptoError`, restricted to the variants the BP++ modules return. -/
inductive Error
  | InvalidInput
  | InvalidProof
  | GeneralOpaqueError
  deriving DecidableEq, Repr

/-- `FastCryptoResult<T>`. -/
abbrev Result (α : Type) := Except Error α

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E]

/-- The value `head!` reads on an empty `Vec`, where Rust panics. -/
instance : Inhabited F := ⟨0⟩

/-- `Scalar::inverse`. -/
def inverse (x : F) : Result F := if x = 0 then .error .InvalidInput else .ok x⁻¹

/-- `MultiScalarMul::multi_scalar_mul`. -/
def multi_scalar_mul (scalars : List F) (points : List E) : Result E :=
  if scalars.length ≠ points.length then .error .InvalidInput
  else .ok (List.zipWith (· • ·) scalars points).sum

/-- `MixedMultiScalarMul::mixed_multi_scalar_mul` over the precomputed `static_points`. -/
def mixed_multi_scalar_mul (static_points : List E) (static_scalars dynamic_scalars : List F)
    (dynamic_points : List E) : Result E :=
  if static_scalars.length ≠ static_points.length ∨ dynamic_scalars.length ≠ dynamic_points.length
  then .error .InvalidInput
  else .ok ((List.zipWith (· • ·) static_scalars static_points).sum +
    (List.zipWith (· • ·) dynamic_scalars dynamic_points).sum)

/-- `pedersen::Range`. -/
inductive Range
  | Bits8
  | Bits16
  | Bits32
  | Bits64

namespace Range

/-- `Range::bits`. -/
def bits : Range → ℕ
  | Bits8 => 8
  | Bits16 => 16
  | Bits32 => 32
  | Bits64 => 64

/-- `Range::is_in_range`, for a `u64` value. -/
def is_in_range (r : Range) (value : ℕ) : Bool := value ≤ 2 ^ r.bits - 1

end Range

/-- `pedersen::PedersenCommitment`. -/
structure PedersenCommitment (E : Type) where
  point : E

/-- `PedersenCommitment::new` under the Pedersen bases `pedersen::G`, `pedersen::H`:
`value*H + blinding*G`. -/
def PedersenCommitment.new (G H : E) (value blinding : F) : PedersenCommitment E :=
  ⟨value • H + blinding • G⟩

end Bppp
