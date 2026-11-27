-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.Fastcrypto

/-!
# `crs.rs`

`Generators::new` derives `nm` generators by hash-to-curve and is not modelled: statements take
it as an input function of `nm`.
-/

namespace Bppp

/-- `BASE`. -/
def BASE : ℕ := 16

/-- `H_LEN`. -/
def H_LEN : ℕ := 8

/-- `usize::next_power_of_two`: the least power of two `≥ n`. -/
def next_power_of_two (n : ℕ) : ℕ := 2 ^ Nat.clog 2 n

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E]

variable (E) in
/-- `Generators`, without the precomputed tables. -/
structure Generators where
  g : E
  h_vec : List E
  g_vec : List E

namespace Generators

variable (self : Generators E)

/-- `Generators::msm`: `sigma*G + <l, h_vec> + <n, g_vec> + <dynamic_scalars, dynamic_points>`
when `l` and `n` have the lengths of `h_vec` and `g_vec`. As in Rust, only their total length is
checked. -/
def msm (sigma : F) (l n : List F) (dynamic_scalars : List F) (dynamic_points : List E) :
    Result E :=
  mixed_multi_scalar_mul (self.g :: self.h_vec ++ self.g_vec) (sigma :: l ++ n) dynamic_scalars
    dynamic_points

end Generators

/-- `compatible_with_pedersen_commitments`, for the Pedersen bases `G`, `H`. -/
def compatible_with_pedersen_commitments (G H : E) (gens : Generators E) : Prop :=
  gens.g = H ∧ gens.h_vec[0]? = some G

end Bppp
