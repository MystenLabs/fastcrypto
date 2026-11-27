-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.Crs

/-!
# `util.rs`
-/

namespace Bppp

variable {F : Type} [Field F] [DecidableEq F]

/-- `one`. -/
def one : F := 1

/-- `inner_product`. -/
def inner_product (a b : List F) : F :=
  (List.zip a b).foldl (fun acc (x, y) => acc + x * y) 0

/-- `weighted_inner_product`. -/
def weighted_inner_product (a b : List F) (mu : F) : F :=
  ((List.zip a b).foldl (fun (weight, result) (x, y) => (weight * mu, result + x * y * weight))
    (mu, 0)).2

/-- `weighted_norm`. -/
def weighted_norm (n : List F) (mu : F) : F := weighted_inner_product n n mu

/-- `to_scalars`. -/
def to_scalars (xs : List ℕ) : List F := xs.map (Nat.cast : ℕ → F)

/-- `power_vector`. -/
def power_vector (x : F) (n : ℕ) : List F :=
  ((List.range n).foldl (fun (v, cur) _ => (v ++ [cur], cur * x)) ([], one)).1

/-- `vec_add`. -/
def vec_add (a b : List F) : List F := List.zipWith (· + ·) a b

/-- `vec_scalar_mul`. -/
def vec_scalar_mul (s : F) (a : List F) : List F := a.map (s * ·)

/-- `hadamard`. -/
def hadamard (a b : List F) : List F := List.zipWith (· * ·) a b

/-- `pad_to`, which resizes like `Vec::resize`. -/
def pad_to (v : List F) (n : ℕ) : List F := (v ++ List.replicate (n - v.length) 0).take n

/-- `batch_invert`. -/
def batch_invert (inputs : List F) : Result (List F) := do
  let (pre, acc) := inputs.foldl (fun (pre, acc) x => (pre ++ [acc], acc * x)) ([], one)
  let suffix_inv ← inverse acc
  let (out, _) := (List.zip inputs pre).foldr
    (fun (x, p) (out, suffix_inv) => (suffix_inv * p :: out, suffix_inv * x)) ([], suffix_inv)
  pure out

/-- `to_digits`, for a `u64` value. -/
def to_digits (value d : ℕ) : List ℕ :=
  let bits := Nat.log2 BASE
  (List.range d).map fun t => (value >>> (bits * t)) &&& (BASE - 1)

/-- `multiplicities`. -/
def multiplicities (digits : List ℕ) : List ℕ :=
  digits.foldl (fun m d => if d > 0 then m.modify (d - 1) (· + 1) else m)
    (List.replicate (BASE - 1) 0)

end Bppp
