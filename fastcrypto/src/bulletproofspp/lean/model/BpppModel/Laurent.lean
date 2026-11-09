import BpppModel.Util

/-!
# `laurent.rs`
-/

namespace Bppp

variable {F : Type} [Add F] [Mul F] [Sub F] [Neg F] [Zero F] [One F] [Inv F] [NatCast F] [OfNat F 2] [DecidableEq F]

/-- `Coefficient`. -/
class Coefficient (F : outParam Type) (C : Type) where
  add : C → C → C
  scale : C → F → C

instance : Coefficient F F where
  add x y := x + y
  scale x s := x * s

instance : Coefficient F (List F) where
  add := vec_add
  scale x s := vec_scalar_mul s x

/-- `Laurent<C>`: `sum_i coeffs[i]*T^{low+i}`. -/
structure Laurent (C : Type) where
  low : Int
  coeffs : List C

namespace Laurent

variable {C : Type} [Inhabited C] [Coefficient F C]

instance : Inhabited (Laurent C) := ⟨⟨0, [default]⟩⟩

/-- `Laurent::new`. -/
def new (low : Int) (coeffs : List C) : Laurent C := ⟨low, coeffs⟩

/-- `Laurent::monomial`. -/
def monomial (power : Int) (c : C) : Laurent C := new power [c]

/-- `Laurent::coeff`. -/
def coeff (self : Laurent C) (power : Int) : C :=
  if 0 ≤ power - self.low then (self.coeffs[(power - self.low).toNat]?).getD
    (Coefficient.scale self.coeffs.head! (0 : F))
  else Coefficient.scale self.coeffs.head! (0 : F)

/-- `Laurent::degree`. -/
def degree (self : Laurent C) : Int := self.low + self.coeffs.length - 1

/-- `Laurent::scale`. -/
def scale (self : Laurent C) (s : F) : Laurent C := new self.low (self.coeffs.map (Coefficient.scale · s))

/-- `Laurent::eval`. -/
def eval (self : Laurent C) (x : F) : Result C := do
  let base ← if self.low < 0 then inverse x else pure x
  let x_pow := (List.range self.low.natAbs).foldl (fun acc _ => acc * base) one
  let (result, _) := self.coeffs.tail.foldl
    (fun (result, x_pow) c => (Coefficient.add result (Coefficient.scale c (x_pow * x)), x_pow * x))
    (Coefficient.scale self.coeffs.head! x_pow, x_pow)
  pure result

/-- `Laurent + Laurent`. -/
def add (self other : Laurent C) : Laurent C :=
  let low := min self.low other.low
  new low ((List.range (max self.degree other.degree - low + 1).toNat).map fun (i : Nat) =>
    Coefficient.add (self.coeff (low + i)) (other.coeff (low + i)))

instance : Add (Laurent C) := ⟨add⟩

/-- `Laurent - Laurent`. -/
def sub (self other : Laurent C) : Laurent C := self + other.scale (-one : F)

instance : Sub (Laurent C) := ⟨sub⟩

/-- `Laurent::from_terms`. -/
def from_terms : List (Int × C) → Laurent C
  | [] => panic! "at least one term"
  | (p, c) :: terms => terms.foldl (fun acc (p, c) => acc + monomial p c) (monomial p c)

end Laurent

namespace Laurent

/-- `Laurent<Vec<S>>::inner_product`. -/
def inner_product (self other : Laurent (List F)) : Laurent F :=
  let coeffs := self.coeffs.zipIdx.foldl (fun coeffs (a, i) =>
      other.coeffs.zipIdx.foldl (fun coeffs (b, j) =>
        coeffs.modify (i + j) (· + Bppp.inner_product a b)) coeffs)
    (List.replicate (self.coeffs.length + other.coeffs.length - 1) 0)
  new (self.low + other.low) coeffs

/-- `Laurent<Vec<S>>::weighted_inner_product`. -/
def weighted_inner_product (self other : Laurent (List F)) (weights : List F) : Laurent F :=
  let weighted := new self.low (self.coeffs.map fun a => hadamard a weights)
  weighted.inner_product other

end Laurent

end Bppp
