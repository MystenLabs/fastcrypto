/-!
# A model of `fastcrypto_tbls::polynomial::Poly` over BLS12-381 scalars

The functions mirror `polynomial.rs` one by one. Scalars are `Fin r` for the BLS12-381 scalar order
`r`, so that the arithmetic is core Lean's (in Mathlib, `ZMod r` is definitionally `Fin r`). The
`@[export]` functions at the end are what the Rust property tests call; they pass scalars as
64-character big-endian hex strings, the encoding of `Scalar::to_byte_array`.
-/

namespace ShamirModel

/-- The order of the BLS12-381 scalar field. -/
def r : Nat := 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

instance : NeZero r := ⟨by decide⟩

/-- `fastcrypto::groups::bls12381::Scalar`. -/
abbrev Scalar := Fin r

/-- `x^e` by square-and-multiply. -/
def pow (x : Scalar) (e : Nat) : Scalar :=
  if e = 0 then 1
  else
    let y := pow (x * x) (e / 2)
    if e % 2 = 1 then x * y else y
termination_by e
decreasing_by omega

/-- `Scalar::inverse`: `x^(r - 2)` (Fermat), and an error for zero. -/
def inverse (x : Scalar) : Except String Scalar :=
  if x = 0 then .error "InvalidInput" else .ok (pow x (r - 2))

/-- `fastcrypto_tbls::polynomial::Poly`: the coefficients, constant term first. -/
abbrev Poly := Array Scalar

/-- `fastcrypto_tbls::polynomial::Eval`. -/
structure Eval where
  index : Nat
  value : Scalar

/-- `Poly::degree_bound`. -/
def degree_bound (p : Poly) : Nat := p.size - 1

/-- `Poly::c0`. -/
def c0 (p : Poly) : Scalar := p.getD 0 0

/-- `Poly::eval`, by Horner's method. -/
def eval (p : Poly) (i : Nat) : Eval :=
  let xi : Scalar := Fin.ofNat r i
  ⟨i, p.foldr (fun coeff sum => sum * xi + coeff) 0⟩

/-- `impl Add<&Poly> for Poly`: add coefficient-wise, keeping the tail of the longer polynomial. -/
def add (p q : Poly) : Poly :=
  (p.zipWith (· + ·) q) ++ (if p.size < q.size then q.extract p.size q.size else p.extract q.size p.size)

/-- The Lagrange coefficient `λ_i = ∏_{j ≠ i} j / (j - i)` at zero, for the indices `idx`. -/
def lagrange (idx : List Nat) (i : Nat) : Except String Scalar := do
  let others := (idx.filter (· ≠ i)).map (Fin.ofNat r)
  let den ← inverse ((others.map (· - Fin.ofNat r i)).foldr (· * ·) 1)
  return others.foldr (· * ·) 1 * den

/-- `Poly::recover_c0`: Lagrange interpolation at zero from exactly `t` shares with distinct
indices. -/
def recover_c0 (t : Nat) (shares : List Eval) : Except String Scalar := do
  let idx := shares.map (·.index)
  if !idx.Nodup || idx.length ≠ t || idx.contains 0 then throw "InvalidInput"
  let terms ← shares.mapM fun share => return share.value * (← lagrange idx share.index)
  return terms.foldr (· + ·) 0

/-! ## Encoding -/

def hexDigit (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

/-- A scalar from 64 big-endian hex digits; an error if malformed or not below `r`. -/
def ofHex (s : String) : Except String Scalar := do
  if s.length ≠ 64 then throw s!"bad length: {s}"
  let n ← s.foldl (fun acc c => do
    let a ← acc
    match hexDigit c with
    | some d => pure (16 * a + d)
    | none => throw s!"bad digit in {s}") (pure 0 : Except String Nat)
  if h : n < r then pure ⟨n, h⟩ else throw s!"not reduced: {s}"

/-- 64 big-endian hex digits. -/
def toHex (x : Scalar) : String :=
  let digits := (List.range 64).reverse.map fun k =>
    Nat.digitChar (x.val / 16 ^ k % 16)
  String.ofList digits

def polyOfHex (cs : Array String) : Except String Poly := cs.mapM ofHex

/-! ## Exports for the Rust property tests -/

@[export shamir_model_degree_bound]
def exportDegreeBound (cs : Array String) : Except String UInt64 :=
  return (degree_bound (← polyOfHex cs)).toUInt64

@[export shamir_model_c0]
def exportC0 (cs : Array String) : Except String String :=
  return toHex (c0 (← polyOfHex cs))

@[export shamir_model_eval]
def exportEval (cs : Array String) (i : UInt64) : Except String String :=
  return toHex (eval (← polyOfHex cs) i.toNat).value

@[export shamir_model_add]
def exportAdd (p q : Array String) : Except String (Array String) :=
  return (add (← polyOfHex p) (← polyOfHex q)).map toHex

@[export shamir_model_recover_c0]
def exportRecoverC0 (t : UInt64) (indices : Array UInt64) (values : Array String) :
    Except String String := do
  let vs ← values.mapM ofHex
  let shares := (indices.toList.zip vs.toList).map fun (i, v) => Eval.mk i.toNat v
  return toHex (← recover_c0 t.toNat shares)

end ShamirModel
