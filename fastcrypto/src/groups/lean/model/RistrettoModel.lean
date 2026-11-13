/-!
An executable model of `fastcrypto::groups::ristretto255`, following RFC 9496.

Points are extended twisted Edwards coordinates `(X : Y : Z : T)` over `Fe = Fin p`; two of them
are the same group element when they have the same encoding. Scalars are `Fin L`. The `@[export]`
functions at the end are what the Rust tests call; they pass points and scalars as 64-character
hex strings of their little-endian bytes, the encoding of `to_byte_array`.
-/

namespace RistrettoModel

/-- The field characteristic. -/
def p : Nat := 2 ^ 255 - 19

/-- The group order. -/
def L : Nat := 2 ^ 252 + 27742317777372353535851937790883648493

instance : NeZero p := ⟨by decide⟩
instance : NeZero L := ⟨by decide⟩

/-- The field of definition of Curve25519. -/
abbrev Fe := Fin p

/-- `RistrettoScalar`. -/
abbrev Scalar := Fin L

/-- `x^e` by square-and-multiply. -/
def pow {n : Nat} [NeZero n] (x : Fin n) (e : Nat) : Fin n :=
  if e = 0 then 1
  else
    let y := pow (x * x) (e / 2)
    if e % 2 = 1 then x * y else y
termination_by e
decreasing_by omega

/-! ## Constants (RFC 9496 §4.1) -/

/-- The curve coefficient `d = -121665 / 121666`. -/
def D : Fe := 37095705934669439343138083508754565189542113879843219016388785533085940283555

def SQRT_M1 : Fe := 19681161376707505956807079304988542015446066515923890162744021073123829784752

def SQRT_AD_MINUS_ONE : Fe :=
  25063068953384623474111414158702152701244531502492656460079210482610430750235

def INVSQRT_A_MINUS_D : Fe :=
  54469307008909316920995813868745141605393597292927456921205312896311721017578

def ONE_MINUS_D_SQ : Fe :=
  1159843021668779879193775521855586647937357759715417654439879720876111806838

def D_MINUS_ONE_SQ : Fe :=
  40440834346308536858101042469323190826248399146238708352240133220865137265952

/-! ## Field helpers (RFC 9496 §4.2) -/

/-- `IS_NEGATIVE`: the low bit of the canonical representative. -/
def isNegative (x : Fe) : Bool := x.val % 2 == 1

/-- `CT_ABS`. -/
def abs (x : Fe) : Fe := if isNegative x then -x else x

/-- `SQRT_RATIO_M1`: `(true, √(u/v))` if `u/v` is a square, otherwise `(false, √(SQRT_M1 · u/v))`,
the root being non-negative. -/
def sqrtRatioM1 (u v : Fe) : Bool × Fe :=
  let r := (u * v ^ 3) * pow (u * v ^ 7) ((p - 5) / 8)
  let check := v * (r * r)
  let correctSign := check == u
  let flippedSign := check == -u
  let flippedSignI := check == -u * SQRT_M1
  let r := if flippedSign || flippedSignI then SQRT_M1 * r else r
  (correctSign || flippedSign, abs r)

/-! ## The group -/

/-- `RistrettoPoint`, in extended coordinates: `x = X/Z`, `y = Y/Z`, `X Y = Z T`. -/
structure Point where
  X : Fe
  Y : Fe
  Z : Fe
  T : Fe

/-- `GroupElement::zero`. -/
def zero : Point := ⟨0, 1, 1, 0⟩

/-- `GroupElement::generator`: the Ed25519 base point, `y = 4/5` with `x` even. -/
def generator : Point :=
  let x : Fe := 15112221349535400772501151409588531511454012693041857206046113283949847762202
  let y : Fe := 46316835694926478169428394003475163141307993866256225615783033603165251855960
  ⟨x, y, 1, x * y⟩

/-- The complete addition law for `a = -1` (Hisil, Wong, Carter, Dawson 2008, §4.2). -/
def add (P Q : Point) : Point :=
  let a := (P.Y - P.X) * (Q.Y - Q.X)
  let b := (P.Y + P.X) * (Q.Y + Q.X)
  let c := P.T * (2 * D) * Q.T
  let d := P.Z * 2 * Q.Z
  let e := b - a
  let f := d - c
  let g := d + c
  let h := b + a
  ⟨e * f, g * h, f * g, e * h⟩

def neg (P : Point) : Point := ⟨-P.X, P.Y, P.Z, -P.T⟩

def sub (P Q : Point) : Point := add P (neg Q)

/-- `Doubling::double`. -/
def double (P : Point) : Point := add P P

/-- `e • P` by double-and-add. -/
def nsmul (P : Point) (e : Nat) : Point :=
  if e = 0 then zero
  else
    let Q := nsmul (double P) (e / 2)
    if e % 2 = 1 then add P Q else Q
termination_by e
decreasing_by omega

/-- `Mul<RistrettoScalar> for RistrettoPoint`. -/
def smul (P : Point) (k : Scalar) : Point := nsmul P k.val

/-- `MultiScalarMul::multi_scalar_mul`. -/
def msm (ks : Array Scalar) (Ps : Array Point) : Except String Point :=
  if ks.size ≠ Ps.size then .error "InvalidInput"
  else .ok ((ks.zip Ps).foldl (fun acc (k, P) => add acc (smul P k)) zero)

/-! ## Encoding (RFC 9496 §4.3) -/

/-- `ENCODE`, §4.3.2, as the field element `s`. -/
def encode (P : Point) : Fe :=
  let u1 := (P.Z + P.Y) * (P.Z - P.Y)
  let u2 := P.X * P.Y
  let invsqrt := (sqrtRatioM1 1 (u1 * (u2 * u2))).2
  let den1 := invsqrt * u1
  let den2 := invsqrt * u2
  let zInv := den1 * den2 * P.T
  let rotate := isNegative (P.T * zInv)
  let x := if rotate then P.Y * SQRT_M1 else P.X
  let y := if rotate then P.X * SQRT_M1 else P.Y
  let denInv := if rotate then den1 * INVSQRT_A_MINUS_D else den2
  let y := if isNegative (x * zInv) then -y else y
  abs (denInv * (P.Z - y))

/-- `DECODE`, §4.3.1: an error if `s` is not below `p`, is negative, or is not a valid encoding. -/
def decode (n : Nat) : Except String Point :=
  if h : n < p then
    let s : Fe := ⟨n, h⟩
    if isNegative s then .error "InvalidInput"
    else
      let ss := s * s
      let u1 := 1 - ss
      let u2 := 1 + ss
      let u2Sqr := u2 * u2
      let v := -(D * (u1 * u1)) - u2Sqr
      let (wasSquare, invsqrt) := sqrtRatioM1 1 (v * u2Sqr)
      let denX := invsqrt * u2
      let denY := invsqrt * denX * v
      let x := abs (2 * s * denX)
      let y := u1 * denY
      let t := x * y
      if !wasSquare || isNegative t || y == 0 then .error "InvalidInput"
      else .ok ⟨x, y, 1, t⟩
  else .error "InvalidInput"

/-- `MAP`, §4.3.4. -/
def map (t : Fe) : Point :=
  let r := SQRT_M1 * (t * t)
  let u := (r + 1) * ONE_MINUS_D_SQ
  let v := (-1 - r * D) * (r + D)
  let (wasSquare, s) := sqrtRatioM1 u v
  let s := if wasSquare then s else -(abs (s * t))
  let c : Fe := if wasSquare then -1 else r
  let n := c * (r - 1) * D_MINUS_ONE_SQ - v
  let w0 := 2 * s * v
  let w1 := n * SQRT_AD_MINUS_ONE
  let w2 := 1 - s * s
  let w3 := 1 + s * s
  ⟨w0 * w3, w2 * w1, w1 * w3, w0 * w2⟩

/-- `RistrettoPoint::from_uniform_bytes`, §4.3.4, on the two halves as little-endian integers. -/
def fromUniform (r0 r1 : Nat) : Point :=
  add (map (Fin.ofNat p (r0 % 2 ^ 255))) (map (Fin.ofNat p (r1 % 2 ^ 255)))

/-! ## Scalars -/

/-- `Scalar::inverse`: `x^(L - 2)` (Fermat), and an error for zero. -/
def inverse (x : Scalar) : Except String Scalar :=
  if x = 0 then .error "InvalidInput" else .ok (pow x (L - 2))

/-- `ToFromByteArray::from_byte_array`: an error if the integer is not below `L`. -/
def scalarOfNat (n : Nat) : Except String Scalar :=
  if h : n < L then .ok ⟨n, h⟩ else .error "InvalidInput"

/-! ## Hex encoding -/

def hexDigit (c : Char) : Except String Nat :=
  if '0' ≤ c ∧ c ≤ '9' then .ok (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then .ok (c.toNat - 'a'.toNat + 10)
  else .error s!"bad hex digit {c}"

/-- The bytes of a hex string, in order. -/
def bytesOfChars : List Char → Except String (List Nat)
  | [] => .ok []
  | a :: b :: rest => do
    let hi ← hexDigit a
    let lo ← hexDigit b
    return (16 * hi + lo) :: (← bytesOfChars rest)
  | _ => .error "odd hex length"

/-- The little-endian integer of `bytes` hexadecimal bytes. -/
def natOfHex (bytes : Nat) (s : String) : Except String Nat := do
  let bs ← bytesOfChars s.toList
  if bs.length ≠ bytes then throw s!"bad length: {s}"
  return bs.foldr (fun b acc => b + 256 * acc) 0

/-- 32 little-endian bytes in hex. -/
def hexOfNat (n : Nat) : String :=
  let digit (k : Nat) := Nat.digitChar (n / 16 ^ k % 16)
  String.ofList ((List.range 32).flatMap fun i => [digit (2 * i + 1), digit (2 * i)])

def pointOfHex (s : String) : Except String Point := do decode (← natOfHex 32 s)

def scalarOfHex (s : String) : Except String Scalar := do scalarOfNat (← natOfHex 32 s)

def pointToHex (P : Point) : String := hexOfNat (encode P).val

def scalarToHex (x : Scalar) : String := hexOfNat x.val

/-! ## Exports for the Rust tests -/

@[export ristretto_model_point_zero]
def exportPointZero (_ : UInt64) : String := pointToHex zero

@[export ristretto_model_point_generator]
def exportPointGenerator (_ : UInt64) : String := pointToHex generator

/-- Decodes and re-encodes. -/
@[export ristretto_model_point_decode]
def exportPointDecode (s : String) : Except String String :=
  return pointToHex (← pointOfHex s)

@[export ristretto_model_point_add]
def exportPointAdd (a b : String) : Except String String :=
  return pointToHex (add (← pointOfHex a) (← pointOfHex b))

@[export ristretto_model_point_sub]
def exportPointSub (a b : String) : Except String String :=
  return pointToHex (sub (← pointOfHex a) (← pointOfHex b))

@[export ristretto_model_point_neg]
def exportPointNeg (a : String) : Except String String :=
  return pointToHex (neg (← pointOfHex a))

@[export ristretto_model_point_double]
def exportPointDouble (a : String) : Except String String :=
  return pointToHex (double (← pointOfHex a))

@[export ristretto_model_point_mul]
def exportPointMul (a k : String) : Except String String :=
  return pointToHex (smul (← pointOfHex a) (← scalarOfHex k))

/-- `Div<RistrettoScalar> for RistrettoPoint`. -/
@[export ristretto_model_point_div]
def exportPointDiv (a k : String) : Except String String :=
  return pointToHex (smul (← pointOfHex a) (← inverse (← scalarOfHex k)))

@[export ristretto_model_point_msm]
def exportPointMsm (ks ps : Array String) : Except String String :=
  return pointToHex (← msm (← ks.mapM scalarOfHex) (← ps.mapM pointOfHex))

@[export ristretto_model_point_from_uniform]
def exportPointFromUniform (r0 r1 : String) : Except String String :=
  return pointToHex (fromUniform (← natOfHex 32 r0) (← natOfHex 32 r1))

/-- Parses and re-encodes. -/
@[export ristretto_model_scalar_decode]
def exportScalarDecode (s : String) : Except String String :=
  return scalarToHex (← scalarOfHex s)

@[export ristretto_model_scalar_add]
def exportScalarAdd (a b : String) : Except String String :=
  return scalarToHex ((← scalarOfHex a) + (← scalarOfHex b))

@[export ristretto_model_scalar_sub]
def exportScalarSub (a b : String) : Except String String :=
  return scalarToHex ((← scalarOfHex a) - (← scalarOfHex b))

@[export ristretto_model_scalar_neg]
def exportScalarNeg (a : String) : Except String String :=
  return scalarToHex (-(← scalarOfHex a))

@[export ristretto_model_scalar_mul]
def exportScalarMul (a b : String) : Except String String :=
  return scalarToHex ((← scalarOfHex a) * (← scalarOfHex b))

@[export ristretto_model_scalar_inverse]
def exportScalarInverse (a : String) : Except String String :=
  return scalarToHex (← inverse (← scalarOfHex a))

/-- `RistrettoScalar::from_bytes_mod_order`. -/
@[export ristretto_model_scalar_mod_order]
def exportScalarModOrder (a : String) : Except String String :=
  return scalarToHex (Fin.ofNat L (← natOfHex 32 a))

/-- `RistrettoScalar::from_bytes_mod_order_wide`, on 64 bytes. -/
@[export ristretto_model_scalar_mod_order_wide]
def exportScalarModOrderWide (a : String) : Except String String :=
  return scalarToHex (Fin.ofNat L (← natOfHex 64 a))

end RistrettoModel
