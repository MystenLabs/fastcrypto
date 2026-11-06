/-
The model of `polynomial.rs` (`ShamirModel`) as Mathlib polynomials.

`ShamirModel.Scalar` is `Fin r`, which is `ZMod r` by definition, and the model's `+`, `-`, `*`
are Mathlib's. The theorems that need a field assume that `r` is prime (`[Fact r.Prime]`).
-/
import Mathlib
import ShamirModel

namespace Shamir

open ShamirModel Polynomial

/-- The BLS12-381 scalar field: the model's `Fin r`. -/
abbrev F := Scalar

/-- `Fin r` is `ZMod r`, with the same `+`, `-` and `*` as the model. -/
instance : CommRing F := inferInstanceAs (CommRing (ZMod r))

/-- A field when `r` is prime. -/
instance [Fact r.Prime] : Field F := inferInstanceAs (Field (ZMod r))

deriving instance DecidableEq for ShamirModel.Eval

/-- The polynomial `c₀ + c₁X + ⋯` with coefficients `cs`. -/
noncomputable def toPoly : List F → F[X]
  | [] => 0
  | c :: cs => C c + X * toPoly cs

lemma coeff_toPoly (cs : List F) (m : ℕ) : (toPoly cs).coeff m = cs.getD m 0 := by
  induction cs generalizing m with
  | nil => simp [toPoly]
  | cons c cs ih =>
    cases m with
    | zero => simp [toPoly]
    | succ m => simp [toPoly, coeff_X_mul, ih]

lemma degree_toPoly_lt (cs : List F) : (toPoly cs).degree < cs.length := by
  rw [degree_lt_iff_coeff_zero]
  intro m hm
  rw [coeff_toPoly, List.getD_eq_default _ _ (by exact_mod_cast hm)]

lemma eval_toPoly (cs : List F) (x : F) :
    (toPoly cs).eval x = cs.foldr (fun c sum => sum * x + c) 0 := by
  induction cs with
  | nil => simp [toPoly]
  | cons c cs ih => simp [toPoly, ih]; ring

/-- `Poly::eval` is evaluation of `toPoly`. -/
lemma eval_eq (p : Poly) (i : ℕ) :
    (ShamirModel.eval p i).value = (toPoly p.toList).eval (i : F) := by
  rw [eval_toPoly, ShamirModel.eval, ← Array.foldr_toList]
  rfl

lemma eval_index (p : Poly) (i : ℕ) : (ShamirModel.eval p i).index = i := rfl

/-- `Poly::c0` is the constant coefficient. -/
lemma c0_eq (p : Poly) : c0 p = (toPoly p.toList).coeff 0 := by
  rw [coeff_toPoly, ShamirModel.c0, Array.getD_eq_getD_getElem?]
  simp [List.getD_eq_getElem?_getD]

/-- Coefficient-wise addition of lists, keeping the tail of the longer one. -/
def addL : List F → List F → List F
  | [], q => q
  | p, [] => p
  | a :: p, b :: q => (a + b) :: addL p q

lemma addL_eq (p q : List F) :
    List.zipWith (· + ·) p q ++ (if p.length < q.length then q.drop p.length else p.drop q.length) =
      addL p q := by
  induction p generalizing q with
  | nil => cases q <;> simp [addL]
  | cons a p ih =>
    cases q with
    | nil => simp [addL]
    | cons b q => simp [addL, ← ih]

lemma add_toList (p q : Poly) : (ShamirModel.add p q).toList = addL p.toList q.toList := by
  rw [← addL_eq, ShamirModel.add, Array.toList_append, Array.toList_zipWith]
  congr 1
  by_cases h : p.size < q.size <;>
    simp [h, Array.toList_extract, List.take_of_length_le]

lemma toPoly_addL (p q : List F) : toPoly (addL p q) = toPoly p + toPoly q := by
  induction p generalizing q with
  | nil => cases q <;> simp [addL, toPoly]
  | cons a p ih =>
    cases q with
    | nil => simp [addL, toPoly]
    | cons b q => simp [addL, toPoly, ih]; ring

lemma length_addL (p q : List F) : (addL p q).length = max p.length q.length := by
  induction p generalizing q with
  | nil => cases q <;> simp [addL]
  | cons a p ih => cases q <;> simp [addL, ih, Nat.succ_max_succ]

/-- `impl Add for Poly` is addition of polynomials. -/
lemma toPoly_add (p q : Poly) :
    toPoly (ShamirModel.add p q).toList = toPoly p.toList + toPoly q.toList := by
  rw [add_toList, toPoly_addL]

lemma size_add (p q : Poly) : (ShamirModel.add p q).size = max p.size q.size := by
  rw [← Array.length_toList, add_toList, length_addL]; simp

end Shamir
