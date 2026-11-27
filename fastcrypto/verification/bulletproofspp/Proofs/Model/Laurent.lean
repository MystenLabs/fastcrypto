-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.Laurent
import bulletproofspp.Proofs.Model.Util
import bulletproofspp.Proofs.Spec.Poly

/-!
# Lemmas about `laurent.rs`

A `Laurent<S>` denotes the Laurent polynomial `toPoly`, and a `Laurent<Vec<S>>` the vector of
Laurent polynomials `toPolys`. The operations on `Laurent<Vec<S>>` are only linear when every
coefficient has the same length (`Uniform`).
-/

open Finset LaurentPolynomial

namespace Bppp

variable {F : Type} [Field F] [DecidableEq F]

set_option linter.unusedSectionVars false

namespace Laurent

/-- The Laurent polynomial `sum_i coeffs[i] T^{low+i}`. -/
noncomputable def toPoly (P : Laurent F) : F[T;T⁻¹] :=
  ∑ i ∈ range P.coeffs.length, mono (P.low + i) (P.coeffs.getD i 0)

/-- Entry `k` of `sum_i coeffs[i] T^{low+i}`. -/
noncomputable def toPolys (P : Laurent (List F)) (k : ℕ) : F[T;T⁻¹] :=
  ∑ i ∈ range P.coeffs.length, mono (P.low + i) ((P.coeffs.getD i []).getD k 0)

/-- Every coefficient has length `L`, and there is at least one. -/
def Uniform (L : ℕ) (P : Laurent (List F)) : Prop := P.coeffs ≠ [] ∧ ∀ c ∈ P.coeffs, c.length = L

/-! ## Coefficients -/

lemma coeff_sum_mono (low : ℤ) (n : ℕ) (f : ℕ → F) (p : ℤ) :
    Bppp.coeff p (∑ i ∈ range n, mono (low + i) (f i)) =
      if 0 ≤ p - low ∧ (p - low).toNat < n then f (p - low).toNat else 0 := by
  rw [map_sum]
  simp only [coeff_mono]
  split_ifs with h
  · rw [sum_eq_single_of_mem (p - low).toNat (mem_range.2 h.2)]
    · rw [if_pos (by omega)]
    · intro i _ hi; rw [if_neg (by omega)]
  · refine sum_eq_zero fun i hi => if_neg ?_
    intro he; apply h; simp only [mem_range] at hi; omega

lemma coeff_toPoly (P : Laurent F) (p : ℤ) :
    Bppp.coeff p P.toPoly = if 0 ≤ p - P.low then P.coeffs.getD (p - P.low).toNat 0 else 0 := by
  rw [toPoly, coeff_sum_mono]
  split_ifs with h1 h2 <;> first | rfl | omega |
    exact (getD_eq_zero_of_le (by omega)).symm

lemma coeff_toPolys (P : Laurent (List F)) (k : ℕ) (p : ℤ) :
    Bppp.coeff p (P.toPolys k) =
      if 0 ≤ p - P.low then (P.coeffs.getD (p - P.low).toNat []).getD k 0 else 0 := by
  rw [toPolys, coeff_sum_mono]
  split_ifs with h1 h2 <;> first | rfl | omega |
    rw [List.getD_eq_getElem?_getD (l := P.coeffs), List.getElem?_eq_none (by omega)]; rfl

/-- `Laurent::coeff` reads the coefficient of the denoted polynomial. -/
lemma coeff_eq (P : Laurent F) (p : ℤ) : P.coeff p = Bppp.coeff p P.toPoly := by
  rw [coeff_toPoly, Laurent.coeff]
  have h0 : (Coefficient.scale P.coeffs.head! (0 : F) : F) = 0 := mul_zero _
  split_ifs <;> simp [h0, List.getD_eq_getElem?_getD]

lemma getD_coeff (P : Laurent (List F)) (p : ℤ) (k : ℕ) :
    (P.coeff p).getD k 0 = Bppp.coeff p (P.toPolys k) := by
  rw [coeff_toPolys, Laurent.coeff]
  have h0 : ∀ j, (Coefficient.scale P.coeffs.head! (0 : F) : List F).getD j 0 = 0 := fun j => by
    show (vec_scalar_mul 0 _).getD j 0 = 0
    rw [getD_vec_scalar_mul, zero_mul]
  split_ifs
  · rw [List.getD_eq_getElem?_getD (l := P.coeffs)]
    cases P.coeffs[(p - P.low).toNat]? with
    | none => simpa [List.getD_eq_getElem?_getD] using h0 k
    | some c => simp
  · exact h0 k

lemma length_coeff {L : ℕ} {P : Laurent (List F)} (hP : Uniform L P) (p : ℤ) :
    (P.coeff p).length = L := by
  have h0 : (Coefficient.scale P.coeffs.head! (0 : F) : List F).length = L := by
    show (vec_scalar_mul 0 _).length = L
    rw [length_vec_scalar_mul]
    obtain ⟨c, cs, hc⟩ := List.exists_cons_of_ne_nil hP.1
    rw [hc, List.head!_cons]; exact hP.2 c (by simp [hc])
  rw [Laurent.coeff]
  split_ifs
  · cases h : P.coeffs[(p - P.low).toNat]? with
    | none => simpa using h0
    | some c => simpa using hP.2 c (List.mem_of_getElem? h)
  · exact h0

/-- Two denotations agree when their coefficients do. -/
lemma toPoly_ext {f g : F[T;T⁻¹]} (h : ∀ p, Bppp.coeff p f = Bppp.coeff p g) : f = g :=
  ext_coeff h

/-! ## `new`, `monomial`, `+`, `-` -/

lemma toPolys_new (low : ℤ) (cs : List (List F)) (k : ℕ) :
    (new low cs).toPolys k = ∑ i ∈ range cs.length, mono (low + i) ((cs.getD i []).getD k 0) := rfl

lemma toPolys_monomial (p : ℤ) (c : List F) (k : ℕ) :
    (monomial p c).toPolys k = mono p (c.getD k 0) := by
  simp [toPolys, monomial, new]

lemma toPoly_new (low : ℤ) (cs : List F) :
    (new low cs).toPoly = ∑ i ∈ range cs.length, mono (low + i) (cs.getD i 0) := rfl

lemma toPoly_monomial (p : ℤ) (c : F) : (monomial p c).toPoly = mono p c := by
  simp [toPoly, monomial, new]

lemma uniform_new {L : ℕ} {low : ℤ} {cs : List (List F)} (hne : cs ≠ [])
    (h : ∀ c ∈ cs, c.length = L) : Uniform L (new low cs) := ⟨hne, h⟩

lemma uniform_monomial {L : ℕ} (p : ℤ) {c : List F} (h : c.length = L) :
    Uniform L (monomial p c) := ⟨by simp [monomial, new], by simp [monomial, new, h]⟩

lemma coeff_toPolys_of_out {P : Laurent (List F)} {k : ℕ} {p : ℤ}
    (h : p < P.low ∨ P.low + P.coeffs.length ≤ p) : Bppp.coeff p (P.toPolys k) = 0 := by
  rw [coeff_toPolys]
  split_ifs with h0
  · rw [List.getD_eq_getElem?_getD (l := P.coeffs), List.getElem?_eq_none (by omega)]; rfl
  · rfl

lemma coeff_toPoly_of_out {P : Laurent F} {p : ℤ}
    (h : p < P.low ∨ P.low + P.coeffs.length ≤ p) : Bppp.coeff p P.toPoly = 0 := by
  rw [coeff_toPoly]
  split_ifs with h0
  · exact getD_eq_zero_of_le (by omega)
  · rfl

lemma add_low (P Q : Laurent (List F)) : (P + Q).low = min P.low Q.low := rfl

lemma add_coeffs (P Q : Laurent (List F)) : (P + Q).coeffs =
    (List.range (max P.degree Q.degree - min P.low Q.low + 1).toNat).map fun (i : ℕ) =>
      vec_add (P.coeff (min P.low Q.low + i)) (Q.coeff (min P.low Q.low + i)) := rfl

lemma uniform_add {L : ℕ} {P Q : Laurent (List F)} (hP : Uniform L P) (hQ : Uniform L Q) :
    Uniform L (P + Q) := by
  refine ⟨?_, ?_⟩
  · rw [add_coeffs]
    have := List.length_pos_of_ne_nil hP.1
    simp only [ne_eq, List.map_eq_nil_iff, List.range_eq_nil, degree]
    omega
  · intro c hc
    rw [add_coeffs, List.mem_map] at hc
    obtain ⟨i, _, rfl⟩ := hc
    rw [length_vec_add, length_coeff hP, length_coeff hQ, min_self]

lemma toPolys_add {L : ℕ} {P Q : Laurent (List F)} (hP : Uniform L P) (hQ : Uniform L Q)
    (k : ℕ) : (P + Q).toPolys k = P.toPolys k + Q.toPolys k := by
  apply ext_coeff
  intro p
  rw [map_add, coeff_toPolys, add_low, add_coeffs]
  have hPl := List.length_pos_of_ne_nil hP.1
  have hQl := List.length_pos_of_ne_nil hQ.1
  simp only [degree] at *
  split_ifs with hp
  · rw [List.getD_eq_getElem?_getD (a := ([] : List F))]
    by_cases hi : (p - min P.low Q.low).toNat <
        (max (P.low + P.coeffs.length - 1) (Q.low + Q.coeffs.length - 1) - min P.low Q.low + 1).toNat
    · rw [List.getElem?_map, List.getElem?_range hi, Option.map_some, Option.getD_some,
        getD_vec_add (by rw [length_coeff hP, length_coeff hQ]), getD_coeff, getD_coeff,
        show min P.low Q.low + ((p - min P.low Q.low).toNat : ℤ) = p by omega]
    · rw [List.getElem?_eq_none (by rw [List.length_map, List.length_range]; omega)]
      rw [coeff_toPolys_of_out (by omega), coeff_toPolys_of_out (by omega)]; simp
  · rw [coeff_toPolys_of_out (by omega), coeff_toPolys_of_out (by omega), add_zero]

lemma toPoly_add (P Q : Laurent F) : (P + Q).toPoly = P.toPoly + Q.toPoly := by
  apply ext_coeff
  intro p
  rw [map_add, coeff_toPoly]
  show (if 0 ≤ p - min P.low Q.low then ((List.range (max P.degree Q.degree - min P.low Q.low +
    1).toNat).map fun (i : ℕ) => P.coeff (min P.low Q.low + i) + Q.coeff (min P.low Q.low + i)).getD
    (p - min P.low Q.low).toNat 0 else 0) = _
  simp only [degree]
  split_ifs with hp
  · rw [List.getD_eq_getElem?_getD]
    by_cases hi : (p - min P.low Q.low).toNat <
        (max (P.low + P.coeffs.length - 1) (Q.low + Q.coeffs.length - 1) - min P.low Q.low + 1).toNat
    · rw [List.getElem?_map, List.getElem?_range hi, Option.map_some, Option.getD_some,
        coeff_eq, coeff_eq, show min P.low Q.low + ((p - min P.low Q.low).toNat : ℤ) = p by omega]
    · rw [List.getElem?_eq_none (by rw [List.length_map, List.length_range]; omega),
        Option.getD_none]
      rw [coeff_toPoly_of_out (by omega), coeff_toPoly_of_out (by omega), add_zero]
  · rw [coeff_toPoly_of_out (by omega), coeff_toPoly_of_out (by omega), add_zero]

lemma toPoly_scale (P : Laurent F) (s : F) : (P.scale s).toPoly = mono 0 s * P.toPoly := by
  simp only [toPoly, scale, new, List.length_map, mul_sum, mono_mul, zero_add]
  refine sum_congr rfl fun i hi => ?_
  rw [List.getD_eq_getElem?_getD, List.getElem?_map, List.getD_eq_getElem?_getD,
    List.getElem?_eq_getElem (mem_range.1 hi)]
  simp only [Option.map_some, Option.getD_some]
  congr 1; exact mul_comm _ _

lemma toPoly_sub (P Q : Laurent F) : (P - Q).toPoly = P.toPoly - Q.toPoly := by
  show (P + Q.scale (-one)).toPoly = _
  rw [toPoly_add, toPoly_scale, sub_eq_add_neg, one, ← neg_one_mul (Q.toPoly)]
  congr 1
  simp [mono]

/-! ## `from_terms` -/

lemma from_terms_spec {L : ℕ} (t : ℤ × List F) (ts : List (ℤ × List F))
    (h : ∀ x ∈ t :: ts, x.2.length = L) :
    Uniform L (from_terms (t :: ts)) ∧ ∀ k, (from_terms (t :: ts)).toPolys k =
      ((t :: ts).map fun x => mono x.1 (x.2.getD k 0)).sum := by
  have key : ∀ (ts : List (ℤ × List F)) (acc : Laurent (List F)), Uniform L acc →
      (∀ x ∈ ts, x.2.length = L) →
      Uniform L (ts.foldl (fun acc (p, c) => acc + monomial p c) acc) ∧
      ∀ k, (ts.foldl (fun acc (p, c) => acc + monomial p c) acc).toPolys k =
        acc.toPolys k + (ts.map fun x => mono x.1 (x.2.getD k 0)).sum := by
    intro ts
    induction ts with
    | nil => intro acc hacc _; simp [hacc]
    | cons x ts ih =>
      intro acc hacc hts
      have hm := uniform_monomial x.1 (hts x (by simp))
      obtain ⟨h1, h2⟩ := ih (acc + monomial x.1 x.2) (uniform_add hacc hm)
        fun y hy => hts y (by simp [hy])
      refine ⟨h1, fun k => ?_⟩
      rw [List.foldl_cons, h2, toPolys_add hacc hm, toPolys_monomial, List.map_cons, List.sum_cons,
        add_assoc]
  obtain ⟨p, c⟩ := t
  obtain ⟨h1, h2⟩ := key ts (monomial p c) (uniform_monomial p (h (p, c) (by simp)))
    fun y hy => h y (by simp [hy])
  exact ⟨h1, fun k => by rw [from_terms, h2, toPolys_monomial, List.map_cons, List.sum_cons]⟩

lemma from_terms_toPoly (t : ℤ × F) (ts : List (ℤ × F)) :
    (from_terms (t :: ts)).toPoly = ((t :: ts).map fun x => mono x.1 x.2).sum := by
  have key : ∀ (ts : List (ℤ × F)) (acc : Laurent F),
      (ts.foldl (fun acc (p, c) => acc + monomial p c) acc).toPoly =
        acc.toPoly + (ts.map fun x => mono x.1 x.2).sum := by
    intro ts
    induction ts with
    | nil => intro acc; simp
    | cons x ts ih =>
      intro acc
      rw [List.foldl_cons, ih, toPoly_add, toPoly_monomial, List.map_cons, List.sum_cons, add_assoc]
  obtain ⟨p, c⟩ := t
  rw [from_terms, key, toPoly_monomial, List.map_cons, List.sum_cons]

/-! ## `eval` -/

lemma foldl_mul_const (b a : F) (n : ℕ) :
    (List.range n).foldl (fun acc _ => acc * b) a = a * b ^ n := by
  induction n generalizing a with
  | zero => simp
  | succ n ih => rw [List.range_succ, List.foldl_append, ih]; simp [pow_succ, mul_assoc]

/-- `Laurent::eval` evaluates every entry at a nonzero point. -/
lemma eval_eq {L : ℕ} {P : Laurent (List F)} (hP : Uniform L P) (τ : Fˣ) :
    P.eval (τ : F) = .ok ((List.range L).map fun k => evalAt τ (P.toPolys k)) := by
  have hx : (τ : F) ≠ 0 := τ.ne_zero
  -- The loop over the remaining coefficients from `(res, xp)`.
  have key : ∀ (cs : List (List F)) (res : List F) (xp : F), (∀ c ∈ cs, c.length = L) →
      res.length = L →
      (cs.foldl (fun (result, x_pow) c =>
          (Coefficient.add result (Coefficient.scale c (x_pow * (τ : F))), x_pow * (τ : F)))
        (res, xp)).1.length = L ∧
      ∀ k, (cs.foldl (fun (result, x_pow) c =>
          (Coefficient.add result (Coefficient.scale c (x_pow * (τ : F))), x_pow * (τ : F)))
        (res, xp)).1.getD k 0 =
        res.getD k 0 + ∑ j ∈ range cs.length, (cs.getD j []).getD k 0 * (xp * (τ : F) ^ (j + 1)) := by
    intro cs
    induction cs with
    | nil => intro res xp _ hres; simp [hres]
    | cons c cs ih =>
      intro res xp hcs hres
      have hc := hcs c (by simp)
      have hlen : (Coefficient.add res (Coefficient.scale c (xp * (τ : F))) : List F).length = L := by
        show (vec_add res (vec_scalar_mul _ c)).length = L
        rw [length_vec_add, length_vec_scalar_mul, hc, hres, min_self]
      obtain ⟨h1, h2⟩ := ih _ (xp * τ) (fun d hd => hcs d (by simp [hd])) hlen
      refine ⟨by rw [List.foldl_cons]; exact h1, fun k => ?_⟩
      rw [List.foldl_cons, h2]
      show (vec_add res (vec_scalar_mul _ c)).getD k 0 + _ = _
      rw [getD_vec_add (by rw [length_vec_scalar_mul, hc, hres]), getD_vec_scalar_mul,
        List.length_cons, sum_range_succ', List.getD_cons_zero, add_assoc]
      congr 1
      rw [add_comm]; congr 1
      · exact sum_congr rfl fun j _ => by simp only [List.getD_cons_succ]; ring
      · ring
  obtain ⟨c0, cs, hcs⟩ := List.exists_cons_of_ne_nil hP.1
  have hc0 : c0.length = L := hP.2 c0 (by simp [hcs])
  -- `x_pow` starts at `τ^low`.
  set v : F := if P.low < 0 then (τ : F)⁻¹ else τ with hv
  have hpow : v ^ P.low.natAbs = (τ : F) ^ P.low := by
    rw [hv]; split_ifs with h
    · rw [inv_pow, ← zpow_natCast, ← zpow_neg, show -(P.low.natAbs : ℤ) = P.low by omega]
    · rw [← zpow_natCast, show (P.low.natAbs : ℤ) = P.low by omega]
  set xp := (List.range P.low.natAbs).foldl (fun acc _ => acc * v) one with hxp
  have hxp' : xp = (τ : F) ^ P.low := by rw [hxp, foldl_mul_const, one, one_mul, hpow]
  have hev : P.eval (τ : F) = .ok (cs.foldl (fun (result, x_pow) c =>
          (Coefficient.add result (Coefficient.scale c (x_pow * (τ : F))), x_pow * (τ : F)))
        (Coefficient.scale c0 xp, xp)).1 := by
    unfold Laurent.eval
    rw [hcs]
    by_cases hl : P.low < 0
    · simp only [hv, hxp, hl, if_true, inverse, hx, if_false]; rfl
    · simp only [hv, hxp, hl, if_false]; rfl
  have hhead : (Coefficient.scale c0 xp : List F).length = L := by
    show (vec_scalar_mul _ c0).length = L
    rw [length_vec_scalar_mul, hc0]
  obtain ⟨h1, h2⟩ := key cs _ xp (fun d hd => hP.2 d (by simp [hcs, hd])) hhead
  rw [hev]
  congr 1
  apply List.ext_getElem (by rw [h1]; simp)
  intro k hk1 hk2
  have := h2 k
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk1, Option.getD_some] at this
  rw [this, List.getElem_map, List.getElem_range]
  show (vec_scalar_mul _ c0).getD k 0 + _ = _
  rw [getD_vec_scalar_mul, toPolys, hcs, map_sum, List.length_cons, sum_range_succ', hxp']
  simp only [evalAt_mono, List.getD_cons_zero, List.getD_cons_succ, Nat.cast_zero, add_zero]
  rw [add_comm]
  congr 1
  · exact sum_congr rfl fun j _ => by
      rw [show P.low + ((j + 1 : ℕ) : ℤ) = P.low + (j + 1 : ℕ) from rfl, zpow_add₀ hx,
        zpow_natCast]
  · ring

/-- `Laurent::eval` succeeds at a nonzero point. -/
lemma eval_ok {C : Type} [Inhabited C] [Coefficient F C] (P : Laurent C) (τ : Fˣ) :
    ∃ x, P.eval (τ : F) = .ok x := by
  unfold Laurent.eval
  by_cases hl : P.low < 0
  · simp only [hl, if_true, inverse, τ.ne_zero, if_false]; exact ⟨_, rfl⟩
  · simp only [hl, if_false]; exact ⟨_, rfl⟩

/-- `T^p` evaluates to `τ^p`. -/
lemma eval_monomial_one (p : ℤ) (τ : Fˣ) :
    (monomial p (one : F)).eval (τ : F) = .ok ((τ : F) ^ p) := by
  have hx : (τ : F) ≠ 0 := τ.ne_zero
  unfold Laurent.eval
  simp only [monomial, new]
  by_cases hl : p < 0
  · simp only [hl, if_true, inverse, hx, if_false, bind, Except.bind, pure, Except.pure,
      List.tail_cons, List.foldl_nil, List.head!_cons, foldl_mul_const]
    show Except.ok (one * (one * (τ : F)⁻¹ ^ p.natAbs)) = _
    rw [one, one_mul, one_mul, inv_pow, ← zpow_natCast, ← zpow_neg,
      show -(p.natAbs : ℤ) = p by omega]
  · simp only [hl, if_false, bind, Except.bind, pure, Except.pure, List.tail_cons,
      List.foldl_nil, List.head!_cons, foldl_mul_const]
    show Except.ok (one * (one * (τ : F) ^ p.natAbs)) = _
    rw [one, one_mul, one_mul, ← zpow_natCast, show (p.natAbs : ℤ) = p by omega]

/-! ## Inner products -/

lemma getD_modify_add (R : List F) (m n : ℕ) (v : F) :
    (R.modify m (· + v)).getD n 0 = R.getD n 0 + if m = n ∧ n < R.length then v else 0 := by
  simp only [List.getD_eq_getElem?_getD, List.getElem?_modify]
  rcases lt_or_ge n R.length with hn | hn
  · rw [List.getElem?_eq_getElem hn]; by_cases hmn : m = n <;> simp [hmn, hn]
  · rw [List.getElem?_eq_none hn]; simp; omega

lemma getD_mem' {α : Type*} {l : List α} {i : ℕ} (h : i < l.length) (d : α) :
    l.getD i d ∈ l := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem h, Option.getD_some]
  exact List.getElem_mem h

lemma mono_sum {ι : Type*} (p : ℤ) (s : Finset ι) (f : ι → F) :
    mono p (∑ i ∈ s, f i) = ∑ i ∈ s, mono p (f i) := by
  simp only [mono, map_sum, sum_mul]

lemma mono_ite (p : ℤ) (c : Prop) [Decidable c] (x : F) :
    mono p (if c then x else 0) = if c then mono p x else 0 := by
  split_ifs <;> simp

/-- The inner loop of `inner_product` adds `g b_j` to entry `i + j`. -/
lemma inner_loop (g : List F → F) (i : ℕ) : ∀ (bs : List (List F)) (s : ℕ) (R : List F),
    ((bs.zipIdx s).foldl (fun R (b, j) => R.modify (i + j) (· + g b)) R).length = R.length ∧
    ∀ n, ((bs.zipIdx s).foldl (fun R (b, j) => R.modify (i + j) (· + g b)) R).getD n 0 =
      R.getD n 0 + ∑ j ∈ range bs.length,
        if i + (s + j) = n ∧ n < R.length then g (bs.getD j []) else 0
  | [], _, R => by simp
  | b :: bs, s, R => by
    obtain ⟨h1, h2⟩ := inner_loop g i bs (s + 1) (R.modify (i + s) (· + g b))
    simp only [List.zipIdx_cons, List.foldl_cons, List.length_modify] at h1 h2 ⊢
    refine ⟨h1, fun n => ?_⟩
    rw [h2, getD_modify_add, List.length_cons, sum_range_succ', add_assoc]
    congr 1
    simp only [List.getD_cons_zero, List.getD_cons_succ, add_zero]
    rw [add_comm]; congr 1
    exact sum_congr rfl fun j _ => by rw [show s + 1 + j = s + (j + 1) by ring]

/-- The nested loops of `inner_product` add `g a_i b_j` to entry `i + j`. -/
lemma outer_loop (g : List F → List F → F) (bs : List (List F)) :
    ∀ (as : List (List F)) (s : ℕ) (R : List F),
    ((as.zipIdx s).foldl (fun R (a, i) =>
        (bs.zipIdx).foldl (fun R (b, j) => R.modify (i + j) (· + g a b)) R) R).length =
      R.length ∧
    ∀ n, ((as.zipIdx s).foldl (fun R (a, i) =>
        (bs.zipIdx).foldl (fun R (b, j) => R.modify (i + j) (· + g a b)) R) R).getD n 0 =
      R.getD n 0 + ∑ i ∈ range as.length, ∑ j ∈ range bs.length,
        if s + i + j = n ∧ n < R.length then g (as.getD i []) (bs.getD j []) else 0
  | [], _, R => by simp
  | a :: as, s, R => by
    obtain ⟨i1, i2⟩ := inner_loop (g a) s bs 0 R
    obtain ⟨h1, h2⟩ := outer_loop g bs as (s + 1)
      ((bs.zipIdx).foldl (fun R (b, j) => R.modify (s + j) (· + g a b)) R)
    simp only [List.zipIdx_cons, List.foldl_cons] at h1 h2 ⊢
    refine ⟨h1.trans i1, fun n => ?_⟩
    rw [h2, i2, i1, List.length_cons, sum_range_succ', add_assoc]
    congr 1
    simp only [List.getD_cons_zero, List.getD_cons_succ, zero_add, add_zero]
    rw [add_comm]; congr 1
    exact sum_congr rfl fun i _ => sum_congr rfl fun j _ => by
      rw [show s + 1 + i = s + (i + 1) by ring]

/-- `Laurent<Vec<S>>::inner_product` is the inner product of the denoted vectors. -/
lemma toPoly_inner_product {L : ℕ} {P Q : Laurent (List F)} (hP : Uniform L P)
    (hQ : Uniform L Q) :
    (P.inner_product Q).toPoly = ∑ k ∈ range L, P.toPolys k * Q.toPolys k := by
  have hla : 0 < P.coeffs.length := List.length_pos_of_ne_nil hP.1
  have hlb : 0 < Q.coeffs.length := List.length_pos_of_ne_nil hQ.1
  set N := P.coeffs.length + Q.coeffs.length - 1 with hN
  obtain ⟨h1, h2⟩ := outer_loop (fun a b => Bppp.inner_product a b) Q.coeffs P.coeffs 0
    (List.replicate N 0)
  simp only [List.length_replicate, zero_add] at h1 h2
  have hrep : ∀ n, (List.replicate N (0 : F)).getD n 0 = 0 := fun n => by
    rw [List.getD_eq_getElem?_getD, List.getElem?_replicate]; split_ifs <;> rfl
  -- Both sides are `Σ_i Σ_j T^{low_P + low_Q + i + j} <P_i, Q_j>`.
  have lhs : (P.inner_product Q).toPoly = ∑ i ∈ range P.coeffs.length,
      ∑ j ∈ range Q.coeffs.length, mono (P.low + Q.low + (i + j : ℕ))
        (Bppp.inner_product (P.coeffs.getD i []) (Q.coeffs.getD j [])) := by
    show (new (P.low + Q.low) _).toPoly = _
    rw [toPoly_new]
    simp only
    rw [← hN, h1]
    simp_rw [h2, hrep, zero_add, mono_sum, mono_ite]
    rw [sum_comm]
    refine sum_congr rfl fun i hi => ?_
    rw [sum_comm]
    refine sum_congr rfl fun j hj => ?_
    simp only [mem_range] at hi hj
    rw [sum_eq_single_of_mem (i + j) (mem_range.2 (by omega))]
    · rw [if_pos ⟨rfl, by omega⟩]
    · intro n _ hn; rw [if_neg (by omega)]
  have rhs : ∑ k ∈ range L, P.toPolys k * Q.toPolys k = ∑ i ∈ range P.coeffs.length,
      ∑ j ∈ range Q.coeffs.length, mono (P.low + Q.low + (i + j : ℕ))
        (Bppp.inner_product (P.coeffs.getD i []) (Q.coeffs.getD j [])) := by
    simp only [toPolys, sum_mul_sum, mono_mul]
    rw [sum_comm]
    refine sum_congr rfl fun i hi => ?_
    rw [sum_comm]
    refine sum_congr rfl fun j hj => ?_
    simp only [mem_range] at hi hj
    rw [inner_product_eq, hP.2 _ (getD_mem' hi _), hQ.2 _ (getD_mem' hj _), min_self,
      mono_sum]
    refine sum_congr rfl fun k _ => ?_
    congr 1; push_cast; ring
  rw [lhs, rhs]

/-- `Laurent<Vec<S>>::weighted_inner_product` is the weighted inner product of the denoted
vectors, for weights of length `L`. -/
lemma toPoly_weighted_inner_product {L : ℕ} {P Q : Laurent (List F)} (hP : Uniform L P)
    (hQ : Uniform L Q) (w : List F) (hw : w.length = L) :
    (P.weighted_inner_product Q w).toPoly =
      ∑ k ∈ range L, mono 0 (w.getD k 0) * (P.toPolys k * Q.toPolys k) := by
  have hW : Uniform L (new P.low (P.coeffs.map fun a => hadamard a w)) := by
    refine ⟨by simpa [new] using hP.1, fun c hc => ?_⟩
    simp only [new, List.mem_map] at hc
    obtain ⟨a, ha, rfl⟩ := hc
    rw [length_hadamard, hP.2 a ha, hw, min_self]
  rw [weighted_inner_product, toPoly_inner_product hW hQ]
  refine sum_congr rfl fun k hk => ?_
  rw [← mul_assoc]; congr 1
  simp only [toPolys, new, List.length_map, mul_sum, mono_mul, zero_add]
  refine sum_congr rfl fun i hi => ?_
  rw [List.getD_eq_getElem?_getD (a := ([] : List F)), List.getElem?_map,
    List.getElem?_eq_getElem (mem_range.1 hi), Option.map_some, Option.getD_some,
    getD_hadamard _ (by rw [hw]; exact mem_range.1 hk),
    List.getD_eq_getElem?_getD (a := ([] : List F)), List.getElem?_eq_getElem (mem_range.1 hi),
    Option.getD_some, mul_comm]

end Laurent

end Bppp
