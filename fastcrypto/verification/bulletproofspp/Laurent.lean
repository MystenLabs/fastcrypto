-- THIS FILE IS AI-ONLY
import bulletproofspp.Util
import bulletproofspp.Model.Laurent

/-!
The generated functions of `laurent.rs` compute the functions of `Model/Laurent.lean`. They are
generic in the coefficient type `C`, so the lemmas take a `CoeffModel`: the generated
`Coefficient` instance computes the model's, through a map `ψ`, on the coefficients satisfying
`P` (for vectors, those of one length).
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar

/-- The generated `Coefficient` instance `inst` computes the model's on the coefficients
satisfying `P`, which it preserves. -/
structure CoeffModel {C Cm : Type} [Bppp.Coefficient F Cm] (φ : S → F)
    (inst : bulletproofspp.laurent.Coefficient C) (ψ : C → Cm) (P : C → Prop) : Prop where
  clone : ∀ a, inst.corecloneCloneInst.clone a = ok a
  add : ∀ a b, P a → P b → ∃ c, inst.add a b = ok c ∧ P c ∧
    ψ c = Bppp.Coefficient.add (ψ a) (ψ b)
  scale : ∀ a s, P a → ∃ c, inst.scale a s = ok c ∧ P c ∧
    ψ c = Bppp.Coefficient.scale (ψ a) (φ s)

/-- The bound on the powers of the polynomials, which keeps the `i32` arithmetic exact. -/
def powBound : ℤ := 2 ^ 29

section Generic

variable {C Cm : Type} [Inhabited Cm] [Bppp.Coefficient F Cm]

/-- The model of a generated polynomial. -/
def toL (ψ : C → Cm) (l : bulletproofspp.laurent.Laurent C) : Bppp.Laurent Cm :=
  ⟨l.low.val, l.coeffs.val.map ψ⟩

/-- A well-formed polynomial: some coefficients, all satisfying `P`, and powers within
`powBound`. -/
def WF (P : C → Prop) (l : bulletproofspp.laurent.Laurent C) : Prop :=
  l.coeffs.val ≠ [] ∧ (∀ c ∈ l.coeffs.val, P c) ∧ -powBound ≤ l.low.val ∧
    l.low.val + l.coeffs.length ≤ powBound

lemma spec_eq_ok' {α : Type} {m : Result α} {p : α → Prop} (h : m ⦃ x => p x ⦄) :
    ∃ x, m = ok x ∧ p x := by
  cases m with
  | ret a => exact ⟨a, rfl, (WP.spec_ok a).mp h⟩
  | vis e k => exact absurd h (by simp)
  | div => exact absurd h (by simp)

lemma usize_to_i32 (n : Usize) (h : n.val < 2 ^ 31) :
    (UScalar.hcast .I32 n).val = n.val := by
  rw [UScalar.hcast_val_eq]
  simp only [IScalarTy.numBits]
  rw [Int.bmod_eq_of_le] <;> omega

lemma i32_to_usize (x : I32) (h : 0 ≤ x.val) :
    (IScalar.hcast .Usize x).val = x.val.toNat := by
  rw [IScalar.hcast_val_eq]
  have hx : x.val < 2 ^ 31 := by scalar_tac
  have : (2 : ℤ) ^ 32 ≤ 2 ^ UScalarTy.Usize.numBits := by
    cases System.Platform.numBits_eq <;> simp [UScalarTy.numBits, *]
  rw [Int.emod_eq_of_lt h (by omega)]

@[simp] lemma into_vec_val {α : Type} (s : Slice α) : (alloc.slice.Slice.into_vec s).val = s.val :=
  rfl

lemma new_spec (inst : bulletproofspp.laurent.Coefficient C) (low : I32) (coeffs : alloc.vec.Vec C)
    (h : coeffs.val ≠ []) :
    bulletproofspp.laurent.Laurent.new inst low coeffs ⦃ r => r = { low, coeffs } ⦄ := by
  unfold bulletproofspp.laurent.Laurent.new
  step*
  simp_all [alloc.vec.Vec.length]

lemma monomial_spec (inst : bulletproofspp.laurent.Coefficient C) (p : I32) (c : C) :
    bulletproofspp.laurent.Laurent.monomial inst p c ⦃ r => r.low = p ∧ r.coeffs.val = [c] ⦄ := by
  unfold bulletproofspp.laurent.Laurent.monomial
  step*
  apply WP.spec_mono (new_spec inst p _ (by simp [y_post]))
  intro r hr
  simp [hr, y_post]

lemma degree_spec (inst : bulletproofspp.laurent.Coefficient C) (P : C → Prop)
    (l : bulletproofspp.laurent.Laurent C) (hl : WF P l) :
    bulletproofspp.laurent.Laurent.degree inst l ⦃ d =>
      d.val = l.low.val + l.coeffs.length - 1 ⦄ := by
  obtain ⟨hne, -, hlo, hhi⟩ := hl
  unfold bulletproofspp.laurent.Laurent.degree
  have hlen : l.coeffs.length ≤ 2 * powBound := by omega
  simp only [powBound] at hlo hhi hlen
  norm_num at hlo hhi hlen
  have hc : (UScalar.hcast IScalarTy.I32 l.coeffs.len).val = l.coeffs.length := by
    rw [usize_to_i32 _ (by simp; omega)]; simp
  step*

lemma coeff_spec (hs : ScalarModel F φ) {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (l : bulletproofspp.laurent.Laurent C) (hl : WF P l) (p : I32)
    (hp : -2 * powBound ≤ p.val ∧ p.val ≤ 2 * powBound) :
    bulletproofspp.laurent.Laurent.coeff inst l p ⦃ r =>
      P r ∧ ψ r = (toL ψ l).coeff p.val ⦄ := by
  obtain ⟨hne, hP, hlo, hhi⟩ := hl
  have h0 : 0 < l.coeffs.val.length := List.length_pos_of_ne_nil hne
  obtain ⟨z, hz, hPz, hψz⟩ := hc.scale l.coeffs.val[0] hs.z (hP _ (List.getElem_mem h0))
  have hhead : (l.coeffs.val.map ψ).head! = ψ l.coeffs.val[0] := by
    obtain ⟨a, t, hat⟩ := List.exists_cons_of_ne_nil hne
    simp [hat]
  simp only [powBound] at hp hlo hhi
  unfold bulletproofspp.laurent.Laurent.coeff
  simp only [hs.zero_eq]
  step*
  · rename_i hge hlt
    have hoff : 0 ≤ offset.val := by scalar_tac
    have hiv : i2.val = (p.val - l.low.val).toNat := by
      rw [i2_post, i32_to_usize _ hoff, offset_post]
    have hlt' : (p.val - l.low.val).toNat < l.coeffs.val.length := by
      rw [← hiv, i2_post, ← i_post]; scalar_tac
    rw [hc.clone, WP.spec_ok, t_post]
    refine ⟨hP _ (List.getElem_mem _), ?_⟩
    simp only [Bppp.Laurent.coeff, toL, show 0 ≤ p.val - l.low.val by omega, ite_true]
    rw [List.getElem?_eq_getElem (by simpa using hlt')]
    simp [hiv]
  · rename_i hge hlt
    have hoff : 0 ≤ offset.val := by scalar_tac
    have hge' : l.coeffs.val.length ≤ (p.val - l.low.val).toNat := by
      have := i32_to_usize _ hoff
      rw [← i_post, offset_post] at this
      scalar_tac
    rw [t_post, hz, WP.spec_ok]
    refine ⟨hPz, ?_⟩
    simp only [Bppp.Laurent.coeff, toL, show 0 ≤ p.val - l.low.val by omega, ite_true]
    rw [List.getElem?_eq_none (by simpa using hge')]
    simp [hψz, hhead]
  · rename_i hge
    have hoff : offset.val < 0 := by scalar_tac
    rw [t_post, hz, WP.spec_ok]
    refine ⟨hPz, ?_⟩
    simp only [Bppp.Laurent.coeff, toL, show ¬ 0 ≤ p.val - l.low.val by omega, ite_false]
    simp [hψz, hhead]

lemma scale_loop_spec {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P) (v : alloc.vec.Vec C) (hv : ∀ c ∈ v.val, P c)
    (s : S) (out : alloc.vec.Vec C) (i : Usize) (hi : i.val ≤ v.length) (ho : out.length = i.val)
    (hout : (∀ c ∈ out.val, P c) ∧
      out.val.map ψ = (v.val.take i.val).map (fun c => Bppp.Coefficient.scale (ψ c) (φ s))) :
    bulletproofspp.laurent.Laurent.scale_loop inst v s out i ⦃ r =>
      (∀ c ∈ r.val, P c) ∧ r.val.map ψ = v.val.map (fun c => Bppp.Coefficient.scale (ψ c) (φ s)) ⦄ := by
  unfold bulletproofspp.laurent.Laurent.scale_loop
  apply loop.spec_decr_nat (fun p => v.length - p.2.val)
    (fun p => p.2.val ≤ v.length ∧ p.1.length = p.2.val ∧ (∀ c ∈ p.1.val, P c) ∧
      p.1.val.map ψ = (v.val.take p.2.val).map (fun c => Bppp.Coefficient.scale (ψ c) (φ s)))
  · rintro ⟨o, j⟩ ⟨hj, hoj, hP', heq⟩
    dsimp only at hj hoj hP' heq
    unfold bulletproofspp.laurent.Laurent.scale_loop.body
    step*
    · have hjl : j.val < v.val.length := by scalar_tac
      obtain ⟨c, hcs, hPc, hψc⟩ := hc.scale t s (by rw [t_post]; exact hv _ (List.getElem_mem _))
      rw [hcs]
      step*
      refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, coeffs1_post]; scalar_tac, ?_, ?_,
        by scalar_tac⟩
      · intro x hx
        rw [coeffs1_post] at hx
        rcases List.mem_append.1 hx with hx | hx
        · exact hP' x hx
        · simp at hx; subst hx; exact hPc
      · rw [coeffs1_post, i2_post, List.take_succ_eq_append_getElem hjl]
        simp only [List.map_append, heq, List.map_cons, List.map_nil, hψc, t_post]
    · have : j.val = v.val.length := by scalar_tac
      refine ⟨hP', ?_⟩
      rw [heq, this, List.take_length]
  · exact ⟨hi, ho, hout⟩

lemma scale_spec {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (l : bulletproofspp.laurent.Laurent C) (hl : WF P l) (s : S) :
    bulletproofspp.laurent.Laurent.scale inst l s ⦃ r =>
      WF P r ∧ toL ψ r = (toL ψ l).scale (φ s) ⦄ := by
  obtain ⟨hne, hP, hlo, hhi⟩ := hl
  unfold bulletproofspp.laurent.Laurent.scale
  apply WP.spec_bind (scale_loop_spec hc l.coeffs hP s _ 0#usize (by simp) (by simp)
    (by simp))
  rintro r ⟨hPr, hr⟩
  have hlen : r.val.length = l.coeffs.val.length := by
    simpa using congrArg List.length hr
  have hrne : r.val ≠ [] := by
    intro h; rw [h] at hlen; exact hne (List.eq_nil_of_length_eq_zero hlen.symm)
  apply WP.spec_mono (new_spec inst l.low r hrne)
  intro q hq
  subst hq
  refine ⟨⟨hrne, hPr, hlo, by simpa [alloc.vec.Vec.length, hlen] using hhi⟩, ?_⟩
  simp [toL, Bppp.Laurent.scale, Bppp.Laurent.new, hr]

/-- The coefficients of `a + b` from the power `lo` up to, not including, `lo + k`. -/
def addCoeffs (a b : Bppp.Laurent Cm) (lo : ℤ) (k : ℕ) : List Cm :=
  (List.range k).map fun (i : ℕ) => Bppp.Coefficient.add (a.coeff (lo + i)) (b.coeff (lo + i))

lemma addCoeffs_succ (a b : Bppp.Laurent Cm) (lo : ℤ) (k : ℕ) :
    addCoeffs a b lo (k + 1) = addCoeffs a b lo k ++
      [Bppp.Coefficient.add (a.coeff (lo + k)) (b.coeff (lo + k))] := by
  simp [addCoeffs, List.range_succ]

lemma add_loop_spec (hs : ScalarModel F φ) {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (a b : bulletproofspp.laurent.Laurent C) (ha : WF P a) (hb : WF P b)
    (lo high : I32) (hlo : -powBound ≤ lo.val) (hhigh : high.val < powBound)
    (out : alloc.vec.Vec C) (p : I32) (hp : lo.val ≤ p.val ∧ p.val ≤ high.val)
    (hout : out.length = (p.val - lo.val).toNat ∧ (∀ c ∈ out.val, P c) ∧
      out.val.map ψ = addCoeffs (toL ψ a) (toL ψ b) lo.val (p.val - lo.val).toNat) :
    bulletproofspp.laurent.Laurent.Insts.CoreOpsArithAddLaurentLaurent.add_loop inst a.low
      a.coeffs b.low b.coeffs high out p ⦃ r =>
      (∀ c ∈ r.val, P c) ∧
      r.val.map ψ = addCoeffs (toL ψ a) (toL ψ b) lo.val (high.val - lo.val + 1).toNat ⦄ := by
  unfold bulletproofspp.laurent.Laurent.Insts.CoreOpsArithAddLaurentLaurent.add_loop
  apply loop.spec_decr_nat (fun q => (high.val - q.2.val).toNat)
    (fun q => lo.val ≤ q.2.val ∧ q.2.val ≤ high.val ∧
      q.1.length = (q.2.val - lo.val).toNat ∧ (∀ c ∈ q.1.val, P c) ∧
      q.1.val.map ψ = addCoeffs (toL ψ a) (toL ψ b) lo.val (q.2.val - lo.val).toNat)
  · rintro ⟨o, q⟩ ⟨hq1, hq2, hol, hPo, heq⟩
    dsimp only at hq1 hq2 hol hPo heq
    unfold bulletproofspp.laurent.Laurent.Insts.CoreOpsArithAddLaurentLaurent.add_loop.body
    have hqb : -2 * powBound ≤ q.val ∧ q.val ≤ 2 * powBound := by
      simp only [powBound] at *; omega
    have ha' : WF P { low := a.low, coeffs := a.coeffs } := ha
    have hb' : WF P { low := b.low, coeffs := b.coeffs } := hb
    have hle : q ≤ high := by scalar_tac
    simp only [hle, ite_true]
    apply WP.spec_bind (coeff_spec hs hc _ ha' q hqb)
    rintro t ⟨hPt, hψt⟩
    apply WP.spec_bind (coeff_spec hs hc _ hb' q hqb)
    rintro t1 ⟨hPt1, hψt1⟩
    obtain ⟨t2, ht2, hPt2, hψt2⟩ := hc.add t t1 hPt hPt1
    rw [ht2]
    have hlen : o.val.length < Usize.max := by
      have : (q.val - lo.val).toNat < 2 ^ 31 := by simp only [powBound] at *; omega
      have : (2 : ℕ) ^ 31 ≤ Usize.max := by
        cases System.Platform.numBits_eq <;> simp [Usize.max, Usize.numBits, *]
      have : o.val.length = (q.val - lo.val).toNat := hol
      omega
    have hnew : (o.val ++ [t2]).map ψ =
        addCoeffs (toL ψ a) (toL ψ b) lo.val ((q.val - lo.val).toNat + 1) := by
      rw [addCoeffs_succ, ← heq, show lo.val + ((q.val - lo.val).toNat : ℤ) = q.val by omega]
      simp [hψt2, hψt, hψt1]
    have hPn : ∀ c ∈ o.val ++ [t2], P c := by
      intro c hc'
      rcases List.mem_append.1 hc' with hc' | hc'
      · exact hPo c hc'
      · simp at hc'; subst hc'; exact hPt2
    step*
    · rename_i hqe
      have hqe' : q.val = high.val := by rw [hqe]
      refine ⟨by rw [coeffs1_post]; exact hPn, ?_⟩
      rw [coeffs1_post, hnew]
      congr 1; omega
    · rename_i hqne
      have hqne' : q.val ≠ high.val := fun h => hqne (IScalar.eq_of_val_eq h)
      refine ⟨by omega, by omega, ?_, ?_, ?_, by omega⟩
      · have : o.val.length = (q.val - lo.val).toNat := hol
        simp [alloc.vec.Vec.length, coeffs1_post]; omega
      · rw [coeffs1_post]; exact hPn
      · rw [coeffs1_post, hnew, p1_post]; congr 1; omega
  · exact ⟨hp.1, hp.2, hout⟩

lemma add_spec (hs : ScalarModel F φ) {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (a b : bulletproofspp.laurent.Laurent C) (ha : WF P a) (hb : WF P b) :
    bulletproofspp.laurent.Laurent.Insts.CoreOpsArithAddLaurentLaurent.add inst a b ⦃ r =>
      WF P r ∧ toL ψ r = toL ψ a + toL ψ b ⦄ := by
  unfold bulletproofspp.laurent.Laurent.Insts.CoreOpsArithAddLaurentLaurent.add
  have ha0 := ha; have hb0 := hb
  obtain ⟨hane, haP, halo, hahi⟩ := ha0
  obtain ⟨hbne, hbP, hblo, hbhi⟩ := hb0
  have hal : 0 < a.coeffs.val.length := List.length_pos_of_ne_nil hane
  have hbl : 0 < b.coeffs.val.length := List.length_pos_of_ne_nil hbne
  have hal' : a.coeffs.length = a.coeffs.val.length := rfl
  have hbl' : b.coeffs.length = b.coeffs.val.length := rfl
  step*
  apply WP.spec_bind (degree_spec inst P a ha)
  intro da hda
  apply WP.spec_bind (degree_spec inst P b hb)
  intro db hdb
  step*
  have hlo : low.val = min a.low.val b.low.val := by scalar_tac
  have hhi : high.val = max da.val db.val := by scalar_tac
  apply WP.spec_bind (add_loop_spec hs hc a b ha hb low high (by simp only [powBound] at *; omega)
    (by simp only [powBound] at *; omega) (alloc.vec.Vec.new C) low
    (by constructor <;> omega) (by simp [alloc.vec.Vec.length, addCoeffs]))
  rintro coeffs ⟨hPc, hψc⟩
  have hlenc : coeffs.val.length = (high.val - low.val + 1).toNat := by
    simpa [addCoeffs] using congrArg List.length hψc
  have hne : coeffs.val ≠ [] := by
    intro h; rw [h] at hlenc; simp at hlenc; omega
  apply WP.spec_mono (new_spec inst low coeffs hne)
  intro r hr
  subst hr
  refine ⟨⟨hne, hPc, by simp only [powBound] at *; omega,
    by simp only [powBound, alloc.vec.Vec.length] at *; omega⟩, ?_⟩
  show toL ψ { low := low, coeffs := coeffs } = Bppp.Laurent.add (toL ψ a) (toL ψ b)
  simp only [toL, Bppp.Laurent.add, Bppp.Laurent.new, Bppp.Laurent.degree, hψc, addCoeffs,
    List.length_map, hlo]
  congr 2
  simp only [hhi, hda, hdb, hlo, alloc.vec.Vec.length] at *

lemma sub_spec (hs : ScalarModel F φ) {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (a b : bulletproofspp.laurent.Laurent C) (ha : WF P a) (hb : WF P b) :
    bulletproofspp.laurent.Laurent.Insts.CoreOpsArithSubLaurentLaurent.sub inst a b ⦃ r =>
      WF P r ∧ toL ψ r = toL ψ a - toL ψ b ⦄ := by
  unfold bulletproofspp.laurent.Laurent.Insts.CoreOpsArithSubLaurentLaurent.sub
  simp only [one_spec hs, hs.neg_eq, bind_ok]
  apply WP.spec_bind (scale_spec hc b hb _)
  rintro l ⟨hl, hψl⟩
  apply WP.spec_mono (add_spec hs hc a l ha hl)
  rintro r ⟨hr, hψr⟩
  refine ⟨hr, ?_⟩
  rw [hψr, hψl]
  simp
  rfl

/-- A term `(p, c)` with `P c` and a power within `powBound`. -/
def TermOK (P : C → Prop) (t : I32 × C) : Prop :=
  P t.2 ∧ -powBound ≤ t.1.val ∧ t.1.val + 1 ≤ powBound

lemma monomial_wf {inst : bulletproofspp.laurent.Coefficient C} {ψ : C → Cm} {P : C → Prop}
    (t : I32 × C) (ht : TermOK P t) :
    bulletproofspp.laurent.Laurent.monomial inst t.1 t.2 ⦃ r =>
      WF P r ∧ toL ψ r = Bppp.Laurent.monomial t.1.val (ψ t.2) ⦄ := by
  apply WP.spec_mono (monomial_spec inst t.1 t.2)
  rintro r ⟨hlow, hc⟩
  refine ⟨⟨by simp [hc], by simp [hc]; exact ht.1, by rw [hlow]; exact ht.2.1, ?_⟩, ?_⟩
  · have : r.coeffs.length = 1 := by simp [alloc.vec.Vec.length, hc]
    rw [this, hlow]; exact_mod_cast ht.2.2
  · simp [toL, hlow, hc, Bppp.Laurent.monomial, Bppp.Laurent.new]

lemma from_terms_loop_spec (hs : ScalarModel F φ) {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (terms : alloc.vec.Vec (I32 × C)) (hterms : ∀ t ∈ terms.val, TermOK P t)
    (acc : bulletproofspp.laurent.Laurent C) (hacc : WF P acc) (i : Usize)
    (hi : i.val ≤ terms.length) :
    bulletproofspp.laurent.Laurent.from_terms_loop inst terms acc i ⦃ r =>
      WF P r ∧ toL ψ r = (terms.val.drop i.val).foldl
        (fun acc (p, c) => acc + Bppp.Laurent.monomial p.val (ψ c)) (toL ψ acc) ⦄ := by
  unfold bulletproofspp.laurent.Laurent.from_terms_loop
  apply loop.spec_decr_nat (fun q => terms.length - q.2.val)
    (fun q => q.2.val ≤ terms.length ∧ WF P q.1 ∧
      (terms.val.drop q.2.val).foldl
        (fun acc (p, c) => acc + Bppp.Laurent.monomial p.val (ψ c)) (toL ψ q.1) =
      (terms.val.drop i.val).foldl
        (fun acc (p, c) => acc + Bppp.Laurent.monomial p.val (ψ c)) (toL ψ acc))
  · rintro ⟨a, j⟩ ⟨hj, ha, heq⟩
    dsimp only at hj ha heq
    unfold bulletproofspp.laurent.Laurent.from_terms_loop.body
    simp only [BuiltinClone]
    step*
    · generalize ‹C› = c at *
      have hjl' : j.val < terms.val.length := by scalar_tac
      have ht : TermOK P (p, c) := by rw [p_post]; exact hterms _ (List.getElem_mem hjl')
      apply WP.spec_bind (monomial_wf (inst := inst) (ψ := ψ) (p, c) ht)
      rintro m ⟨hm, hψm⟩
      apply WP.spec_bind (add_spec hs hc a m ha hm)
      rintro r ⟨hr, hψr⟩
      step*
      refine ⟨by scalar_tac, hr, ?_, by scalar_tac⟩
      rw [← heq, List.drop_eq_getElem_cons hjl', ← p_post, i2_post, List.foldl_cons, hψr, hψm]
    · refine ⟨ha, ?_⟩
      rw [← heq, List.drop_of_length_le (by scalar_tac)]
      rfl
  · exact ⟨hi, hacc, rfl⟩

lemma from_terms_spec (hs : ScalarModel F φ) {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (terms : alloc.vec.Vec (I32 × C)) (hne : terms.val ≠ [])
    (hterms : ∀ t ∈ terms.val, TermOK P t) :
    bulletproofspp.laurent.Laurent.from_terms inst terms ⦃ r =>
      WF P r ∧ toL ψ r = Bppp.Laurent.from_terms (terms.val.map fun t => (t.1.val, ψ t.2)) ⦄ := by
  unfold bulletproofspp.laurent.Laurent.from_terms
  simp only [BuiltinClone]
  obtain ⟨t0, ts, hts⟩ := List.exists_cons_of_ne_nil hne
  step*
  generalize ‹C› = c at *
  have ht0 : (p, c) = t0 := by rw [p_post]; simp [hts]
  have hok : TermOK P (p, c) := ht0 ▸ hterms t0 (by simp [hts])
  apply WP.spec_bind (monomial_wf (inst := inst) (ψ := ψ) (p, c) hok)
  rintro m ⟨hm, hψm⟩
  apply WP.spec_mono (from_terms_loop_spec hs hc terms hterms m hm 1#usize
    (by simp [alloc.vec.Vec.length, hts]))
  rintro r ⟨hr, hψr⟩
  refine ⟨hr, ?_⟩
  rw [hψr, hψm]
  simp only [hts, List.map_cons, Bppp.Laurent.from_terms, ← ht0]
  simp [List.foldl_map]

lemma foldl_mul_const (a b : F) (n : ℕ) :
    (List.range n).foldl (fun acc _ => acc * b) a = a * b ^ n := by
  induction n generalizing a with
  | zero => simp
  | succ n ih => rw [List.range_succ, List.foldl_append, ih]; simp [pow_succ, mul_assoc]

/-- The first loop of `eval`: `x_pow * base ^ (|low| - k)`. -/
lemma eval_pow_loop_spec (body : S × U32 → Result (ControlFlow (S × U32) S))
    (hs : ScalarModel F φ) (low : I32) (base : S)
    (hbody : ∀ x_pow k, body (x_pow, k) = (do
      let i1 ← core.num.I32.unsigned_abs low
      if k < i1 then
        let x_pow1 ←
          groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulAssignRistrettoScalar.mul_assign
            x_pow base
        let k1 ← k + 1#u32
        ok (ControlFlow.cont (x_pow1, k1))
      else ok (ControlFlow.done x_pow)))
    (x_pow : S) (k : U32) (hk : k.val ≤ low.val.natAbs) :
    loop body (x_pow, k) ⦃ r => φ r = φ x_pow * φ base ^ (low.val.natAbs - k.val) ⦄ := by
  have hlow : low.val.natAbs ≤ 2 ^ 31 := by
    have h1 := low.hmin; have h2 := low.hmax
    simp only [IScalarTy.numBits] at h1 h2
    omega
  apply loop.spec_decr_nat (fun q => low.val.natAbs - q.2.val)
    (fun q => q.2.val ≤ low.val.natAbs ∧
      φ q.1 * φ base ^ (low.val.natAbs - q.2.val) = φ x_pow * φ base ^ (low.val.natAbs - k.val))
  · rintro ⟨xp, j⟩ ⟨hj, heq⟩
    dsimp only at hj heq
    rw [hbody]
    simp only [core.num.I32.unsigned_abs, bind_ok, hs.mul_assign_eq]
    have hu : (⟨BitVec.ofNat 32 low.val.natAbs⟩ : U32).val = low.val.natAbs := by
      show (BitVec.ofNat 32 low.val.natAbs).toNat = _
      rw [BitVec.toNat_ofNat]; apply Nat.mod_eq_of_lt; omega
    split
    · rename_i hjk
      have hjk' : j.val < low.val.natAbs := by rw [← hu]; exact hjk
      step*
      refine ⟨by omega, ?_, by omega⟩
      rw [← heq, k1_post, hs.φ_mulAF, mul_assoc, ← pow_succ']
      congr 2; omega
    · rename_i hjk
      have hjk' : ¬ j.val < low.val.natAbs := by rw [← hu]; exact hjk
      simp only [WP.spec_ok]
      rw [← heq, show low.val.natAbs - j.val = 0 by omega]
      simp
  · exact ⟨hk, rfl⟩

/-- The step of the second loop of `eval`, and of the `foldl` of `Bppp.Laurent.eval`. -/
def evalStep (x : F) : Cm × F → Cm → Cm × F :=
  fun (result, x_pow) c =>
    (Bppp.Coefficient.add result (Bppp.Coefficient.scale c (x_pow * x)), x_pow * x)

/-- The second loop of `eval`: adds up the coefficients from index `i` on. -/
lemma eval_sum_loop_spec {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P) (hs : ScalarModel F φ)
    (body : S × C × Usize → Result (ControlFlow (S × C × Usize) C))
    (v : alloc.vec.Vec C) (hv : ∀ c ∈ v.val, P c) (x : S)
    (hbody : ∀ x_pow result i, body (x_pow, result, i) = (do
      if i < v.len then
        let x_pow1 ←
          groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulAssignRistrettoScalar.mul_assign
            x_pow x
        let t ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice C) v i
        let t1 ← inst.scale t x_pow1
        let result1 ← inst.add result t1
        let i2 ← i + 1#usize
        ok (ControlFlow.cont (x_pow1, result1, i2))
      else ok (ControlFlow.done result)))
    (x_pow : S) (result : C) (hres : P result) (i : Usize) (hi : i.val ≤ v.length) :
    loop body (x_pow, result, i) ⦃ r =>
      P r ∧ ψ r = (((v.val.map ψ).drop i.val).foldl (evalStep (φ x)) (ψ result, φ x_pow)).1 ⦄ := by
  apply loop.spec_decr_nat (fun q => v.length - q.2.2.val)
    (fun q => q.2.2.val ≤ v.length ∧ P q.2.1 ∧
      ((v.val.map ψ).drop q.2.2.val).foldl (evalStep (φ x)) (ψ q.2.1, φ q.1) =
      ((v.val.map ψ).drop i.val).foldl (evalStep (φ x)) (ψ result, φ x_pow))
  · rintro ⟨xp, res, j⟩ ⟨hj, hP, heq⟩
    dsimp only at hj hP heq
    rw [hbody]
    simp only [hs.mul_assign_eq, bind_ok]
    split
    · rename_i hjl
      have hjl' : j.val < v.val.length := by scalar_tac
      step*
      obtain ⟨t1, ht1, hPt1, hψt1⟩ := hc.scale t (hs.mulAF xp x)
        (by rw [t_post]; exact hv _ (List.getElem_mem hjl'))
      obtain ⟨r1, hr1, hPr1, hψr1⟩ := hc.add res t1 hP hPt1
      rw [ht1, bind_ok, hr1, bind_ok]
      step*
      refine ⟨by scalar_tac, hPr1, ?_, by scalar_tac⟩
      rw [← heq, i2_post]
      conv_rhs => rw [List.drop_eq_getElem_cons (by simpa using hjl'), List.foldl_cons]
      simp [evalStep, hψr1, hψt1, t_post]
    · simp only [WP.spec_ok]
      refine ⟨hP, ?_⟩
      rw [← heq, List.drop_of_length_le (by simp; scalar_tac)]
      rfl
  · exact ⟨hi, hres, rfl⟩

lemma eval_spec (hs : ScalarModel F φ) {inst : bulletproofspp.laurent.Coefficient C}
    {ψ : C → Cm} {P : C → Prop} (hc : CoeffModel φ inst ψ P)
    (l : bulletproofspp.laurent.Laurent C) (hl : WF P l) (x : S) :
    bulletproofspp.laurent.Laurent.eval inst l x ⦃ r =>
      match (toL ψ l).eval (φ x) with
      | .ok c => ∃ c', r = .Ok c' ∧ P c' ∧ ψ c' = c
      | .error _ => r = .Err .InvalidInput ⦄ := by
  obtain ⟨hne, hP, hlo, hhi⟩ := hl
  have h0 : 0 < l.coeffs.val.length := List.length_pos_of_ne_nil hne
  obtain ⟨a, t, hat⟩ := List.exists_cons_of_ne_nil hne
  have hP0 : P l.coeffs.val[0] := hP _ (List.getElem_mem h0)
  have hhead : (l.coeffs.val.map ψ).head! = ψ l.coeffs.val[0] := by simp [hat]
  have htail : (l.coeffs.val.map ψ).tail = (l.coeffs.val.map ψ).drop 1 := by simp
  -- the shared part of both branches, from the base on
  have hrest : ∀ (base : S) (body0 : S × U32 → Result (ControlFlow (S × U32) S))
      (body1 : S × C × Usize → Result (ControlFlow (S × C × Usize) C)),
      (∀ x_pow k, body0 (x_pow, k) = (do
        let i1 ← core.num.I32.unsigned_abs l.low
        if k < i1 then
          let x_pow1 ←
            groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulAssignRistrettoScalar.mul_assign
              x_pow base
          let k1 ← k + 1#u32
          ok (ControlFlow.cont (x_pow1, k1))
        else ok (ControlFlow.done x_pow))) →
      (∀ x_pow result i, body1 (x_pow, result, i) = (do
        if i < l.coeffs.len then
          let x_pow1 ←
            groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulAssignRistrettoScalar.mul_assign
              x_pow x
          let t ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice C) l.coeffs i
          let t1 ← inst.scale t x_pow1
          let result1 ← inst.add result t1
          let i2 ← i + 1#usize
          ok (ControlFlow.cont (x_pow1, result1, i2))
        else ok (ControlFlow.done result))) →
      (do
        let x_pow1 ← loop body0 (hs.o, 0#u32)
        let t ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice C) l.coeffs 0#usize
        let result ← inst.scale t x_pow1
        let result1 ← loop body1 (x_pow1, result, 1#usize)
        (ok (core.result.Result.Ok result1) :
          Result (core.result.Result C error.FastCryptoError))) ⦃ r =>
        ∃ c', r = .Ok c' ∧ P c' ∧ ψ c' = ((l.coeffs.val.map ψ).tail.foldl
          (fun (result, x_pow) c => (Bppp.Coefficient.add result
            (Bppp.Coefficient.scale c (x_pow * φ x)), x_pow * φ x))
          (Bppp.Coefficient.scale (l.coeffs.val.map ψ).head! (φ base ^ l.low.val.natAbs),
            φ base ^ l.low.val.natAbs)).1 ⦄ := by
    intro base body0 body1 h0' h1'
    apply WP.spec_bind (eval_pow_loop_spec body0 hs l.low base h0' hs.o 0#u32 (by simp))
    intro xp hxp
    step*
    obtain ⟨r0, hr0, hPr0, hψr0⟩ := hc.scale t xp (by rw [t_post]; exact hP0)
    rw [hr0, bind_ok]
    apply WP.spec_bind (eval_sum_loop_spec hc hs body1 l.coeffs hP x h1' xp r0 hPr0 1#usize
      (by simp [alloc.vec.Vec.length]; omega))
    rintro r ⟨hPr, hψr⟩
    simp only [WP.spec_ok]
    refine ⟨r, rfl, hPr, ?_⟩
    rw [hψr, htail, hhead, hψr0, t_post, hxp]
    simp
    rfl
  unfold bulletproofspp.laurent.Laurent.eval
  simp only [one_spec hs, bind_ok]
  split
  · rename_i hneg
    have hneg' : l.low.val < 0 := by scalar_tac
    by_cases hx : φ x = 0
    · rw [hs.inverse_zero x hx]
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
        Bppp.Laurent.eval, toL, hneg', Bppp.inverse, hx]
    · obtain ⟨b, hb, hbv⟩ := hs.inverse x hx
      rw [hb]
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
      apply WP.spec_mono (hrest b _ _ (fun _ _ => rfl) (fun _ _ _ => rfl))
      rintro r ⟨c', hr, hPc, hψc⟩
      simp only [Bppp.Laurent.eval, toL, hneg', ite_true, Bppp.inverse, hx, ite_false]
      refine ⟨c', hr, hPc, ?_⟩
      rw [hψc, hbv]
      simp [foldl_mul_const, Bppp.one]
  · rename_i hneg
    have hneg' : ¬ l.low.val < 0 := by scalar_tac
    apply WP.spec_mono (hrest x _ _ (fun _ _ => rfl) (fun _ _ _ => rfl))
    rintro r ⟨c', hr, hPc, hψc⟩
    simp only [Bppp.Laurent.eval, toL, hneg', ite_false]
    refine ⟨c', hr, hPc, ?_⟩
    rw [hψc]
    simp [foldl_mul_const, Bppp.one]

end Generic

variable {C : Type}

lemma foldl_zipIdx_take_succ {α β : Type} (l : List α) (f : β → α × ℕ → β) (b : β) (k : ℕ)
    (hk : k < l.length) :
    (l.zipIdx.take (k + 1)).foldl f b = f ((l.zipIdx.take k).foldl f b) (l[k], k) := by
  rw [List.take_succ_eq_append_getElem (by simpa using hk), List.foldl_append]
  simp

/-- The inner step of `Bppp.Laurent.inner_product`: row `a` at index `i` against `other`. -/
def ipInner (a : List F) (i : ℕ) (coeffs : List F) (bj : List F × ℕ) : List F :=
  coeffs.modify (i + bj.2) (· + Bppp.inner_product a bj.1)

/-- The outer step of `Bppp.Laurent.inner_product`. -/
def ipOuter (other : List (List F)) (coeffs : List F) (ai : List F × ℕ) : List F :=
  other.zipIdx.foldl (ipInner ai.1 ai.2) coeffs

/-- Every coefficient of a vector polynomial has length `n`. -/
def VecLen (n : ℕ) (v : alloc.vec.Vec S) : Prop := v.length = n

lemma ip_inner_loop_spec (hs : ScalarModel F φ) (n : ℕ)
    (v v1 : alloc.vec.Vec (alloc.vec.Vec S)) (hv : ∀ c ∈ v.val, VecLen n c)
    (hv1 : ∀ c ∈ v1.val, VecLen n c) (i : Usize) (hi : i.val < v.length)
    (coeffs : alloc.vec.Vec S) (hcl : coeffs.length = v.length + v1.length - 1)
    (j : Usize) (hj : j.val ≤ v1.length) :
    bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product_loop0_loop0 v v1 coeffs i j
      ⦃ r => r.length = coeffs.length ∧ r.val.map φ =
        ((v1.val.map (·.val.map φ)).zipIdx.drop j.val).foldl
          (ipInner (v.val[i.val].val.map φ) i.val) (coeffs.val.map φ) ⦄ := by
  unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product_loop0_loop0
  apply loop.spec_decr_nat (fun q => v1.length - q.2.val)
    (fun q => q.2.val ≤ v1.length ∧ q.1.length = coeffs.length ∧
      ((v1.val.map (·.val.map φ)).zipIdx.drop q.2.val).foldl
          (ipInner (v.val[i.val].val.map φ) i.val) (q.1.val.map φ) =
      ((v1.val.map (·.val.map φ)).zipIdx.drop j.val).foldl
          (ipInner (v.val[i.val].val.map φ) i.val) (coeffs.val.map φ))
  · rintro ⟨c, k⟩ ⟨hk, hcl', heq⟩
    dsimp only at hk hcl' heq
    unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product_loop0_loop0.body
    have hcmax : coeffs.val.length ≤ Usize.max := coeffs.property
    have hcl0 : coeffs.val.length = v.val.length + v1.val.length - 1 := hcl
    have hcl1 : c.val.length = coeffs.val.length := hcl'
    have e1 : v.length = v.val.length := rfl
    have e2 : v1.length = v1.val.length := rfl
    step*
    · scalar_tac
    · have : k.val < v1.val.length := by scalar_tac
      have : c.length = c.val.length := rfl
      omega
    · have hkl : k.val < v1.val.length := by scalar_tac
      have hil : i.val < v.val.length := hi
      have hlen : (v2.deref).length = (v3.deref).length := by
        have h1 : VecLen n v2 := by rw [v2_post]; exact hv _ (List.getElem_mem _)
        have h2 : VecLen n v3 := by rw [v3_post]; exact hv1 _ (List.getElem_mem _)
        simpa [VecLen, alloc.vec.Vec.deref, alloc.vec.Vec.length, Slice.length] using
          h1.trans h2.symm
      apply WP.spec_bind (inner_product_spec hs v2.deref v3.deref hlen)
      intro rs1 hrs1
      simp only [hs.add_assign_eq, bind_ok]
      step*
      have hi2 : i2.val < c.val.length := by
        have : k.val < v1.val.length := hkl
        omega
      refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, index_mut_back_post]; exact hcl', ?_,
        by scalar_tac⟩
      rw [← heq, j1_post]
      conv_rhs => rw [List.drop_eq_getElem_cons (by simpa using hkl), List.foldl_cons]
      congr 1
      rw [index_mut_back_post]
      simp only [alloc.vec.Vec.set_val_eq, List.map_set, ipInner, List.getElem_zipIdx,
        List.getElem_map]
      rw [show i.val + (0 + k.val) = i2.val by omega]
      apply List.ext_getElem (by simp)
      intro m h1 h2
      rw [List.getElem_set, List.getElem_modify]
      split
      · rename_i hm
        subst hm
        simp [hrs1, rs_post, v2_post, v3_post, alloc.vec.Vec.deref]
      · rfl
    · refine ⟨hcl', ?_⟩
      rw [← heq, List.drop_of_length_le (by simp; scalar_tac)]
      rfl
  · exact ⟨hj, rfl, rfl⟩

lemma ip_outer_loop_spec (hs : ScalarModel F φ) (n : ℕ)
    (v v1 : alloc.vec.Vec (alloc.vec.Vec S)) (hv : ∀ c ∈ v.val, VecLen n c)
    (hv1 : ∀ c ∈ v1.val, VecLen n c)
    (coeffs : alloc.vec.Vec S) (hcl : coeffs.length = v.length + v1.length - 1)
    (i : Usize) (hi : i.val ≤ v.length) :
    bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product_loop0 v v1 coeffs i
      ⦃ r => r.val.map φ = ((v.val.map (·.val.map φ)).zipIdx.drop i.val).foldl
          (ipOuter (v1.val.map (·.val.map φ))) (coeffs.val.map φ) ⦄ := by
  unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product_loop0
  apply loop.spec_decr_nat (fun q => v.length - q.2.val)
    (fun q => q.2.val ≤ v.length ∧ q.1.length = coeffs.length ∧
      ((v.val.map (·.val.map φ)).zipIdx.drop q.2.val).foldl
          (ipOuter (v1.val.map (·.val.map φ))) (q.1.val.map φ) =
      ((v.val.map (·.val.map φ)).zipIdx.drop i.val).foldl
          (ipOuter (v1.val.map (·.val.map φ))) (coeffs.val.map φ))
  · rintro ⟨c, k⟩ ⟨hk, hcl', heq⟩
    dsimp only at hk hcl' heq
    unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product_loop0.body
    step*
    · have hkl' : k.val < v.val.length := by scalar_tac
      apply WP.spec_bind (ip_inner_loop_spec hs n v v1 hv hv1 k (by scalar_tac) c
        (by rw [hcl']; exact hcl) 0#usize (by simp))
      rintro r ⟨hrl, hr⟩
      step*
      refine ⟨by scalar_tac, by rw [hrl, hcl'], ?_, by scalar_tac⟩
      rw [← heq, i2_post]
      conv_rhs => rw [List.drop_eq_getElem_cons (by simpa using hkl'), List.foldl_cons]
      rw [hr]
      simp [ipOuter]
    · rw [← heq, List.drop_of_length_le (by simp; scalar_tac)]
      rfl
  · exact ⟨hi, rfl, rfl⟩

lemma foldl_ipOuter_length (o : List (List F)) (l : List (List F × ℕ)) (c : List F) :
    (l.foldl (ipOuter o) c).length = c.length := by
  induction l generalizing c with
  | nil => rfl
  | cons x l ih =>
    rw [List.foldl_cons, ih]
    unfold ipOuter
    generalize o.zipIdx = m
    induction m generalizing c with
    | nil => rfl
    | cons y m ih' => rw [List.foldl_cons, ih']; simp [ipInner]

/-- The model of a vector coefficient. -/
def vecψ (φ : S → F) (v : alloc.vec.Vec S) : List F := v.val.map φ

/-- A polynomial whose powers lie within half of `powBound`, so that products stay within it. -/
def Half (l : bulletproofspp.laurent.Laurent C) : Prop :=
  -(powBound / 2) ≤ l.low.val ∧ l.low.val + l.coeffs.length ≤ powBound / 2

lemma inner_product_spec' (hs : ScalarModel F φ) (n : ℕ)
    (a b : bulletproofspp.laurent.Laurent (alloc.vec.Vec S)) (ha : WF (VecLen n) a)
    (hb : WF (VecLen n) b) (ha' : Half a) (hb' : Half b) :
    bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product a b ⦃ r =>
      WF (fun _ => True) r ∧
      toL φ r = (toL (vecψ φ) a).inner_product (toL (vecψ φ) b) ⦄ := by
  obtain ⟨hane, haP, -, -⟩ := ha
  obtain ⟨hbne, hbP, -, -⟩ := hb
  obtain ⟨halo, hahi⟩ := ha'
  obtain ⟨hblo, hbhi⟩ := hb'
  have hal : 0 < a.coeffs.val.length := List.length_pos_of_ne_nil hane
  have hbl : 0 < b.coeffs.val.length := List.length_pos_of_ne_nil hbne
  have e1 : a.coeffs.length = a.coeffs.val.length := rfl
  have e2 : b.coeffs.length = b.coeffs.val.length := rfl
  simp only [powBound] at halo hahi hblo hbhi
  norm_num at halo hahi hblo hbhi
  unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.inner_product
  simp only [hs.zero_eq, bind_ok]
  step*
  · simp [hs.clone]
  · apply WP.spec_bind (ip_outer_loop_spec hs n a.coeffs b.coeffs haP hbP coeffs
      (by scalar_tac) 0#usize (by simp))
    intro r hr
    step*
    have hi3 : i3.val = a.coeffs.val.length + b.coeffs.val.length - 1 := by scalar_tac
    have hrl : r.val.length = a.coeffs.val.length + b.coeffs.val.length - 1 := by
      have := congrArg List.length hr
      rw [List.length_map, foldl_ipOuter_length] at this
      rw [this]; simp [coeffs_post, hi3]
    have hrne : r.val ≠ [] := by
      intro h; rw [h] at hrl; simp at hrl; omega
    apply WP.spec_mono (new_spec _ i4 r hrne)
    intro q hq
    subst hq
    refine ⟨⟨hrne, fun _ _ => trivial, by simp only [powBound]; scalar_tac,
      by simp only [powBound, alloc.vec.Vec.length]; scalar_tac⟩, ?_⟩
    simp only [toL, Bppp.Laurent.inner_product, Bppp.Laurent.new, hr, i4_post, coeffs_post,
      hi3, List.map_replicate, hs.φ_z, List.length_map]
    rfl

lemma eq_ok_of_spec {α : Type} {m : Result α} {a : α} (h : m ⦃ x => x = a ⦄) : m = ok a := by
  cases m with
  | ret b => have := (WP.spec_ok b).mp h; rw [this]
  | vis e k => exact absurd h (by simp)
  | div => exact absurd h (by simp)

lemma vec_clone_eq (hs : ScalarModel F φ) (v : alloc.vec.Vec S) :
    alloc.vec.CloneVec.clone groups.ristretto255.RistrettoScalar.Insts.CoreCloneClone v = ok v := by
  apply eq_ok_of_spec
  unfold alloc.vec.CloneVec.clone
  apply WP.spec_bind (Slice.clone_spec (fun x _ => hs.clone x))
  intro s' hs'
  simp only [WP.spec_ok]
  rw [← hs']

/-- `Vec<RistrettoScalar>` as a coefficient type, on vectors of length `n`. -/
lemma vec_coeff_model (hs : ScalarModel F φ) (n : ℕ) :
    CoeffModel φ alloc.vec.VecRistrettoScalar.Insts.FastcryptoBulletproofsppLaurentCoefficient
      (vecψ φ) (VecLen n) where
  clone a := vec_clone_eq hs a
  add a b ha hb := by
    have hab : (alloc.vec.Vec.deref a).length = (alloc.vec.Vec.deref b).length := by
      have : a.length = b.length := ha.trans hb.symm
      simpa [alloc.vec.Vec.deref, alloc.vec.Vec.length, Slice.length] using this
    obtain ⟨c, hc, hcv⟩ := spec_eq_ok' (vec_add_spec hs _ _ hab)
    refine ⟨c, hc, ?_, ?_⟩
    · have := congrArg List.length hcv
      simp [Bppp.vec_add, alloc.vec.Vec.deref] at this
      have ha' : a.val.length = n := ha
      have hb' : b.val.length = n := hb
      show c.val.length = n
      omega
    · show vecψ φ c = Bppp.vec_add (vecψ φ a) (vecψ φ b)
      simpa [vecψ, alloc.vec.Vec.deref] using hcv
  scale a s ha := by
    obtain ⟨c, hc, hcv⟩ := spec_eq_ok' (vec_scalar_mul_spec hs s (alloc.vec.Vec.deref a))
    refine ⟨c, hc, ?_, ?_⟩
    · have := congrArg List.length hcv
      simp [Bppp.vec_scalar_mul, alloc.vec.Vec.deref] at this
      have ha' : a.val.length = n := ha
      show c.val.length = n
      omega
    · show vecψ φ c = Bppp.vec_scalar_mul (φ s) (vecψ φ a)
      simpa [vecψ, alloc.vec.Vec.deref] using hcv

lemma wip_loop_spec (hs : ScalarModel F φ) (n : ℕ) (v : alloc.vec.Vec (alloc.vec.Vec S))
    (hv : ∀ c ∈ v.val, VecLen n c) (w : Slice S) (hw : w.length = n)
    (out : alloc.vec.Vec (alloc.vec.Vec S)) (i : Usize) (hi : i.val ≤ v.length)
    (ho : out.length = i.val) (hout : (∀ c ∈ out.val, VecLen n c) ∧
      out.val.map (vecψ φ) = (v.val.take i.val).map fun a => Bppp.hadamard (vecψ φ a) (w.val.map φ)) :
    bulletproofspp.laurent.LaurentVecRistrettoScalar.weighted_inner_product_loop v w out i ⦃ r =>
      (∀ c ∈ r.val, VecLen n c) ∧
      r.val.map (vecψ φ) = v.val.map fun a => Bppp.hadamard (vecψ φ a) (w.val.map φ) ⦄ := by
  unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.weighted_inner_product_loop
  apply loop.spec_decr_nat (fun p => v.length - p.2.val)
    (fun p => p.2.val ≤ v.length ∧ p.1.length = p.2.val ∧ (∀ c ∈ p.1.val, VecLen n c) ∧
      p.1.val.map (vecψ φ) = (v.val.take p.2.val).map
        fun a => Bppp.hadamard (vecψ φ a) (w.val.map φ))
  · rintro ⟨o, j⟩ ⟨hj, hoj, hP', heq⟩
    dsimp only at hj hoj hP' heq
    unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.weighted_inner_product_loop.body
    step*
    · have hjl : j.val < v.val.length := by scalar_tac
      have hlen : (alloc.vec.Vec.deref v1).length = w.length := by
        have h1 : VecLen n v1 := by rw [v1_post]; exact hv _ (List.getElem_mem _)
        rw [hw]; simpa [VecLen, alloc.vec.Vec.deref, alloc.vec.Vec.length, Slice.length] using h1
      apply WP.spec_bind (hadamard_spec hs _ w hlen)
      intro h hh
      have hhl : h.val.length = n := by
        have := congrArg List.length hh
        simp [Bppp.hadamard, alloc.vec.Vec.deref] at this
        have h1 : v1.val.length = n := by rw [v1_post]; exact hv _ (List.getElem_mem _)
        have : w.val.length = n := hw
        omega
      step*
      refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, coeffs1_post]; scalar_tac, ?_, ?_,
        by scalar_tac⟩
      · intro x hx
        rw [coeffs1_post] at hx
        rcases List.mem_append.1 hx with hx | hx
        · exact hP' x hx
        · simp at hx; subst hx; exact hhl
      · rw [coeffs1_post, i2_post, List.take_succ_eq_append_getElem hjl]
        simp only [List.map_append, heq, List.map_cons, List.map_nil]
        congr 2
        simp only [vecψ]; rw [hh, v1_post]; simp [alloc.vec.Vec.deref]
    · have : j.val = v.val.length := by scalar_tac
      refine ⟨hP', ?_⟩
      rw [heq, this, List.take_length]
  · exact ⟨hi, ho, hout⟩

lemma weighted_inner_product_spec' (hs : ScalarModel F φ) (n : ℕ)
    (a b : bulletproofspp.laurent.Laurent (alloc.vec.Vec S)) (ha : WF (VecLen n) a)
    (hb : WF (VecLen n) b) (ha' : Half a) (hb' : Half b) (w : Slice S) (hw : w.length = n) :
    bulletproofspp.laurent.LaurentVecRistrettoScalar.weighted_inner_product a b w ⦃ r =>
      WF (fun _ => True) r ∧
      toL φ r = (toL (vecψ φ) a).weighted_inner_product (toL (vecψ φ) b) (w.val.map φ) ⦄ := by
  have ha0 := ha
  obtain ⟨hane, haP, halo, hahi⟩ := ha0
  unfold bulletproofspp.laurent.LaurentVecRistrettoScalar.weighted_inner_product
  apply WP.spec_bind (wip_loop_spec hs n a.coeffs haP w hw _ 0#usize (by simp) (by simp)
    (by simp))
  rintro c ⟨hcP, hc⟩
  have hcl : c.val.length = a.coeffs.val.length := by simpa using congrArg List.length hc
  have hcne : c.val ≠ [] := by
    intro h; rw [h] at hcl; exact hane (List.eq_nil_of_length_eq_zero hcl.symm)
  apply WP.spec_bind (new_spec _ a.low c hcne)
  intro q hq
  subst hq
  have hq : WF (VecLen n) { low := a.low, coeffs := c } :=
    ⟨hcne, hcP, halo, by simpa [alloc.vec.Vec.length, hcl] using hahi⟩
  have hq' : Half { low := a.low, coeffs := c } := by
    obtain ⟨h1, h2⟩ := ha'
    exact ⟨h1, by simpa [alloc.vec.Vec.length, hcl] using h2⟩
  apply WP.spec_mono (inner_product_spec' hs n _ b hq hb hq' hb')
  rintro r ⟨hr, hψr⟩
  refine ⟨hr, ?_⟩
  rw [hψr]
  simp only [Bppp.Laurent.weighted_inner_product, Bppp.Laurent.new, toL, hc, List.map_map]
  rfl

end BpppProofs
