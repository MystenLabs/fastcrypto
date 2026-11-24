-- THIS FILE IS AI-ONLY
import bulletproofspp.NormLinear
import bulletproofspp.Model.Circuit

/-!
The helpers of `circuit.rs` compute the functions of `Model/Circuit.lean`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

/-- A loop that pushes, for `i` from `i₀` to `n - 1`, a value that `ψ` maps to `g i`, onto a
vector whose length is `i` up to the offsets `a`, `b`. -/
lemma push_loop_off {α β : Type} {body : alloc.vec.Vec α × Usize →
      Result (ControlFlow (alloc.vec.Vec α × Usize) (alloc.vec.Vec α))}
    (a b n : ℕ) (ψ : α → β) (g : ℕ → β)
    (hbody : ∀ v i, v.length + a = i.val + b → i.val < n →
      body (v, i) ⦃ r => ∃ v' i', r = .cont (v', i') ∧ (∃ x, v'.val = v.val ++ [x] ∧ ψ x = g i.val) ∧
        i'.val = i.val + 1 ⦄)
    (hdone : ∀ v i, v.length + a = i.val + b → n ≤ i.val → body (v, i) ⦃ r => r = .done v ⦄)
    (v : alloc.vec.Vec α) (i : Usize) (hv : v.length + a = i.val + b) (hi : i.val ≤ n) :
    loop body (v, i) ⦃ r =>
      r.val.map ψ = v.val.map ψ ++ (List.range' i.val (n - i.val)).map g ⦄ := by
  apply loop.spec_decr_nat (fun p => n - p.2.val)
    (fun p => p.1.length + a = p.2.val + b ∧ p.2.val ≤ n ∧
      p.1.val.map ψ ++ (List.range' p.2.val (n - p.2.val)).map g =
        v.val.map ψ ++ (List.range' i.val (n - i.val)).map g)
  · rintro ⟨v', i'⟩ ⟨hv', hi', heq⟩
    simp only at hv' hi' heq
    by_cases hlt : i'.val < n
    · apply WP.spec_mono (hbody v' i' hv' hlt)
      rintro r ⟨v'', i'', rfl, ⟨x, hv'', hx⟩, hi''⟩
      dsimp only
      have hl : v''.length = v'.length + 1 := by
        simp only [alloc.vec.Vec.length, hv'', List.length_append, List.length_singleton]
      refine ⟨⟨by omega, by omega, ?_⟩, by omega⟩
      rw [← heq, hv'', hi'', show n - i'.val = (n - (i'.val + 1)) + 1 by omega,
        List.range'_succ]
      simp [hx]
    · apply WP.spec_mono (hdone v' i' hv' (by omega))
      intro r hr
      subst hr
      rw [← heq, show n - i'.val = 0 by omega]
      simp
  · exact ⟨hv, hi, rfl⟩

section Shape

variable {C Cm : Type} [Inhabited Cm] [Bppp.Coefficient F Cm]

/-- The powers of a model polynomial lie in `[lo, hi)`, and it has a coefficient. -/
def Spans (l : Bppp.Laurent Cm) (lo hi : ℤ) : Prop :=
  l.coeffs ≠ [] ∧ lo ≤ l.low ∧ l.low + l.coeffs.length ≤ hi

lemma spans_mono {l : Bppp.Laurent Cm} {lo hi lo' hi' : ℤ} (h : Spans l lo hi) (h1 : lo' ≤ lo)
    (h2 : hi ≤ hi') : Spans l lo' hi' :=
  ⟨h.1, by have := h.2.1; omega, by have := h.2.2; omega⟩

lemma spans_monomial (p : ℤ) (c : Cm) : Spans (Bppp.Laurent.monomial p c) p (p + 1) := by
  simp [Spans, Bppp.Laurent.monomial, Bppp.Laurent.new]

lemma spans_add {A B : Bppp.Laurent Cm} {lo1 hi1 lo2 hi2 : ℤ} (hA : Spans A lo1 hi1)
    (hB : Spans B lo2 hi2) : Spans (A + B) (min lo1 lo2) (max hi1 hi2) := by
  obtain ⟨hA0, hA1, hA2⟩ := hA
  obtain ⟨hB0, hB1, hB2⟩ := hB
  have a := List.length_pos_of_ne_nil hA0
  have b := List.length_pos_of_ne_nil hB0
  show Spans (Bppp.Laurent.add A B) _ _
  simp only [Spans, Bppp.Laurent.add, Bppp.Laurent.new, Bppp.Laurent.degree, List.length_map,
    List.length_range, ne_eq, List.map_eq_nil_iff, List.range_eq_nil]
  omega

lemma spans_scale {A : Bppp.Laurent Cm} {lo hi : ℤ} (hA : Spans A lo hi) (s : F) :
    Spans (A.scale s) lo hi := by
  obtain ⟨h0, h1, h2⟩ := hA
  simp only [Spans, Bppp.Laurent.scale, Bppp.Laurent.new, List.length_map, ne_eq,
    List.map_eq_nil_iff]
  exact ⟨h0, h1, h2⟩

lemma spans_sub {A B : Bppp.Laurent Cm} {lo1 hi1 lo2 hi2 : ℤ} (hA : Spans A lo1 hi1)
    (hB : Spans B lo2 hi2) : Spans (A - B) (min lo1 lo2) (max hi1 hi2) :=
  spans_add hA (spans_scale hB _)

lemma spans_from_terms (t : ℤ × Cm) (ts : List (ℤ × Cm)) (lo hi : ℤ)
    (h : ∀ x ∈ t :: ts, lo ≤ x.1 ∧ x.1 + 1 ≤ hi) :
    Spans (Bppp.Laurent.from_terms (t :: ts)) lo hi := by
  have key : ∀ (ts : List (ℤ × Cm)) (acc : Bppp.Laurent Cm), Spans acc lo hi →
      (∀ x ∈ ts, lo ≤ x.1 ∧ x.1 + 1 ≤ hi) →
      Spans (ts.foldl (fun acc (p, c) => acc + Bppp.Laurent.monomial p c) acc) lo hi := by
    intro ts
    induction ts with
    | nil => intro acc hacc _; exact hacc
    | cons x ts ih =>
      intro acc hacc hts
      have hx := hts x (by simp)
      have hm := spans_mono (spans_monomial x.1 x.2) hx.1 hx.2
      have := spans_add hacc hm
      rw [min_self, max_self] at this
      exact ih _ this fun y hy => hts y (by simp [hy])
  obtain ⟨p, c⟩ := t
  have ht := h (p, c) (by simp)
  exact key ts _ (spans_mono (spans_monomial p c) ht.1 ht.2) fun y hy => h y (by simp [hy])

lemma foldl_modify_length (_f : F → F) : ∀ (xs : List (List F × ℕ)) (ys : List (List F × ℕ))
    (g : List F → List F → F) (L : List F),
    (xs.foldl (fun coeffs (a, i) => ys.foldl (fun coeffs (b, j) =>
      coeffs.modify (i + j) (· + g a b)) coeffs) L).length = L.length := by
  intro xs ys g
  have inner : ∀ (ys : List (List F × ℕ)) (a : List F) (i : ℕ) (L : List F),
      (ys.foldl (fun coeffs (b, j) => coeffs.modify (i + j) (· + g a b)) L).length = L.length := by
    intro ys
    induction ys with
    | nil => intro _ _ _; rfl
    | cons y ys ih => intro a i L; rw [List.foldl_cons, ih, List.length_modify]
  induction xs with
  | nil => intro _; rfl
  | cons x xs ih => intro L; rw [List.foldl_cons, ih, inner]

lemma spans_inner_product {A B : Bppp.Laurent (List F)} {lo1 hi1 lo2 hi2 : ℤ}
    (hA : Spans A lo1 hi1) (hB : Spans B lo2 hi2) :
    Spans (A.inner_product B) (lo1 + lo2) (hi1 + hi2 - 1) := by
  obtain ⟨hA0, hA1, hA2⟩ := hA
  obtain ⟨hB0, hB1, hB2⟩ := hB
  have a := List.length_pos_of_ne_nil hA0
  have b := List.length_pos_of_ne_nil hB0
  have hlen := foldl_modify_length id A.coeffs.zipIdx B.coeffs.zipIdx Bppp.inner_product
    (List.replicate (A.coeffs.length + B.coeffs.length - 1) 0)
  simp only [List.length_replicate] at hlen
  refine ⟨List.ne_nil_of_length_pos ?_, ?_, ?_⟩
  · simp only [Bppp.Laurent.inner_product, Bppp.Laurent.new]; rw [hlen]; omega
  · simp only [Bppp.Laurent.inner_product, Bppp.Laurent.new]; omega
  · simp only [Bppp.Laurent.inner_product, Bppp.Laurent.new]; rw [hlen]; omega

lemma spans_weighted_inner_product {A B : Bppp.Laurent (List F)} {lo1 hi1 lo2 hi2 : ℤ}
    (hA : Spans A lo1 hi1) (hB : Spans B lo2 hi2) (w : List F) :
    Spans (A.weighted_inner_product B w) (lo1 + lo2) (hi1 + hi2 - 1) := by
  apply spans_inner_product _ hB
  obtain ⟨h0, h1, h2⟩ := hA
  simp only [Spans, Bppp.Laurent.new, List.length_map, ne_eq, List.map_eq_nil_iff]
  exact ⟨h0, h1, h2⟩

/-- A generated polynomial whose model spans powers within half of `powBound` is `Half`. -/
lemma half_of_spans {ψ : C → Cm} {r : bulletproofspp.laurent.Laurent C} {M : Bppp.Laurent Cm}
    {lo hi : ℤ} (hr : toL ψ r = M) (hM : Spans M lo hi) (hlo : -(powBound / 2) ≤ lo)
    (hhi : hi ≤ powBound / 2) : Half r := by
  subst hr
  obtain ⟨_, h1, h2⟩ := hM
  simp only [toL, List.length_map] at h1 h2
  exact ⟨by omega, by simp only [alloc.vec.Vec.length]; omega⟩

lemma spans_of_toL {ψ : C → Cm} {Pr : C → Prop} {r : bulletproofspp.laurent.Laurent C}
    (hr : WF Pr r) : Spans (toL ψ r) r.low.val (r.low.val + r.coeffs.length) := by
  obtain ⟨h0, _, _, _⟩ := hr
  simp only [Spans, toL, ne_eq, List.map_eq_nil_iff, List.length_map, le_refl, and_true]
  exact h0

end Shape

lemma cr_val : bulletproofspp.circuit.CR_POWERS.val.map (·.val) = Bppp.Circuit.CR_POWERS := by
  unfold bulletproofspp.circuit.CR_POWERS
  simp [Array.make, Bppp.Circuit.CR_POWERS]

lemma cr_len : bulletproofspp.circuit.CR_POWERS.val.length = 7 := by
  unfold bulletproofspp.circuit.CR_POWERS
  simp [Array.make]

lemma cr_get (j : ℕ) (h : j < 7) :
    Bppp.Circuit.CR_POWERS[j]'(by simp [Bppp.Circuit.CR_POWERS]; omega) =
      (bulletproofspp.circuit.CR_POWERS.val[j]'(by rw [cr_len]; exact h)).val := by
  simp only [← cr_val, List.getElem_map]

lemma is_cr_power_spec (power : I32) :
    bulletproofspp.circuit.is_cr_power power ⦃ b =>
      b = decide (power.val ∈ Bppp.Circuit.CR_POWERS) ⦄ := by
  unfold bulletproofspp.circuit.is_cr_power bulletproofspp.circuit.is_cr_power_loop
  apply loop.spec_decr_nat (fun p => 7 - p.2.val)
    (fun p => p.2.val ≤ 7 ∧ p.1 = decide (power.val ∈ Bppp.Circuit.CR_POWERS.take p.2.val))
  · rintro ⟨found, j⟩ ⟨hj, hf⟩
    simp only at hj hf
    unfold bulletproofspp.circuit.is_cr_power_loop.body
    step*
    · have hj7 : j.val < 7 := by scalar_tac
      have hc : Bppp.Circuit.CR_POWERS.take (j.val + 1) =
          Bppp.Circuit.CR_POWERS.take j.val ++ [i1.val] := by
        rw [List.take_succ_eq_append_getElem (by simp [Bppp.Circuit.CR_POWERS]; omega),
          cr_get _ hj7, i1_post]
      by_cases h : i1 = power
      · simp only [h, if_true, bind_ok]
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [j1_post, hc]
        simp [h]
      · simp only [h, if_false, bind_ok]
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        have hne : power.val ≠ i1.val := fun h' => h (IScalar.eq_of_val_eq h'.symm)
        rw [j1_post, hc, hf]
        simp [hne]
    · have hj7 : j.val = 7 := by scalar_tac
      rw [hf, hj7]
      simp [Bppp.Circuit.CR_POWERS]
  · simp

/-- The generated `Coefficient` instance of `RistrettoScalar` computes the model's. -/
lemma scalar_coeff_model (hs : ScalarModel F φ) :
    CoeffModel φ groups.ristretto255.RistrettoScalar.Insts.FastcryptoBulletproofsppLaurentCoefficient
      φ (fun _ => True) where
  clone a := hs.clone a
  add a b _ _ := ⟨hs.addRF a b, hs.add_ref_eq a b, trivial, by simp [Bppp.Coefficient.add]⟩
  scale a s _ := ⟨hs.mulF a s, hs.mul_eq a s, trivial, by simp [Bppp.Coefficient.scale]⟩

lemma message_opening_spec (hs : ScalarModel F φ) (r : Slice S) (n : alloc.vec.Vec S)
    (hr : 0 < r.length) :
    bulletproofspp.circuit.message_opening r n ⦃ o =>
      toO φ o = Bppp.Circuit.message_opening (r.val.map φ) (n.val.map φ) ∧
        o.l.length = r.length ∧ o.n = n ⦄ := by
  unfold bulletproofspp.circuit.message_opening bulletproofspp.circuit.message_opening_loop
  have er : r.len.val = r.val.length := rfl
  have erl : r.length = r.val.length := rfl
  apply WP.spec_bind (push_loop_off 1 0 r.length φ (fun i => φ (r.val.getD i hs.z))
    (fun v i hv hi => by
      unfold bulletproofspp.circuit.message_opening_loop.body
      step*
      refine ⟨l1, i2, rfl, ⟨rs, l1_post, ?_⟩, by scalar_tac⟩
      rw [rs_post]
      simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by scalar_tac : i.val < r.val.length)])
    (fun v i hv hi => by
      unfold bulletproofspp.circuit.message_opening_loop.body
      step*)
    _ 1#usize (by simp) (by simp; omega))
  intro l hl
  have h1 : ((1#usize : Usize).val) = 1 := rfl
  simp only [with_capacity_val, List.map_nil, List.nil_append, h1] at hl
  have hll : l.val.length = r.length - 1 := by
    have := congrArg List.length hl
    simpa using this
  have hl' : l.length = l.val.length := rfl
  simp only [hs.zero_eq, bind_ok]
  step*
  have hr' : 0 < r.val.length := by omega
  obtain ⟨x, xs, hx⟩ : ∃ x xs, r.val = x :: xs := by
    cases h : r.val with
    | nil => simp [h] at hr'
    | cons x xs => exact ⟨x, xs, rfl⟩
  refine ⟨?_, ?_⟩
  · simp only [toO, Bppp.Circuit.message_opening, l2_post, List.map_append, hl, rs1_post, hx,
      List.headD_cons, List.getElem_cons_zero, List.drop_one, List.tail_cons, List.map_cons,
      ScalarModel.φ_z, List.map_nil, Bppp.Opening.mk.injEq, true_and, and_true]
    rw [show r.length - 1 = xs.length by rw [erl, hx]; simp]
    congr 1
    refine List.ext_getElem (by simp) (fun k h1 h2 => ?_)
    have hk : k < xs.length := by simpa using h2
    simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hk]
  · simp only [alloc.vec.Vec.length, l2_post, List.length_append, List.length_singleton]
    omega

lemma cr_getD_bounds (j : ℕ) :
    -1 ≤ Bppp.Circuit.CR_POWERS.getD j 0 ∧ Bppp.Circuit.CR_POWERS.getD j 0 ≤ 7 := by
  rcases j with _ | _ | _ | _ | _ | _ | _ | j <;> simp [Bppp.Circuit.CR_POWERS]

lemma c_terms_eq (beta : F) :
    (List.range' 0 7).map (fun j => (Bppp.Circuit.CR_POWERS.getD j 0,
      (List.replicate 8 (0 : F)).set j beta)) =
    Bppp.Circuit.CR_POWERS.zipIdx.map fun (a, j) =>
      (a, (List.replicate Bppp.H_LEN (0 : F)).set j beta) := by
  simp [Bppp.Circuit.CR_POWERS, List.zipIdx, List.range', Bppp.H_LEN]

lemma c_spec (hs : ScalarModel F φ) (cons : bulletproofspp.constraints.Constraints)
    (hcl : cons.cl_v.length = 8) (beta : S) :
    bulletproofspp.circuit.c cons beta ⦃ r =>
      WF (VecLen 8) r ∧ Half r ∧ Spans (toL (vecψ φ) r) (-1) 8 ∧
        toL (vecψ φ) r = Bppp.Circuit.c (toC φ cons) (φ beta) ⦄ := by
  unfold bulletproofspp.circuit.c bulletproofspp.circuit.c_loop
  simp only [vec_clone_eq hs, bind_ok]
  have h0 : (alloc.vec.Vec.with_capacity (I32 × alloc.vec.Vec S)
    bulletproofspp.crs.H_LEN).val.length = 0 := rfl
  step*
  apply WP.spec_bind (push_loop_off (body := fun x => bulletproofspp.circuit.c_loop.body beta x.1 x.2)
    0 1 7 (fun t : I32 × alloc.vec.Vec S => (t.1.val, vecψ φ t.2))
    (fun j => (Bppp.Circuit.CR_POWERS.getD j 0, (List.replicate 8 (0 : F)).set j (φ beta)))
    (fun v j hv hj => by
      dsimp only
      unfold bulletproofspp.circuit.c_loop.body
      have hl : (Array.to_slice bulletproofspp.circuit.CR_POWERS).len.val = 7 := by
        simp [cr_len]
      simp only [hs.zero_eq, bulletproofspp.crs.H_LEN]
      step*
      all_goals try exact hs.clone _
      refine ⟨terms1, j1, rfl, ⟨(i1, index_mut_back beta), terms1_post, ?_, ?_⟩, j1_post⟩
      · rw [List.getD_eq_getElem _ _ (by simp [Bppp.Circuit.CR_POWERS]; omega), cr_get _ hj,
          i1_post]
      · simp [vecψ, index_mut_back_post, beta_e_j_post, List.map_set])
    (fun v j hv hj => by
      dsimp only
      unfold bulletproofspp.circuit.c_loop.body
      have hl : (Array.to_slice bulletproofspp.circuit.CR_POWERS).len.val = 7 := by
        simp [cr_len]
      step*)
    terms1 0#usize (by simp [alloc.vec.Vec.length, terms1_post]) (by simp))
  intro terms2 ht2
  have h00 : ((0#usize : Usize).val) = 0 := rfl
  simp only [terms1_post, with_capacity_val, List.nil_append, List.map_cons, List.map_nil,
    List.singleton_append, h00, Nat.sub_zero] at ht2
  have hmem : ∀ x ∈ ((0 : ℤ), vecψ φ cons.cl_v) :: (List.range' 0 7).map (fun j =>
      (Bppp.Circuit.CR_POWERS.getD j 0, (List.replicate 8 (0 : F)).set j (φ beta))),
      -1 ≤ x.1 ∧ x.1 ≤ 7 ∧ x.2.length = 8 := by
    intro x hx
    simp only [List.mem_cons, List.mem_map, List.mem_range'] at hx
    rcases hx with rfl | ⟨j, ⟨-, hj⟩, rfl⟩
    · refine ⟨by norm_num, by norm_num, ?_⟩
      simp only [vecψ, List.length_map]
      exact hcl
    · have := cr_getD_bounds j
      exact ⟨this.1, this.2, by simp⟩
  have hne : terms2.val ≠ [] := by
    intro h
    simp [h] at ht2
  have hterms : ∀ t ∈ terms2.val, TermOK (VecLen 8) t := by
    intro t ht
    have hm : (t.1.val, vecψ φ t.2) ∈ terms2.val.map (fun t => (t.1.val, vecψ φ t.2)) :=
      List.mem_map_of_mem ht
    rw [ht2] at hm
    obtain ⟨h1, h2, h3⟩ := hmem _ hm
    refine ⟨?_, by simp only [powBound]; omega, by simp only [powBound]; omega⟩
    simp only [vecψ, List.length_map] at h3
    exact h3
  apply WP.spec_mono (from_terms_spec hs (vec_coeff_model hs 8) terms2 hne hterms)
  rintro r ⟨hwf, hr⟩
  rw [ht2] at hr
  have hsp : Spans (toL (vecψ φ) r) (-1) 8 := by
    rw [hr]
    apply spans_from_terms
    intro x hx
    have := hmem x hx
    omega
  refine ⟨hwf, half_of_spans rfl hsp (by norm_num [powBound]) (by norm_num [powBound]), hsp, ?_⟩
  rw [hr, Bppp.Circuit.c, ← c_terms_eq]
  rfl

/-- `RistrettoScalar::rand` never fails. -/
def RandOK : Prop := ∀ {R : Type} (inst : traits.AllowedRng R) (rng : R), ∃ s rng',
  groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.rand inst rng = ok (s, rng')

/-- Whether `blinding_vector` draws slot `q + 1` for the commitment power `e`. -/
def bvCond (e : ℤ) (q : ℕ) : Prop :=
  e + Bppp.Circuit.CR_POWERS.getD q 0 = -1 ∨ e + Bppp.Circuit.CR_POWERS.getD q 0 + 1 ∈ Bppp.Circuit.CR_POWERS

lemma cr_getD_eq (j : Usize) (hj : j.val < 7) :
    Bppp.Circuit.CR_POWERS.getD j.val 0 =
      (bulletproofspp.circuit.CR_POWERS.val[j.val]'(by rw [cr_len]; exact hj)).val := by
  rw [List.getD_eq_getElem _ _ (by simp [Bppp.Circuit.CR_POWERS]; omega), cr_get _ hj]

lemma is_cr_power_eq (power : I32) :
    bulletproofspp.circuit.is_cr_power power = ok (decide (power.val ∈ Bppp.Circuit.CR_POWERS)) :=
  eq_ok_of_spec (is_cr_power_spec power)

end BpppProofs
