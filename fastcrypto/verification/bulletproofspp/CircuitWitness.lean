-- THIS FILE IS AI-ONLY
import bulletproofspp.Circuit
import bulletproofspp.Spec.ZeroKnowledge

/-!
`Witness::new` computes `Bppp.Circuit.Witness.new`, for some draws of the random number
generator.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar

/-- The model of a generated witness. -/
def toWit (φ : S → F) (w : bulletproofspp.circuit.Witness) : Bppp.Circuit.Witness F :=
  ⟨w.values.val.map φ, w.blindings.val.map φ, w.off_plane.val.map (fun q => (q.1.val.map φ, φ q.2)),
    w.n_l.val.map φ, w.n_o.val.map φ, w.r_o.val.map φ, w.r_l.val.map φ, w.r_r.val.map φ,
    w.n_s.val.map φ, φ w.l_s⟩

lemma extend_u64_spec (v : alloc.vec.Vec U64) (sl : Slice U64)
    (h : v.length + sl.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU64 v sl ⦃ r => r.val = v.val ++ sl.val ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  rw [dif_pos h]
  apply WP.spec_bind (List.clone_spec (fun x _ => rfl))
  rintro l ⟨hl, -⟩
  simp [hl]

lemma to_digits_length (v d : ℕ) : (Bppp.to_digits v d).length = d := by
  simp [Bppp.to_digits]

lemma to_digits_lt (v d x : ℕ) (hx : x ∈ Bppp.to_digits v d) : x < 16 := by
  simp only [Bppp.to_digits, List.mem_map, List.mem_range] at hx
  obtain ⟨t, -, rfl⟩ := hx
  have : (v >>> (Nat.log2 Bppp.BASE * t)) &&& (Bppp.BASE - 1) ≤ Bppp.BASE - 1 := Nat.and_le_right
  simp only [Bppp.BASE] at this ⊢
  omega

lemma multiplicities_length (ds : List ℕ) : (Bppp.multiplicities ds).length = 15 := by
  unfold Bppp.multiplicities
  have key : ∀ (ds : List ℕ) (m : List ℕ),
      (ds.foldl (fun m d => if d > 0 then m.modify (d - 1) (· + 1) else m) m).length =
        m.length := by
    intro ds
    induction ds with
    | nil => intro m; rfl
    | cons d ds ih => intro m; rw [List.foldl_cons, ih]; split <;> simp
  rw [key]
  simp [Bppp.BASE]

lemma digits_loop_spec (params : bulletproofspp.circuit.CircuitParams) (values : Slice U64)
    (digits : alloc.vec.Vec U64) (i : Usize) (hd : params.d.val ≤ 16)
    (hlen : values.length * params.d.val ≤ Usize.max)
    (hdl : digits.val.length = i.val * params.d.val) (hi : i.val ≤ values.length)
    (hdig : digits.val.map (·.val) =
      (values.val.take i.val).flatMap (fun v => Bppp.to_digits v.val params.d.val)) :
    bulletproofspp.circuit.Witness.new_loop0 params values digits i ⦃ r =>
      r.1 = params ∧
      r.2.val.map (·.val) = values.val.flatMap (fun v => Bppp.to_digits v.val params.d.val) ∧
      r.2.val.length = values.length * params.d.val ⦄ := by
  unfold bulletproofspp.circuit.Witness.new_loop0
  have ev : values.len.val = values.val.length := rfl
  have evl : values.length = values.val.length := rfl
  apply loop.spec_decr_nat (fun x => values.length - x.2.val)
    (fun x => x.1.val.length = x.2.val * params.d.val ∧ x.2.val ≤ values.length ∧
      x.1.val.map (·.val) =
        (values.val.take x.2.val).flatMap (fun v => Bppp.to_digits v.val params.d.val))
  · rintro ⟨dg, k⟩ ⟨hl1, hk, hdg⟩
    simp only at hl1 hk hdg
    unfold bulletproofspp.circuit.Witness.new_loop0.body
    by_cases hlt : k.val < values.length
    · have hlt' : k < values.len := by scalar_tac
      simp only [hlt', if_true]
      step*
      apply WP.spec_bind (to_digits_spec _ _ hd)
      intro v hv
      have hvl : v.val.length = params.d.val := by
        have := congrArg List.length hv
        simpa [to_digits_length] using this
      have hmul : (k.val + 1) * params.d.val ≤ values.length * params.d.val :=
        Nat.mul_le_mul_right _ (by omega)
      apply WP.spec_bind (extend_u64_spec dg (alloc.vec.Vec.deref v) (by
        simp only [alloc.vec.Vec.length, Slice.length, deref_val, hl1, hvl]
        rw [Nat.add_mul, one_mul] at hmul
        omega))
      intro dg' hdg'
      step*
      refine ⟨?_, by scalar_tac, ?_, by scalar_tac⟩
      · simp only [hdg', deref_val, List.length_append, hl1, hvl, i3_post]; ring
      · rw [i3_post, hdg', deref_val, List.map_append, hdg,
          List.take_succ_eq_append_getElem (by omega), List.flatMap_append]
        simp [hv, i2_post]
    · have hge : ¬ k < values.len := by scalar_tac
      simp only [hge, if_false, WP.spec_ok]
      have hk' : k.val = values.length := by omega
      refine ⟨by simp, ?_, ?_⟩
      · rw [hdg, hk', evl, List.take_length]
      · rw [hl1, hk']
  · exact ⟨hdl, hi, hdig⟩

section Stream

variable {R : Type} (hr : RandOK) (inst : traits.AllowedRng R)

/-- The draw of `RistrettoScalar::rand` from the state `rng`, and the next state. -/
noncomputable def rnext (rng : R) : S × R :=
  ((hr inst rng).choose, (hr inst rng).choose_spec.choose)

lemma rnext_spec (rng : R) :
    groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.rand inst rng =
      ok (rnext hr inst rng) :=
  (hr inst rng).choose_spec.choose_spec

/-- The state after `k` draws from `rng`. -/
noncomputable def rstate : ℕ → R → R
  | 0, rng => rng
  | k + 1, rng => (rnext hr inst (rstate k rng)).2

/-- Draw `k` (from `0`) from `rng`. -/
noncomputable def rdraw (k : ℕ) (rng : R) : S := (rnext hr inst (rstate hr inst k rng)).1

lemma rstate_add (b a : ℕ) (rng : R) :
    rstate hr inst (b + a) rng = rstate hr inst a (rstate hr inst b rng) := by
  induction a with
  | zero => rfl
  | succ a ih => show (rnext hr inst (rstate hr inst (b + a) rng)).2 = _; rw [ih]; rfl

lemma rdraw_add (b i : ℕ) (rng : R) :
    rdraw hr inst i (rstate hr inst b rng) = rdraw hr inst (b + i) rng := by
  unfold rdraw; rw [rstate_add]

end Stream

instance (e : ℤ) (q : ℕ) : Decidable (bvCond e q) := by unfold bvCond; infer_instance

/-- One iteration of `blinding_vector`'s loop on the draws `g`: the vector so far and the
number of draws so far. -/
def bvStep (e : ℤ) (g : ℕ → F) (acc : List F × ℕ) (p : ℕ) : List F × ℕ :=
  if bvCond e p then (acc.1 ++ [g acc.2], acc.2 + 1) else (acc.1 ++ [0], acc.2)

/-- `blinding_vector` after `k` iterations of its loop, on the draws `g`. -/
def bvA (e : ℤ) (g : ℕ → F) (k : ℕ) : List F × ℕ :=
  (List.range k).foldl (bvStep e g) ([g 0], 1)

lemma bvA_succ (e : ℤ) (g : ℕ → F) (k : ℕ) : bvA e g (k + 1) = bvStep e g (bvA e g k) k := by
  simp [bvA, List.range_succ, List.foldl_append]

lemma bvA_zero (g : ℕ → F) : bvA 0 g 7 = ([g 0, g 1, g 2, g 3, 0, g 4, g 5, 0], 6) := by
  simp [bvA, bvStep, bvCond, Bppp.Circuit.CR_POWERS, List.range_succ]

lemma bvA_one (g : ℕ → F) : bvA 1 g 7 = ([g 0, g 1, g 2, 0, g 3, g 4, 0, 0], 5) := by
  simp [bvA, bvStep, bvCond, Bppp.Circuit.CR_POWERS, List.range_succ]

lemma bvA_two (g : ℕ → F) : bvA 2 g 7 = ([g 0, g 1, 0, g 2, g 3, 0, 0, 0], 4) := by
  simp [bvA, bvStep, bvCond, Bppp.Circuit.CR_POWERS, List.range_succ]

lemma bvx_step (e : ℤ) (G : ℕ → F) {R : Type} (st : ℕ → R) {rA x : List S} {pA p1 : ℕ} {y : S}
    {rngB : R} (hx : x = rA ++ [y]) (hp : p1 = pA + 1) (hl1 : rA.length = pA + 1)
    (hpA : pA < 7) (hA : rA.map φ = (bvA e G pA).1)
    (hy : (bvCond e pA ∧ φ y = G (bvA e G pA).2 ∧ rngB = st ((bvA e G pA).2 + 1)) ∨
      (¬ bvCond e pA ∧ φ y = 0 ∧ rngB = st (bvA e G pA).2)) :
    x.length = p1 + 1 ∧ p1 ≤ 7 ∧ x.map φ = (bvA e G p1).1 ∧ rngB = st (bvA e G p1).2 ∧
      7 - p1 < 7 - pA := by
  subst hx hp
  rw [bvA_succ]
  rcases hy with ⟨hc, hy, hb⟩ | ⟨hc, hy, hb⟩ <;>
    simp only [bvStep, hc, if_true, if_false] <;>
    exact ⟨by simp [hl1], by omega, by simp [hA, hy], hb, by omega⟩

lemma blinding_vector_exact (hs : ScalarModel F φ) (hr : RandOK) {R : Type}
    (inst : traits.AllowedRng R) (e : I32) (he : -8 ≤ e.val ∧ e.val ≤ 8) (rng : R) :
    bulletproofspp.circuit.blinding_vector inst rng e ⦃ res =>
      res.1.val.map φ = (bvA e.val (fun i => φ (rdraw hr inst i rng)) 7).1 ∧
      res.2 = rstate hr inst (bvA e.val (fun i => φ (rdraw hr inst i rng)) 7).2 rng ⦄ := by
  set G : ℕ → F := fun i => φ (rdraw hr inst i rng) with hG
  unfold bulletproofspp.circuit.blinding_vector bulletproofspp.circuit.blinding_vector_loop
  simp only [rnext_spec hr inst, bind_ok]
  have h0 : (alloc.vec.Vec.with_capacity S bulletproofspp.crs.H_LEN).val.length = 0 := rfl
  have hd0 : rdraw hr inst 0 rng = (rnext hr inst rng).1 := rfl
  have hs0 : rstate hr inst 1 rng = (rnext hr inst rng).2 := rfl
  rcases hn : rnext hr inst rng with ⟨d0, s0⟩
  rw [hn] at hd0 hs0
  simp only [Std.uncurry_apply_pair]
  step*
  apply loop.spec_decr_nat (fun x : R × alloc.vec.Vec S × Usize => 7 - x.2.2.val)
    (fun x : R × alloc.vec.Vec S × Usize => x.2.1.val.length = x.2.2.val + 1 ∧ x.2.2.val ≤ 7 ∧
      x.2.1.val.map φ = (bvA e.val G x.2.2.val).1 ∧ x.1 = rstate hr inst (bvA e.val G x.2.2.val).2 rng)
  · rintro ⟨rngA, rA, pA⟩ ⟨hl1, hp1, hA, hst⟩
    simp only at hl1 hp1 hA hst
    subst hst
    unfold bulletproofspp.circuit.blinding_vector_loop.body
    have hdc : rdraw hr inst (bvA e.val G pA.val).2 rng =
        (rnext hr inst (rstate hr inst (bvA e.val G pA.val).2 rng)).1 := rfl
    have hsc : rstate hr inst ((bvA e.val G pA.val).2 + 1) rng =
        (rnext hr inst (rstate hr inst (bvA e.val G pA.val).2 rng)).2 := rfl
    rcases hn : rnext hr inst (rstate hr inst (bvA e.val G pA.val).2 rng) with ⟨d, s'⟩
    rw [hn] at hdc hsc
    simp only [rnext_spec hr inst, hn, hs.zero_eq]
    have hl : (Array.to_slice bulletproofspp.circuit.CR_POWERS).len.val = 7 := by
      simp [cr_len]
    step*
    all_goals try (
      have hp7 : pA.val < 7 := by scalar_tac
      have := cr_getD_bounds pA.val
      rw [cr_getD_eq _ hp7, ← i1_post] at this
      scalar_tac; done)
    · have hp7 : pA.val < 7 := by scalar_tac
      have hi1 : i1.val = Bppp.Circuit.CR_POWERS.getD pA.val 0 := by
        rw [cr_getD_eq _ hp7, i1_post]
      by_cases hm1 : power = (-1)#i32
      · have hcond : bvCond e.val pA.val := by
          left
          have : power.val = -1 := by rw [hm1]; rfl
          rw [← hi1]; omega
        simp only [hm1, if_true]
        step*
        all_goals first
          | exact bvx_step e.val G (fun c => rstate hr inst c rng) (by assumption) (by assumption)
              hl1 hp7 hA (Or.inl ⟨hcond, by simp [G, hdc], hsc.symm⟩)
          | exact (bvx_step e.val G (fun c => rstate hr inst c rng) (by assumption)
              (by assumption) hl1 hp7 hA (Or.inl ⟨hcond, by simp [G, hdc], hsc.symm⟩)).2
      · simp only [hm1, if_false]
        have hpv : power.val ≠ -1 := fun h => hm1 (IScalar.eq_of_val_eq (by rw [h]; rfl))
        step*
        all_goals try (have := cr_getD_bounds pA.val; scalar_tac; done)
        simp only [is_cr_power_eq, bind_ok]
        have hx := ‹(_ : I32).val = power.val + 1›
        split
        · rename_i hin
          have hcond : bvCond e.val pA.val := by
            right
            simp only [decide_eq_true_eq] at hin
            have : e.val + Bppp.Circuit.CR_POWERS.getD pA.val 0 + 1 = (‹I32›).val := by
              rw [← hi1]; scalar_tac
            rw [this]; exact hin
          step*
          all_goals first
            | exact bvx_step e.val G (fun c => rstate hr inst c rng) (by assumption)
                (by assumption) hl1 hp7 hA (Or.inl ⟨hcond, by simp [G, hdc], hsc.symm⟩)
            | exact (bvx_step e.val G (fun c => rstate hr inst c rng) (by assumption)
                (by assumption) hl1 hp7 hA (Or.inl ⟨hcond, by simp [G, hdc], hsc.symm⟩)).2
        · rename_i hin
          have hncond : ¬ bvCond e.val pA.val := by
            simp only [decide_eq_true_eq] at hin
            rintro (h | h)
            · apply hpv; rw [← hi1] at h; scalar_tac
            · apply hin
              have : (‹I32›).val = e.val + Bppp.Circuit.CR_POWERS.getD pA.val 0 + 1 := by
                rw [← hi1]; scalar_tac
              rw [this]; exact h
          step*
          all_goals first
            | exact bvx_step e.val G (fun c => rstate hr inst c rng) (by assumption)
                (by assumption) hl1 hp7 hA (Or.inr ⟨hncond, by simp, rfl⟩)
            | exact (bvx_step e.val G (fun c => rstate hr inst c rng) (by assumption)
                (by assumption) hl1 hp7 hA (Or.inr ⟨hncond, by simp, rfl⟩)).2
  · refine ⟨by simp [*], by simp, by simp [*, bvA, G], by simp [bvA, hs0]⟩


lemma rand_loop_exact (hr : RandOK) {R : Type} (inst : traits.AllowedRng R) (i : Usize)
    (rng : R) :
    bulletproofspp.circuit.Witness.new_loop1 inst i rng (alloc.vec.Vec.with_capacity S i) 0#usize
      ⦃ res => res.2.val.map φ = (List.range i.val).map (fun k => φ (rdraw hr inst k rng)) ∧
        res.1 = rstate hr inst i.val rng ⦄ := by
  unfold bulletproofspp.circuit.Witness.new_loop1
  apply loop.spec_decr_nat (fun x : R × alloc.vec.Vec S × Usize => i.val - x.2.2.val)
    (fun x : R × alloc.vec.Vec S × Usize => x.2.2.val ≤ i.val ∧ x.2.1.val.length = x.2.2.val ∧
      x.2.1.val.map φ = (List.range x.2.2.val).map (fun k => φ (rdraw hr inst k rng)) ∧
      x.1 = rstate hr inst x.2.2.val rng)
  · rintro ⟨rngA, v, k⟩ ⟨hk, hl1, hv, hst⟩
    simp only at hk hl1 hv hst
    subst hst
    unfold bulletproofspp.circuit.Witness.new_loop1.body
    have hdc : rdraw hr inst k.val rng = (rnext hr inst (rstate hr inst k.val rng)).1 := rfl
    have hsc : rstate hr inst (k.val + 1) rng = (rnext hr inst (rstate hr inst k.val rng)).2 := rfl
    rcases hn : rnext hr inst (rstate hr inst k.val rng) with ⟨d, s'⟩
    rw [hn] at hdc hsc
    simp only [rnext_spec hr inst, hn]
    have : v.length = v.val.length := rfl
    step*
    refine ⟨by scalar_tac, by simp [*], ?_, by rw [j1_post, hsc], by scalar_tac⟩
    rw [n_s1_post, j1_post, List.map_append, hv, List.range_succ, List.map_append]
    simp [hdc]
  · exact ⟨by simp, by simp, by simp, rfl⟩

/-- The draws of `Witness::new` from the random number generator in the state `rng`: `r_O`,
`r_L` and `r_R` take draws `0, ..., 14` at the slots `blinding_vector` draws, `n_S` the next
`nm` and `ℓ_S` the last. -/
noncomputable def rngD (φ : S → F) (hr : RandOK) {R : Type} (inst : traits.AllowedRng R) (rng : R)
    (nm : ℕ) : Bppp.Circuit.Randomness F where
  r_o := Bppp.Spec.blindO (fun i : Fin 15 => φ (rdraw hr inst i rng))
  r_l := Bppp.Spec.blindL (fun i : Fin 15 => φ (rdraw hr inst i rng))
  r_r := Bppp.Spec.blindR (fun i : Fin 15 => φ (rdraw hr inst i rng))
  n_s k := if k < nm then φ (rdraw hr inst (6 + 5 + 4 + k) rng) else 0
  l_s := φ (rdraw hr inst (6 + 5 + 4 + nm) rng)

lemma bv_model_O (B : Fin 15 → F) :
    Bppp.Circuit.blinding_vector (Bppp.Spec.blindO B) Bppp.Circuit.C_O_POWER =
      [B 0, B 1, B 2, B 3, 0, B 4, B 5, 0] := by
  simp [Bppp.Circuit.blinding_vector, Bppp.Circuit.CR_POWERS, Bppp.Circuit.C_O_POWER,
    List.zipIdx, Bppp.Spec.blindO]

lemma bv_model_L (B : Fin 15 → F) :
    Bppp.Circuit.blinding_vector (Bppp.Spec.blindL B) Bppp.Circuit.C_L_POWER =
      [B 6, B 7, B 8, 0, B 9, B 10, 0, 0] := by
  simp [Bppp.Circuit.blinding_vector, Bppp.Circuit.CR_POWERS, Bppp.Circuit.C_L_POWER,
    List.zipIdx, Bppp.Spec.blindL]

lemma bv_model_R (B : Fin 15 → F) :
    Bppp.Circuit.blinding_vector (Bppp.Spec.blindR B) Bppp.Circuit.C_R_POWER =
      [B 11, B 12, 0, B 13, B 14, 0, 0, 0] := by
  simp [Bppp.Circuit.blinding_vector, Bppp.Circuit.CR_POWERS, Bppp.Circuit.C_R_POWER,
    List.zipIdx, Bppp.Spec.blindR]

lemma witness_new_spec (hs : ScalarModel F φ) (hr : RandOK) {R : Type}
    (inst : traits.AllowedRng R) (pm : Bppp.CircuitParams)
    (p : bulletproofspp.circuit.CircuitParams) (hp : ParamsOK pm p) (hd : p.d.val ≤ 16)
    (hnd : p.n_d.val ≤ p.nm.val) (rng : R) (values : Slice U64) (blindings : Slice S)
    (hv : values.length = p.m.val) :
    bulletproofspp.circuit.Witness.new inst p rng values blindings ⦃ res =>
        toWit φ res.1 = Bppp.Circuit.Witness.new pm (rngD φ hr inst rng p.nm.val)
          (values.val.map (·.val)) (blindings.val.map φ) ∧
        res.1.off_plane.val = [] ∧ res.1.n_l.length = p.nm.val ∧ res.1.n_o.length = p.nm.val ∧
        res.1.n_s.length = p.nm.val ∧ res.1.r_o.length = 8 ∧ res.1.r_l.length = 8 ∧
        res.1.r_r.length = 8 ∧ res.1.values.length = p.m.val ∧
        res.1.blindings.length = blindings.length ⦄ := by
  obtain ⟨hm, hpd, hpnd, hpnm, hd0, hnde, hnm, hml, hnml⟩ := hp
  unfold bulletproofspp.circuit.Witness.new
  have hlen : values.length * p.d.val ≤ Usize.max := by
    rw [hv, ← hnde]; omega
  apply WP.spec_bind (digits_loop_spec p values (alloc.vec.Vec.new U64) 0#usize hd hlen
    (by simp) (by simp) (by simp))
  rintro ⟨p', digits⟩ ⟨hp', hdig, hdl⟩
  simp only at hp' hdig hdl
  subst p'
  have h0 : (bulletproofspp.circuit.C_O_POWER).val = 0 := by
    unfold bulletproofspp.circuit.C_O_POWER; rfl
  have h1 : (bulletproofspp.circuit.C_L_POWER).val = 1 := by
    unfold bulletproofspp.circuit.C_L_POWER; rfl
  have h2 : (bulletproofspp.circuit.C_R_POWER).val = 2 := by
    unfold bulletproofspp.circuit.C_R_POWER; rfl
  apply WP.spec_bind (blinding_vector_exact (φ := φ) hs hr inst _ (by rw [h0]; norm_num) rng)
  rintro ⟨r_o, rng1⟩ ⟨ho, hs1⟩
  rw [h0, bvA_zero] at ho hs1
  simp only at ho hs1
  subst hs1
  apply WP.spec_bind (blinding_vector_exact (φ := φ) hs hr inst _ (by rw [h1]; norm_num)
    (rstate hr inst 6 rng))
  rintro ⟨r_l, rng2⟩ ⟨hl, hs2⟩
  rw [h1, bvA_one] at hl hs2
  simp only [rdraw_add, ← rstate_add] at hl hs2
  subst hs2
  apply WP.spec_bind (blinding_vector_exact (φ := φ) hs hr inst _ (by rw [h2]; norm_num)
    (rstate hr inst (6 + 5) rng))
  rintro ⟨r_r, rng3⟩ ⟨hrr, hs3⟩
  rw [h2, bvA_two] at hrr hs3
  simp only [rdraw_add, ← rstate_add] at hrr hs3
  subst hs3
  simp only [Std.uncurry_apply_pair]
  apply WP.spec_bind (rand_loop_exact (φ := φ) hr inst p.nm (rstate hr inst (6 + 5 + 4) rng))
  rintro ⟨rng4, n_s⟩ ⟨hns, hs4⟩
  simp only [rdraw_add] at hns hs4
  subst hs4
  have hls : rdraw hr inst (6 + 5 + 4 + p.nm.val) rng =
      (rnext hr inst (rstate hr inst p.nm.val (rstate hr inst (6 + 5 + 4) rng))).1 := by
    rw [← rdraw_add]; rfl
  rcases hn : rnext hr inst (rstate hr inst p.nm.val (rstate hr inst (6 + 5 + 4) rng)) with
    ⟨l_s, rng5⟩
  rw [hn] at hls
  simp only [rnext_spec hr inst, hn, bind_ok, Std.uncurry_apply_pair]
  have hol : r_o.length = 8 := by
    have := congrArg List.length ho; simpa using this
  have hll : r_l.length = 8 := by
    have := congrArg List.length hl; simpa using this
  have hrl : r_r.length = 8 := by
    have := congrArg List.length hrr; simpa using this
  have hnsl : n_s.length = p.nm.val := by
    have := congrArg List.length hns; simpa using this
  apply WP.spec_bind (to_scalars_spec hs values)
  intro v hv'
  have hclone : ∀ x ∈ blindings.val,
      groups.ristretto255.RistrettoScalar.Insts.CoreCloneClone.clone x = ok x :=
    fun x _ => hs.clone x
  step*
  apply WP.spec_bind (to_scalars_spec hs (alloc.vec.Vec.deref digits))
  intro v2 hv2
  have hv2l : v2.val.length = p.n_d.val := by
    have := congrArg List.length hv2
    simp only [List.length_map, Bppp.to_scalars, deref_val] at this
    rw [this, hdl, hv, hnde]
  apply WP.spec_bind (pad_to_spec hs (alloc.vec.Vec.deref v2) p.nm (by
    simp only [Slice.length, deref_val, hv2l]; exact hnd))
  intro v3 hv3
  have hdlt : ∀ x ∈ (alloc.vec.Vec.deref digits).val, x.val < 16 := by
    intro x hx
    rw [deref_val] at hx
    have hm' : x.val ∈ digits.val.map (·.val) := List.mem_map_of_mem hx
    rw [hdig, List.mem_flatMap] at hm'
    obtain ⟨w, -, hw⟩ := hm'
    exact to_digits_lt _ _ _ hw
  apply WP.spec_bind (multiplicities_spec _ hdlt)
  intro v4 hv4
  apply WP.spec_bind (to_scalars_spec hs (alloc.vec.Vec.deref v4))
  intro v5 hv5
  have hv5l : v5.val.length = 15 := by
    have h1' := congrArg List.length hv5
    have h2' := congrArg List.length hv4
    simp only [List.length_map, Bppp.to_scalars, deref_val,
      multiplicities_length] at h1' h2'
    omega
  apply WP.spec_bind (pad_to_spec hs (alloc.vec.Vec.deref v5) p.nm (by
    simp only [Slice.length, deref_val, hv5l]; omega))
  intro v6 hv6
  rw [WP.spec_ok]
  have hpadl : ∀ (l : List F) (n : ℕ), l.length ≤ n → (Bppp.pad_to l n).length = n := by
    intro l n h; simp [Bppp.pad_to]; omega
  have hv3l : v3.val.length = p.nm.val := by
    have := congrArg List.length hv3
    rw [List.length_map, hpadl _ _ (by simp [deref_val, hv2l, hnd])] at this
    exact this
  have hv6l : v6.val.length = p.nm.val := by
    have := congrArg List.length hv6
    rw [List.length_map, hpadl _ _ (by simp [deref_val, hv5l]; omega)] at this
    exact this
  have hvl : v.val.length = p.m.val := by
    have := congrArg List.length hv'
    simp only [List.length_map, Bppp.to_scalars] at this
    rw [this]; exact hv
  refine ⟨?_, rfl, hv3l, hv6l, hnsl, hol, hll, hrl, hvl, ?_⟩
  · have hco : Bppp.Circuit.C_O_POWER = 0 := rfl
    have hcl : Bppp.Circuit.C_L_POWER = 1 := rfl
    have hcr : Bppp.Circuit.C_R_POWER = 2 := rfl
    simp only [toWit, Bppp.Circuit.Witness.new, Bppp.Circuit.Witness.mk.injEq]
    refine ⟨hv', by rw [blindings_post]; rfl, rfl, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · rw [hv3, deref_val, hv2, deref_val, hdig, hpd, hpnm, List.flatMap_map]
    · rw [hv6, deref_val, hv5, deref_val, hv4, deref_val, hdig, hpnm, hpd, List.flatMap_map]
    · rw [ho]; simp only [rngD]; rw [bv_model_O]; simp
    · rw [hl]; simp only [rngD]; rw [bv_model_L]; simp
    · rw [hrr]; simp only [rngD]; rw [bv_model_R]; simp
    · rw [hns, hpnm]; simp only [rngD]
      refine List.map_congr_left (fun k hk => ?_)
      rw [if_pos (List.mem_range.mp hk)]
    · simp only [rngD]; rw [hls]
  · rw [blindings_post]; rfl


end BpppProofs
