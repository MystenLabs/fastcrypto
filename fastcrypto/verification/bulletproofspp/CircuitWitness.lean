-- THIS FILE IS AI-ONLY
import bulletproofspp.Circuit

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

lemma rand_loop_spec (hr : RandOK) {R : Type} (inst : traits.AllowedRng R) (i : Usize) (rng : R)
    (n_s : alloc.vec.Vec S) (j : Usize) (hl : n_s.val.length = j.val) (hj : j.val ≤ i.val) :
    bulletproofspp.circuit.Witness.new_loop1 inst i rng n_s j ⦃ r => r.2.val.length = i.val ⦄ := by
  unfold bulletproofspp.circuit.Witness.new_loop1
  apply loop.spec_decr_nat (fun x => i.val - x.2.2.val)
    (fun x => x.2.1.val.length = x.2.2.val ∧ x.2.2.val ≤ i.val)
  · rintro ⟨rngA, v, k⟩ ⟨hl1, hk⟩
    simp only at hl1 hk
    unfold bulletproofspp.circuit.Witness.new_loop1.body
    obtain ⟨d, rng2, hd⟩ := hr inst rngA
    simp only [hd]
    have : v.length = v.val.length := rfl
    step*
    exact ⟨by simp [*], by scalar_tac, by scalar_tac⟩
  · exact ⟨hl, hj⟩

lemma witness_new_spec (hs : ScalarModel F φ) (hr : RandOK) {R : Type}
    (inst : traits.AllowedRng R) (pm : Bppp.CircuitParams)
    (p : bulletproofspp.circuit.CircuitParams) (hp : ParamsOK pm p) (hd : p.d.val ≤ 16)
    (hnd : p.n_d.val ≤ p.nm.val) (rng : R) (values : Slice U64) (blindings : Slice S)
    (hv : values.length = p.m.val) :
    bulletproofspp.circuit.Witness.new inst p rng values blindings ⦃ res =>
      ∃ rnd : Bppp.Circuit.Randomness F,
        toWit φ res.1 = Bppp.Circuit.Witness.new pm rnd (values.val.map (·.val))
          (blindings.val.map φ) ∧
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
  apply WP.spec_bind (blinding_vector_spec hs hr inst rng _ (by rw [h0]; norm_num))
  rintro ⟨r_o, rng1⟩ ⟨hol, ho⟩
  apply WP.spec_bind (blinding_vector_spec hs hr inst rng1 _ (by rw [h1]; norm_num))
  rintro ⟨r_l, rng2⟩ ⟨hll, hl⟩
  apply WP.spec_bind (blinding_vector_spec hs hr inst rng2 _ (by rw [h2]; norm_num))
  rintro ⟨r_r, rng3⟩ ⟨hrl, hrr⟩
  simp only [Std.uncurry_apply_pair]
  apply WP.spec_bind (rand_loop_spec hr inst p.nm rng3 _ 0#usize (by simp) (by simp))
  rintro ⟨rng4, n_s⟩ hns
  obtain ⟨l_s, rng5, hls⟩ := hr inst rng4
  simp only [hls, bind_ok, Std.uncurry_apply_pair]
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
  refine ⟨⟨fun k => (r_o.val.map φ).getD k 0, fun k => (r_l.val.map φ).getD k 0,
    fun k => (r_r.val.map φ).getD k 0, fun k => (n_s.val.map φ).getD k 0, φ l_s⟩,
    ?_, rfl, hv3l, hv6l, hns, hol, hll, hrl, hvl, ?_⟩
  · have hco : Bppp.Circuit.C_O_POWER = 0 := rfl
    have hcl : Bppp.Circuit.C_L_POWER = 1 := rfl
    have hcr : Bppp.Circuit.C_R_POWER = 2 := rfl
    simp only [toWit, Bppp.Circuit.Witness.new, Bppp.Circuit.Witness.mk.injEq]
    rw [h0] at ho; rw [h1] at hl; rw [h2] at hrr
    refine ⟨hv', by rw [blindings_post]; rfl, rfl, ?_, ?_, by rw [hco]; exact ho, by rw [hcl]; exact hl,
      by rw [hcr]; exact hrr, ?_, trivial⟩
    · rw [hv3, deref_val, hv2, deref_val, hdig, hpd, hpnm, List.flatMap_map]
    · rw [hv6, deref_val, hv5, deref_val, hv4, deref_val, hdig, hpnm, hpd, List.flatMap_map]
    · rw [hpnm]
      refine List.ext_getElem (by simp [hns]) (fun k h1 h2 => ?_)
      simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by simpa using h1)]
  · rw [blindings_post]; rfl

end BpppProofs
