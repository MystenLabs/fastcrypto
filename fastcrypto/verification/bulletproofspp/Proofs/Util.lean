-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Scalar
import bulletproofspp.Model.Util

/-!
The generated functions of `util.rs` compute the functions of `Model/Util.lean`, with scalars
mapped to `F` by `φ`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar

@[simp] lemma with_capacity_val {α : Type} (n : Usize) :
    (alloc.vec.Vec.with_capacity α n).val = [] := rfl

@[simp] lemma with_capacity_length {α : Type} (n : Usize) :
    (alloc.vec.Vec.with_capacity α n).length = 0 := rfl

lemma inner_product_loop_spec (hs : ScalarModel F φ) (a b : Slice S) (acc : S) (i : Usize)
    (hab : a.length = b.length) (hi : i.val ≤ a.length) :
    bulletproofspp.util.inner_product_loop a b acc i ⦃ r =>
      φ r = ((List.zip (a.val.drop i.val) (b.val.drop i.val)).map
        (fun p => (φ p.1, φ p.2))).foldl (fun acc (x, y) => acc + x * y) (φ acc) ⦄ := by
  unfold bulletproofspp.util.inner_product_loop
  apply loop.spec_decr_nat (fun p => a.length - p.2.val)
    (fun p => p.2.val ≤ a.length ∧
      ((List.zip (a.val.drop p.2.val) (b.val.drop p.2.val)).map
        (fun p => (φ p.1, φ p.2))).foldl (fun acc (x, y) => acc + x * y) (φ p.1) =
      ((List.zip (a.val.drop i.val) (b.val.drop i.val)).map
        (fun p => (φ p.1, φ p.2))).foldl (fun acc (x, y) => acc + x * y) (φ acc))
  · rintro ⟨acc', i'⟩ ⟨hi', heq⟩
    dsimp only at hi' heq ⊢
    unfold bulletproofspp.util.inner_product_loop.body
    simp only [hs.mul_eq, hs.add_assign_eq]
    step*
    · have h1 : i'.val < a.val.length := by scalar_tac
      have h2 : i'.val < b.val.length := by scalar_tac
      refine ⟨by scalar_tac, ?_, by scalar_tac⟩
      rw [← heq, i3_post, List.drop_eq_getElem_cons h1, List.drop_eq_getElem_cons h2]
      simp only [List.zip_cons_cons, List.map_cons, List.foldl_cons, rs_post, rs1_post,
        hs.φ_addAF, hs.φ_mulF]
    · rw [← heq, List.drop_of_length_le (by scalar_tac), List.drop_of_length_le (by scalar_tac)]
      simp
  · exact ⟨hi, rfl⟩

lemma inner_product_spec (hs : ScalarModel F φ) (a b : Slice S) (hab : a.length = b.length) :
    bulletproofspp.util.inner_product a b ⦃ r =>
      φ r = Bppp.inner_product (a.val.map φ) (b.val.map φ) ⦄ := by
  unfold bulletproofspp.util.inner_product
  simp only [hs.zero_eq]
  step*
  apply WP.spec_mono (inner_product_loop_spec hs a b hs.z 0#usize hab (by simp))
  intro r hr
  simp [hr, Bppp.inner_product, List.zip_map, List.foldl_map]

lemma weighted_inner_product_loop_spec (hs : ScalarModel F φ) (a b : Slice S) (mu w acc : S)
    (i : Usize) (hab : a.length = b.length) (hi : i.val ≤ a.length) :
    bulletproofspp.util.weighted_inner_product_loop a b mu w acc i ⦃ r =>
      φ r = (((List.zip (a.val.drop i.val) (b.val.drop i.val)).map
        (fun p => (φ p.1, φ p.2))).foldl
          (fun (weight, result) (x, y) => (weight * φ mu, result + x * y * weight))
          (φ w, φ acc)).2 ⦄ := by
  unfold bulletproofspp.util.weighted_inner_product_loop
  apply loop.spec_decr_nat (fun p => a.length - p.2.2.val)
    (fun p => p.2.2.val ≤ a.length ∧
      (((List.zip (a.val.drop p.2.2.val) (b.val.drop p.2.2.val)).map
        (fun p => (φ p.1, φ p.2))).foldl
          (fun (weight, result) (x, y) => (weight * φ mu, result + x * y * weight))
          (φ p.1, φ p.2.1)).2 =
      (((List.zip (a.val.drop i.val) (b.val.drop i.val)).map
        (fun p => (φ p.1, φ p.2))).foldl
          (fun (weight, result) (x, y) => (weight * φ mu, result + x * y * weight))
          (φ w, φ acc)).2)
  · rintro ⟨w', acc', i'⟩ ⟨hi', heq⟩
    dsimp only at hi' heq ⊢
    unfold bulletproofspp.util.weighted_inner_product_loop.body
    simp only [hs.mul_eq, hs.add_assign_eq, hs.mul_assign_eq]
    step*
    · have h1 : i'.val < a.val.length := by scalar_tac
      have h2 : i'.val < b.val.length := by scalar_tac
      refine ⟨by scalar_tac, ?_, by scalar_tac⟩
      rw [← heq, i3_post, List.drop_eq_getElem_cons h1, List.drop_eq_getElem_cons h2]
      simp only [List.zip_cons_cons, List.map_cons, List.foldl_cons, rs_post, rs1_post,
        hs.φ_addAF, hs.φ_mulAF, hs.φ_mulF]
    · rw [← heq, List.drop_of_length_le (by scalar_tac), List.drop_of_length_le (by scalar_tac)]
      simp
  · exact ⟨hi, rfl⟩

lemma weighted_inner_product_spec (hs : ScalarModel F φ) (a b : Slice S) (mu : S)
    (hab : a.length = b.length) :
    bulletproofspp.util.weighted_inner_product a b mu ⦃ r =>
      φ r = Bppp.weighted_inner_product (a.val.map φ) (b.val.map φ) (φ mu) ⦄ := by
  unfold bulletproofspp.util.weighted_inner_product
  simp only [hs.zero_eq]
  step*
  apply WP.spec_mono
    (weighted_inner_product_loop_spec hs a b mu mu hs.z 0#usize hab (by simp))
  intro r hr
  simp [hr, Bppp.weighted_inner_product, List.zip_map, List.foldl_map]

lemma weighted_norm_spec (hs : ScalarModel F φ) (n : Slice S) (mu : S) :
    bulletproofspp.util.weighted_norm n mu ⦃ r =>
      φ r = Bppp.weighted_norm (n.val.map φ) (φ mu) ⦄ := by
  unfold bulletproofspp.util.weighted_norm
  exact weighted_inner_product_spec hs n n mu rfl

/-- A loop that pushes `f i` for `i` from `i₀` to `n - 1` onto `v`. -/
lemma push_loop_spec {α : Type} {body : alloc.vec.Vec α × Usize →
      Result (ControlFlow (alloc.vec.Vec α × Usize) (alloc.vec.Vec α))}
    (n : ℕ) (f : ℕ → α)
    (hbody : ∀ v i, v.length = i.val → i.val ≤ n →
      body (v, i) ⦃ r => if i.val < n then ∃ v' i', r = .cont (v', i') ∧
          v'.val = v.val ++ [f i.val] ∧ i'.val = i.val + 1
        else r = .done v ⦄)
    (v : alloc.vec.Vec α) (i : Usize) (hv : v.length = i.val) (hi : i.val ≤ n) :
    loop body (v, i) ⦃ r => r.val = v.val ++ (List.range' i.val (n - i.val)).map f ⦄ := by
  apply loop.spec_decr_nat (fun p => n - p.2.val)
    (fun p => p.1.length = p.2.val ∧ p.2.val ≤ n ∧
      p.1.val ++ (List.range' p.2.val (n - p.2.val)).map f =
        v.val ++ (List.range' i.val (n - i.val)).map f)
  · rintro ⟨v', i'⟩ ⟨hv', hi', heq⟩
    apply WP.spec_mono (hbody v' i' hv' hi')
    intro r hr
    split at hr
    · obtain ⟨v'', i'', rfl, hv'', hi''⟩ := hr
      have hlt : i'.val < n := by assumption
      dsimp only
      refine ⟨⟨by simp [alloc.vec.Vec.length, hv'', hi'']; scalar_tac, by omega, ?_⟩, by omega⟩
      rw [← heq, hv'', hi'', show n - i'.val = (n - (i'.val + 1)) + 1 by omega,
        List.range'_succ]
      simp
    · subst hr
      rw [← heq, show n - i'.val = 0 by omega]
      simp
  · exact ⟨hv, hi, rfl⟩

lemma to_scalars_spec (hs : ScalarModel F φ) (xs : Slice U64) :
    bulletproofspp.util.to_scalars xs ⦃ r =>
      r.val.map φ = Bppp.to_scalars (xs.val.map (·.val)) ⦄ := by
  unfold bulletproofspp.util.to_scalars bulletproofspp.util.to_scalars_loop
  apply WP.spec_mono (push_loop_spec xs.length (fun i => hs.fromF (xs.val.getD i 0#u64))
    (fun v i hv hi => by
      unfold bulletproofspp.util.to_scalars_loop.body
      simp only [hs.from_u64_eq]
      step*
      simp_all; scalar_tac) _ 0#usize (by simp) (by simp))
  intro r hr
  rw [hr]
  simp only [Bppp.to_scalars, List.map_map]
  apply List.ext_getElem (by simp)
  intro k h1 h2
  have hk : k < xs.val.length := by simpa using h2
  simp [List.getElem?_eq_getElem hk]

lemma vec_add_spec (hs : ScalarModel F φ) (a b : Slice S) (hab : a.length = b.length) :
    bulletproofspp.util.vec_add a b ⦃ r =>
      r.val.map φ = Bppp.vec_add (a.val.map φ) (b.val.map φ) ⦄ := by
  unfold bulletproofspp.util.vec_add bulletproofspp.util.vec_add_loop
  step*
  apply WP.spec_mono (push_loop_spec a.length (fun i => hs.addF (a.val.getD i hs.z) (b.val.getD i hs.z))
    (fun v i hv hi => by
      unfold bulletproofspp.util.vec_add_loop.body
      simp only [hs.add_eq]
      step*
      simp_all) _ 0#usize (by simp) (by simp))
  intro r hr
  rw [hr]
  simp only [Slice.length] at hab
  apply List.ext_getElem (by simp [Bppp.vec_add, Slice.length]; omega)
  intro k h1 h2
  have hk : k < a.val.length := by simp [Bppp.vec_add] at h2; exact h2.1
  simp [Bppp.vec_add, List.getElem?_eq_getElem hk, List.getElem?_eq_getElem (hab ▸ hk)]

lemma vec_scalar_mul_spec (hs : ScalarModel F φ) (c : S) (a : Slice S) :
    bulletproofspp.util.vec_scalar_mul c a ⦃ r =>
      r.val.map φ = Bppp.vec_scalar_mul (φ c) (a.val.map φ) ⦄ := by
  unfold bulletproofspp.util.vec_scalar_mul bulletproofspp.util.vec_scalar_mul_loop
  apply WP.spec_mono (push_loop_spec a.length (fun i => hs.mulF c (a.val.getD i hs.z))
    (fun v i hv hi => by
      unfold bulletproofspp.util.vec_scalar_mul_loop.body
      simp only [hs.mul_eq]
      step*
      simp_all; scalar_tac) _ 0#usize (by simp) (by simp))
  intro r hr
  rw [hr]
  apply List.ext_getElem (by simp [Bppp.vec_scalar_mul, Slice.length])
  intro k h1 h2
  have hk : k < a.val.length := by simpa [Bppp.vec_scalar_mul] using h2
  simp [Bppp.vec_scalar_mul, List.getElem?_eq_getElem hk]

lemma hadamard_spec (hs : ScalarModel F φ) (a b : Slice S) (hab : a.length = b.length) :
    bulletproofspp.util.hadamard a b ⦃ r =>
      r.val.map φ = Bppp.hadamard (a.val.map φ) (b.val.map φ) ⦄ := by
  unfold bulletproofspp.util.hadamard bulletproofspp.util.hadamard_loop
  step*
  apply WP.spec_mono (push_loop_spec a.length (fun i => hs.mulF (a.val.getD i hs.z) (b.val.getD i hs.z))
    (fun v i hv hi => by
      unfold bulletproofspp.util.hadamard_loop.body
      simp only [hs.mul_eq]
      step*
      simp_all) _ 0#usize (by simp) (by simp))
  intro r hr
  rw [hr]
  simp only [Slice.length] at hab
  apply List.ext_getElem (by simp [Bppp.hadamard, Slice.length]; omega)
  intro k h1 h2
  have hk : k < a.val.length := by simp [Bppp.hadamard] at h2; exact h2.1
  simp [Bppp.hadamard, List.getElem?_eq_getElem hk, List.getElem?_eq_getElem (hab ▸ hk)]

lemma one_spec (hs : ScalarModel F φ) : bulletproofspp.util.one = ok hs.o := by
  unfold bulletproofspp.util.one; exact hs.one_eq

lemma power_vector_eq (x : F) (n : ℕ) :
    Bppp.power_vector x n = (List.range n).map (x ^ ·) := by
  unfold Bppp.power_vector Bppp.one
  suffices h : ∀ (l : List ℕ) (v : List F) (k : ℕ), l = List.range' k l.length →
      (l.foldl (fun (v, cur) _ => (v ++ [cur], cur * x)) (v, x ^ k)).1 = v ++ l.map (x ^ ·) by
    simpa [List.range_eq_range'] using h (List.range n) [] 0 (by simp [List.range_eq_range'])
  intro l
  induction l with
  | nil => simp
  | cons a l ih =>
    intro v k hl
    simp only [List.length_cons, List.range'_succ, List.cons.injEq] at hl
    obtain ⟨rfl, hl⟩ := hl
    simp only [List.foldl_cons, List.map_cons]
    rw [← pow_succ, ih _ _ hl]
    simp

lemma power_vector_spec (hs : ScalarModel F φ) (x : S) (n : Usize) :
    bulletproofspp.util.power_vector x n ⦃ r =>
      r.val.map φ = Bppp.power_vector (φ x) n.val ⦄ := by
  unfold bulletproofspp.util.power_vector bulletproofspp.util.power_vector_loop
  simp only [one_spec hs, bind_ok]
  rw [power_vector_eq]
  apply loop.spec_decr_nat (fun p => n.val - p.2.2.val)
    (fun p => p.1.length = p.2.2.val ∧ p.2.2.val ≤ n.val ∧ φ p.2.1 = φ x ^ p.2.2.val ∧
      p.1.val.map φ = (List.range p.2.2.val).map (φ x ^ ·))
  rotate_left
  · simp [alloc.vec.Vec.length]
  · rintro ⟨v, cur, i⟩ ⟨hv, hi, hcur, heq⟩
    unfold bulletproofspp.util.power_vector_loop.body
    simp only [hs.mul_assign_eq]
    step*
    dsimp only at hv hi hcur heq
    refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> first
      | scalar_tac
      | (simp [hcur, i1_post, pow_succ]; done)
      | simp [v1_post, heq, i1_post, List.range_succ, hcur]

lemma pad_to_spec (hs : ScalarModel F φ) (v : Slice S) (n : Usize) (hv : v.length ≤ n.val) :
    bulletproofspp.util.pad_to v n ⦃ r =>
      r.val.map φ = Bppp.pad_to (v.val.map φ) n.val ⦄ := by
  unfold bulletproofspp.util.pad_to
  simp only [hs.zero_eq]
  step*
  all_goals try simp [hs.clone]
  have hv' : out.val = v.val := by rw [v_post]; rfl
  simp only [r_post, List.resize, hv', Bppp.pad_to]
  simp only [Slice.length] at hv
  simp [List.take_of_length_le hv]
  omega

/-- The first loop of `batch_invert`: the prefix products. -/
lemma batch_invert_loop0_spec (hs : ScalarModel F φ) (inputs : Slice S)
    (pre : alloc.vec.Vec S) (acc : S) (i : Usize) (hpre : pre.length = i.val)
    (hi : i.val ≤ inputs.length) :
    bulletproofspp.util.batch_invert_loop0 inputs pre acc i ⦃ r =>
      (r.1.val.map φ, φ r.2) = ((inputs.val.map φ).drop i.val).foldl
        (fun (pre, acc) x => (pre ++ [acc], acc * x)) (pre.val.map φ, φ acc) ∧
      r.1.length = inputs.length ⦄ := by
  unfold bulletproofspp.util.batch_invert_loop0
  apply loop.spec_decr_nat (fun p => inputs.length - p.2.2.val)
    (fun p => p.1.length = p.2.2.val ∧ p.2.2.val ≤ inputs.length ∧
      ((inputs.val.map φ).drop p.2.2.val).foldl
        (fun (pre, acc) x => (pre ++ [acc], acc * x)) (p.1.val.map φ, φ p.2.1) =
      ((inputs.val.map φ).drop i.val).foldl
        (fun (pre, acc) x => (pre ++ [acc], acc * x)) (pre.val.map φ, φ acc))
  · rintro ⟨pre', acc', i'⟩ ⟨hpre', hi', heq⟩
    dsimp only at hpre' hi' heq
    unfold bulletproofspp.util.batch_invert_loop0.body
    simp only [hs.mul_assign_eq]
    step*
    · have h1 : i'.val < (inputs.val.map φ).length := by simp; scalar_tac
      refine ⟨?_, ?_, ?_, ?_⟩ <;> try scalar_tac
      rw [← heq, i2_post, List.drop_eq_getElem_cons h1]
      simp only [List.foldl_cons, prefix1_post, rs_post, List.map_append, List.map_cons,
        List.map_nil, List.getElem_map, hs.φ_mulAF]
    · rw [← heq, List.drop_of_length_le (by scalar_tac)]
      simp; scalar_tac
  · exact ⟨hpre, hi, rfl⟩

/-- The step of the second loop of `batch_invert`, and of the `foldr` of `Bppp.batch_invert`. -/
def binvStep : F × F → List F × F → List F × F :=
  fun (x, p) (out, s) => (s * p :: out, s * x)

/-- The second loop of `batch_invert`: the inverses, from the last to the first. -/
lemma batch_invert_loop1_spec (hs : ScalarModel F φ) (inputs : Slice S)
    (pre : alloc.vec.Vec S) (s0 s : S) (out : alloc.vec.Vec S) (i : Usize)
    (hpre : pre.length = inputs.length) (hout : out.length = inputs.length)
    (hi : i.val ≤ inputs.length)
    (hinv : ((out.val.drop i.val).map φ, φ s) =
      ((List.zip (inputs.val.map φ) (pre.val.map φ)).drop i.val).foldr binvStep ([], φ s0)) :
    bulletproofspp.util.batch_invert_loop1 inputs pre s out i ⦃ r =>
      r.val.map φ = ((List.zip (inputs.val.map φ) (pre.val.map φ)).foldr binvStep
        ([], φ s0)).1 ⦄ := by
  unfold bulletproofspp.util.batch_invert_loop1
  apply loop.spec_decr_nat (fun p => p.2.2.val)
    (fun p => p.2.1.length = inputs.length ∧ p.2.2.val ≤ inputs.length ∧
      ((p.2.1.val.drop p.2.2.val).map φ, φ p.1) =
      ((List.zip (inputs.val.map φ) (pre.val.map φ)).drop p.2.2.val).foldr binvStep ([], φ s0))
  · rintro ⟨s', out', i'⟩ ⟨hout', hi', heq⟩
    dsimp only at hout' hi' heq
    unfold bulletproofspp.util.batch_invert_loop1.body
    simp only [hs.mul_eq, hs.mul_assign_eq]
    step*
    · have hz : (List.zip (inputs.val.map φ) (pre.val.map φ)).length = inputs.length := by
        simp [Slice.length] at hpre ⊢; scalar_tac
      have h1 : i1.val < (List.zip (inputs.val.map φ) (pre.val.map φ)).length := by
        rw [hz]; scalar_tac
      refine ⟨?_, ?_, ?_, ?_⟩ <;> try scalar_tac
      have hi1 : i'.val = i1.val + 1 := by scalar_tac
      rw [hi1] at heq
      rw [List.drop_eq_getElem_cons h1, List.foldr_cons, ← heq, index_mut_back_post]
      have h2 : i1.val < (out'.val.set i1.val (hs.mulF s' rs)).length := by
        have e1 : out'.val.length = inputs.val.length := hout'
        have e2 : i'.val ≤ inputs.val.length := hi'
        rw [List.length_set]; omega
      have hset : (out'.set i1 (hs.mulF s' rs)).val = out'.val.set i1.val (hs.mulF s' rs) := by
        simp
      rw [hset, List.drop_eq_getElem_cons h2, List.drop_set_of_lt (by omega)]
      simp [binvStep, rs_post, rs2_post]
    · have : i'.val = 0 := by scalar_tac
      have h := congrArg Prod.fst heq
      simpa [this] using h
  · exact ⟨hout, hi, hinv⟩

lemma batch_invert_spec (hs : ScalarModel F φ) (inputs : Slice S) :
    bulletproofspp.util.batch_invert inputs ⦃ r =>
      match Bppp.batch_invert (inputs.val.map φ) with
      | .ok l => ∃ out, r = .Ok out ∧ out.val.map φ = l
      | .error _ => r = .Err .InvalidInput ⦄ := by
  unfold bulletproofspp.util.batch_invert
  simp only [one_spec hs, bind_ok]
  apply WP.spec_bind (batch_invert_loop0_spec hs inputs _ hs.o 0#usize (by simp) (by simp))
  rintro ⟨pre, acc⟩ ⟨hfold, hlen⟩
  have h00 : ((0#usize : Usize) : ℕ) = 0 := rfl
  simp only [with_capacity_val, List.map_nil, ScalarModel.φ_o, h00, List.drop_zero] at hfold
  have hmir : Bppp.batch_invert (inputs.val.map φ) = (do
      let suffix_inv ← Bppp.inverse (φ acc)
      pure ((List.zip (inputs.val.map φ) (pre.val.map φ)).foldr binvStep ([], suffix_inv)).1) := by
    unfold Bppp.batch_invert
    simp only [Bppp.one, ← hfold]
    rfl
  rw [hmir]
  simp only [Std.uncurry_apply_pair]
  dsimp only at hlen
  by_cases h0 : φ acc = 0
  · rw [hs.inverse_zero acc h0]
    simp [Bppp.inverse, h0, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  · obtain ⟨b, hb, hbv⟩ := hs.inverse acc h0
    rw [hb]
    simp only [Bppp.inverse, h0, ite_false]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hs.zero_eq]
    step*
    all_goals simp [hs.clone]
    have hol : out.length = inputs.length := by
      simp [out_post1, Slice.length]
    have hinit : ((out.val.drop inputs.len.val).map φ, φ b) =
        ((List.zip (inputs.val.map φ) (pre.val.map φ)).drop inputs.len.val).foldr binvStep
          ([], φ b) := by
      have e1 : out.val.length = inputs.val.length := hol
      have e2 : pre.val.length = inputs.val.length := hlen
      rw [List.drop_of_length_le (by simp [e1]), List.drop_of_length_le (by simp [e2])]
      simp
    apply WP.spec_bind (batch_invert_loop1_spec hs inputs pre b b out _ hlen hol
      (by simp [Slice.length]) hinit)
    intro r hr
    simp only [WP.spec_ok]
    refine ⟨r, rfl, ?_⟩
    rw [hr, hbv]

lemma to_digits_loop_spec (value : U64) (bits n : U32) (hb : bits.val = 4) (hn : n.val ≤ 16)
    (out : alloc.vec.Vec U64) (t : U32) (ht : t.val ≤ n.val) (hout : out.length = t.val) :
    bulletproofspp.util.to_digits_loop value bits out n t ⦃ r =>
      r.val.map (·.val) = out.val.map (·.val) ++
        (List.range' t.val (n.val - t.val)).map fun k => (value.val >>> (4 * k)) &&& 15 ⦄ := by
  unfold bulletproofspp.util.to_digits_loop
  apply loop.spec_decr_nat (fun p => n.val - p.2.val)
    (fun p => p.1.length = p.2.val ∧ p.2.val ≤ n.val ∧
      p.1.val.map (·.val) ++
        (List.range' p.2.val (n.val - p.2.val)).map (fun k => (value.val >>> (4 * k)) &&& 15) =
      out.val.map (·.val) ++
        (List.range' t.val (n.val - t.val)).map fun k => (value.val >>> (4 * k)) &&& 15)
  · rintro ⟨o, t'⟩ ⟨ho, ht', heq⟩
    dsimp only at ho ht' heq
    unfold bulletproofspp.util.to_digits_loop.body
    simp only [bulletproofspp.crs.BASE]
    step*
    · have hv : i3.val = value.val >>> (4 * t'.val) &&& 15 := by
        rw [i3_post, UScalar.val_and, i1_post, i_post, hb, i2_post]
      refine ⟨by simp [alloc.vec.Vec.length, out1_post]; scalar_tac, by scalar_tac, ?_,
        by scalar_tac⟩
      rw [← heq, out1_post, t1_post,
        show n.val - t'.val = (n.val - (t'.val + 1)) + 1 by scalar_tac, List.range'_succ]
      simp [hv]
    · rw [← heq, show n.val - t'.val = 0 by scalar_tac]
      simp
  · exact ⟨hout, ht, rfl⟩

lemma to_digits_spec (value : U64) (d : Usize) (hd : d.val ≤ 16) :
    bulletproofspp.util.to_digits value d ⦃ r =>
      r.val.map (·.val) = Bppp.to_digits value.val d.val ⦄ := by
  unfold bulletproofspp.util.to_digits
  have h16 : ((16#u64 : U64).val) = 16 := rfl
  simp only [core.num.U64.ilog2, bulletproofspp.crs.BASE, h16, OfNat.ofNat_ne_zero, ite_false,
    bind_ok]
  step*
  apply WP.spec_mono (to_digits_loop_spec value _ n (by simp; rfl) (by scalar_tac) _ 0#u32
    (by simp) (by simp))
  intro r hr
  rw [hr]
  have hn' : n.val = d.val := by scalar_tac
  simp [Bppp.to_digits, Bppp.BASE, hn', List.range_eq_range']

lemma cast_usize_small (x : U64) (h : x.val < 2 ^ 32) :
    (UScalar.cast .Usize x).val = x.val := by
  simp [UScalar.cast_val_eq]; cases System.Platform.numBits_eq <;> simp [*]; scalar_tac

lemma usize_max_le_u64 : Usize.max ≤ U64.max := by
  cases System.Platform.numBits_eq <;> simp [Usize.max, U64.max, Usize.numBits, U64.numBits, *]

/-- The step of `Bppp.multiplicities`. -/
def multStep (m : List ℕ) (d : ℕ) : List ℕ := if d > 0 then m.modify (d - 1) (· + 1) else m

lemma multStep_length (m : List ℕ) (d : ℕ) : (multStep m d).length = m.length := by
  unfold multStep; split <;> simp

lemma multStep_le (m : List ℕ) (d k : ℕ) (h : ∀ x ∈ m, x ≤ k) : ∀ x ∈ multStep m d, x ≤ k + 1 := by
  unfold multStep
  split
  · intro x hx
    rw [List.mem_iff_getElem] at hx
    obtain ⟨j, hj, rfl⟩ := hx
    rw [List.getElem_modify]
    have := h _ (List.getElem_mem (by simpa using hj))
    split <;> omega
  · intro x hx; have := h x hx; omega

lemma multiplicities_loop_spec (digits : Slice U64) (hd : ∀ x ∈ digits.val, x.val < 16)
    (m : alloc.vec.Vec U64) (i : Usize) (hi : i.val ≤ digits.length) (hm : m.length = 15)
    (hle : ∀ x ∈ m.val, x.val ≤ i.val) :
    bulletproofspp.util.multiplicities_loop digits m i ⦃ r =>
      r.val.map (·.val) = ((digits.val.map (·.val)).drop i.val).foldl multStep
        (m.val.map (·.val)) ⦄ := by
  unfold bulletproofspp.util.multiplicities_loop
  apply loop.spec_decr_nat (fun p => digits.length - p.2.val)
    (fun p => p.2.val ≤ digits.length ∧ p.1.length = 15 ∧ (∀ x ∈ p.1.val, x.val ≤ p.2.val) ∧
      ((digits.val.map (·.val)).drop p.2.val).foldl multStep (p.1.val.map (·.val)) =
      ((digits.val.map (·.val)).drop i.val).foldl multStep (m.val.map (·.val)))
  · rintro ⟨m', i'⟩ ⟨hi', hm', hle', heq⟩
    dsimp only at hi' hm' hle' heq
    unfold bulletproofspp.util.multiplicities_loop.body
    step*
    · have hlt : i'.val < digits.val.length := by scalar_tac
      have hdig : digit.val < 16 := hd _ (by rw [digit_post]; exact List.getElem_mem hlt)
      have hdrop : (digits.val.map (·.val)).drop i'.val =
          digit.val :: (digits.val.map (·.val)).drop (i'.val + 1) := by
        rw [List.drop_eq_getElem_cons (by simpa using hlt)]; simp [digit_post]
      rw [hdrop, List.foldl_cons] at heq
      by_cases hdz : digit > 0#u64
      · simp only [hdz, ite_true]
        step*
        · have : m'.val.length = 15 := hm'
          rw [x_post, cast_usize_small _ (by scalar_tac)]
          scalar_tac
        · rename_i _ u _ hu _ j _ hjc
          obtain ⟨i4, back⟩ := x
          dsimp only at x_post x_post1 ⊢
          have hget := x_post
          have hset := x_post1
          clear x_post x_post1
          have hjv : j.val = digit.val - 1 := by
            rw [hjc, cast_usize_small _ (by rw [hu]; norm_num; omega)]; scalar_tac
          have hjl : j.val < m'.val.length := by
            have : m'.val.length = 15 := hm'; omega
          have hi4 : i4.val ≤ i'.val := by
            rw [hget]; exact hle' _ (List.getElem_mem _)
          step*
          · have : i'.val < digits.val.length := hlt
            have : digits.val.length ≤ Usize.max := digits.property
            have := usize_max_le_u64
            scalar_tac
          refine ⟨by scalar_tac, ?_, ?_, ?_, by scalar_tac⟩
          · rw [hset]; simpa [alloc.vec.Vec.length] using hm'
          · intro y hy
            rw [hset, alloc.vec.Vec.set_val_eq] at hy
            rcases List.mem_or_eq_of_mem_set hy with hy | hy
            · have := hle' y hy; scalar_tac
            · subst hy; scalar_tac
          · rw [← heq, i2_post, hset]
            congr 1
            unfold multStep
            have hpos : digit.val > 0 := by scalar_tac
            simp only [gt_iff_lt, hpos, ite_true, alloc.vec.Vec.set_val_eq, List.map_set]
            rw [List.modify_eq_set]
            have hl : digit.val - 1 < m'.val.length := by omega
            simp [hjv, x_post, hget, List.getElem?_eq_getElem hl]
      · simp only [hdz, ite_false]
        step*
        have hz : digit.val = 0 := by scalar_tac
        refine ⟨by scalar_tac, hm', fun x hx => by have := hle' x hx; scalar_tac, ?_, by scalar_tac⟩
        rw [← heq, i2_post]
        simp [multStep, hz]
    · rw [← heq, List.drop_of_length_le (by simp; scalar_tac)]
      simp
  · exact ⟨hi, hm, hle, rfl⟩

lemma multiplicities_spec (digits : Slice U64) (hd : ∀ x ∈ digits.val, x.val < 16) :
    bulletproofspp.util.multiplicities digits ⦃ r =>
      r.val.map (·.val) = Bppp.multiplicities (digits.val.map (·.val)) ⦄ := by
  unfold bulletproofspp.util.multiplicities
  simp only [bulletproofspp.crs.BASE]
  step*
  have hi1 : i1.val = 15 := by rw [i1_post, cast_usize_small _ (by rw [i_post]; norm_num)]; simp [i_post]
  apply WP.spec_mono (multiplicities_loop_spec digits hd m 0#usize (by simp)
    (by rw [m_post1, hi1]) (by intro x hx; simp [m_post] at hx; simp [hx.2]))
  intro r hr
  rw [hr, m_post, hi1]
  simp only [Bppp.multiplicities, Bppp.BASE]
  simp
  rfl

end BpppProofs
