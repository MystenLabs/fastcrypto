-- THIS FILE IS AI-ONLY
import bulletproofspp.Points
import bulletproofspp.Constraints
import bulletproofspp.Model.NormLinear
import bulletproofspp.Proofs.Weights

/-!
The generated functions of `norm_linear.rs` compute the functions of `Model/NormLinear.lean`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

lemma odd_only_spec (hs : ScalarModel F φ) (odd : Slice S) (h : 2 * odd.length ≤ Usize.max) :
    bulletproofspp.norm_linear.odd_only odd ⦃ r =>
      r.val.map φ = Bppp.NormLinear.odd_only (F := F) (odd.val.map φ) ⦄ := by
  unfold bulletproofspp.norm_linear.odd_only bulletproofspp.norm_linear.odd_only_loop
  step*
  apply loop.spec_decr_nat (fun q => odd.length - q.2.val)
    (fun q => q.2.val ≤ odd.length ∧ q.1.length = 2 * q.2.val ∧
      q.1.val.map φ = Bppp.NormLinear.odd_only (F := F) ((odd.val.take q.2.val).map φ))
  · rintro ⟨o, j⟩ ⟨hj, hol, heq⟩
    dsimp only at hj hol heq
    unfold bulletproofspp.norm_linear.odd_only_loop.body
    simp only [hs.zero_eq]
    have e : o.length = o.val.length := rfl
    have eo : odd.length = odd.val.length := rfl
    step*
    · simp [out1_post]; scalar_tac
    · refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, out2_post, out1_post]; scalar_tac, ?_,
        by scalar_tac⟩
      have hjl : j.val < odd.val.length := by scalar_tac
      rw [out2_post, out1_post, i2_post, List.take_succ_eq_append_getElem hjl]
      simp [heq, Bppp.NormLinear.odd_only, rs1_post]
      rw [List.take_succ_eq_append_getElem (by simpa using hjl)]
      simp
    · have : j.val = odd.val.length := by scalar_tac
      rw [heq, this, List.take_length]
  · simp [Bppp.NormLinear.odd_only]

lemma interleave_spec (even odd : Slice S)
    (hl : even.length = odd.length) (h : 2 * even.length ≤ Usize.max) :
    bulletproofspp.norm_linear.interleave even odd ⦃ r =>
      r.val.map φ = Bppp.NormLinear.interleave (F := F) (even.val.map φ) (odd.val.map φ) ⦄ := by
  unfold bulletproofspp.norm_linear.interleave bulletproofspp.norm_linear.interleave_loop
  step*
  have ee : even.length = even.val.length := rfl
  have eo : odd.length = odd.val.length := rfl
  apply loop.spec_decr_nat (fun q => even.length - q.2.val)
    (fun q => q.2.val ≤ even.length ∧ q.1.length = 2 * q.2.val ∧
      q.1.val.map φ = Bppp.NormLinear.interleave (F := F) ((even.val.take q.2.val).map φ)
        ((odd.val.take q.2.val).map φ))
  · rintro ⟨o, j⟩ ⟨hj, hol, heq⟩
    dsimp only at hj hol heq
    unfold bulletproofspp.norm_linear.interleave_loop.body
    have e : o.length = o.val.length := rfl
    step*
    · simp [out1_post]; scalar_tac
    · refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, out2_post, out1_post]; scalar_tac, ?_,
        by scalar_tac⟩
      have hjl : j.val < even.val.length := by scalar_tac
      have hjl' : j.val < odd.val.length := by scalar_tac
      rw [out2_post, out1_post, i3_post, List.take_succ_eq_append_getElem hjl,
        List.take_succ_eq_append_getElem hjl']
      simp [heq, Bppp.NormLinear.interleave, rs_post, rs1_post]
      rw [List.take_succ_eq_append_getElem (by simpa using hjl),
        List.take_succ_eq_append_getElem (by simpa using hjl'),
        List.zip_append (by simp; omega)]
      simp
    · have : j.val = even.val.length := by scalar_tac
      rw [heq, this, List.take_length, show even.val.length = odd.val.length from hl,
        List.take_length]
  · simp [Bppp.NormLinear.interleave]

lemma unzip_pairs_drop {α : Type} (l : List α) (i : ℕ) (hi : i + 1 < l.length) :
    Bppp.NormLinear.unzip_pairs (l.drop i) =
      (l[i] :: (Bppp.NormLinear.unzip_pairs (l.drop (i + 2))).1,
        l[i + 1] :: (Bppp.NormLinear.unzip_pairs (l.drop (i + 2))).2) := by
  rw [List.drop_eq_getElem_cons (by omega), List.drop_eq_getElem_cons hi,
    show i + 1 + 1 = i + 2 by omega]
  rfl

lemma usize_max_odd : Usize.max % 2 = 1 := by
  cases System.Platform.numBits_eq <;> simp [Usize.max, Usize.numBits, *]

lemma split_loop_spec (v : alloc.vec.Vec S) (hev : v.val.length % 2 = 0)
    (even odd : alloc.vec.Vec S) (i : Usize) (hi : i.val % 2 = 0) (hi' : i.val ≤ v.length)
    (he : even.length = i.val / 2) (ho : odd.length = i.val / 2) :
    bulletproofspp.norm_linear.split_even_odd_loop v even odd i ⦃ r =>
      r.1.val.map φ =
        even.val.map φ ++ (Bppp.NormLinear.unzip_pairs ((v.val.map φ).drop i.val)).1 ∧
      r.2.val.map φ =
        odd.val.map φ ++ (Bppp.NormLinear.unzip_pairs ((v.val.map φ).drop i.val)).2 ⦄ := by
  unfold bulletproofspp.norm_linear.split_even_odd_loop
  have ev : v.length = v.val.length := rfl
  have hvm : v.val.length ≤ Usize.max := v.property
  have hmo := usize_max_odd
  apply loop.spec_decr_nat (fun q => v.length - q.2.2.val)
    (fun q => q.2.2.val % 2 = 0 ∧ q.2.2.val ≤ v.length ∧ q.1.length = q.2.2.val / 2 ∧
      q.2.1.length = q.2.2.val / 2 ∧
      q.1.val.map φ ++ (Bppp.NormLinear.unzip_pairs ((v.val.map φ).drop q.2.2.val)).1 =
        even.val.map φ ++ (Bppp.NormLinear.unzip_pairs ((v.val.map φ).drop i.val)).1 ∧
      q.2.1.val.map φ ++ (Bppp.NormLinear.unzip_pairs ((v.val.map φ).drop q.2.2.val)).2 =
        odd.val.map φ ++ (Bppp.NormLinear.unzip_pairs ((v.val.map φ).drop i.val)).2)
  · rintro ⟨e, o, j⟩ ⟨hj, hj', hel, hol, heq1, heq2⟩
    dsimp only at hj hj' hel hol heq1 heq2
    unfold bulletproofspp.norm_linear.split_even_odd_loop.body
    have ee : e.length = e.val.length := rfl
    have eo : o.length = o.val.length := rfl
    have hjm : j.val < Usize.max := by omega
    step*
    · have hd := unzip_pairs_drop (v.val.map φ) j.val (by simp; scalar_tac)
      refine ⟨by scalar_tac, by scalar_tac, by simp [alloc.vec.Vec.length, even1_post]; scalar_tac,
        by simp [alloc.vec.Vec.length, odd1_post]; scalar_tac, ?_, ?_, by scalar_tac⟩
      · rw [← heq1, i3_post, hd, even1_post]
        simp [rs_post]
      · rw [← heq2, i3_post, hd, odd1_post]
        simp [rs1_post, i1_post]
    · have hjv : j.val = v.val.length := by scalar_tac
      rw [hjv, List.drop_of_length_le (by simp)] at heq1 heq2
      simp only [Bppp.NormLinear.unzip_pairs, List.append_nil] at heq1 heq2
      exact ⟨heq1, heq2⟩
  · exact ⟨hi, hi', he, ho, rfl, rfl⟩

lemma split_even_odd_spec (hs : ScalarModel F φ) (v : alloc.vec.Vec S)
    (hv : v.val.length < Usize.max) :
    bulletproofspp.norm_linear.split_even_odd v ⦃ r =>
      (r.1.val.map φ, r.2.val.map φ) = Bppp.NormLinear.split_even_odd (v.val.map φ) ⦄ := by
  unfold bulletproofspp.norm_linear.split_even_odd
  simp only [hs.zero_eq]
  step*
  have hlen : v.len.val = v.val.length := rfl
  have fin : ∀ w : alloc.vec.Vec S, w.val.length % 2 = 0 → ∀ a b : Usize,
      bulletproofspp.norm_linear.split_even_odd_loop w (alloc.vec.Vec.with_capacity S a)
        (alloc.vec.Vec.with_capacity S b) 0#usize ⦃ r =>
        (r.1.val.map φ, r.2.val.map φ) = Bppp.NormLinear.unzip_pairs (w.val.map φ) ⦄ := by
    intro w hw a b
    apply WP.spec_mono (split_loop_spec (φ := φ) w hw _ _ 0#usize (by simp) (by simp) (by simp)
      (by simp))
    rintro r ⟨h1, h2⟩
    simp [h1, h2]
  by_cases hb : b = true
  · have h2 : v.val.length % 2 = 0 := by rw [← hlen, ← b_post]; exact hb
    simp only [hb, ite_true, bind_ok]
    step*
    rw [r_post, Bppp.NormLinear.split_even_odd]
    simp [h2]
  · have h2 : v.val.length % 2 ≠ 0 := by
      intro h; apply hb; rw [b_post, hlen]; exact h
    simp only [hb, Bool.false_eq_true, ite_false]
    step*
    have hw : v1.val.length % 2 = 0 := by rw [v1_post]; simp; omega
    step*
    rw [r_post, Bppp.NormLinear.split_even_odd, v1_post]
    simp [h2]

lemma sparse_mul_spec (hs : ScalarModel F φ) (a b : S) :
    bulletproofspp.norm_linear.sparse_mul a b ⦃ r =>
      φ r = Bppp.NormLinear.sparse_mul (φ a) (φ b) ⦄ := by
  unfold bulletproofspp.norm_linear.sparse_mul
  rw [hs.zero_eq, bind_ok, hs.eq, bind_ok, hs.φ_z]
  unfold Bppp.NormLinear.sparse_mul
  by_cases h : φ a = 0
  · simp only [h, decide_true, ite_true, WP.spec_ok]
  · simp only [h, decide_false, Bool.false_eq_true, ite_false, hs.mul_eq, WP.spec_ok, hs.φ_mulF]

/-- The model of `Weights::tensor`, the first `len` entries of `coeffs ⊗ w`. -/
def tensorM (w coeffs : List F) : List F :=
  coeffs.flatMap fun c => w.map fun x => Bppp.NormLinear.sparse_mul c x

lemma tensorM_take_succ (w coeffs : List F) (i : ℕ) (hi : i < coeffs.length) :
    tensorM w (coeffs.take (i + 1)) =
      tensorM w (coeffs.take i) ++ w.map fun x => Bppp.NormLinear.sparse_mul coeffs[i] x := by
  unfold tensorM
  rw [List.take_succ_eq_append_getElem hi, List.flatMap_append]
  simp

lemma tensorM_length (w coeffs : List F) : (tensorM w coeffs).length = coeffs.length * w.length := by
  induction coeffs with
  | nil => simp [tensorM]
  | cons c cs ih =>
    simp only [tensorM, List.flatMap_cons, List.length_append, List.length_map] at ih ⊢
    rw [ih, List.length_cons]; ring

lemma tensorM_take_prefix (w coeffs : List F) (i n : ℕ)
    (hn : n ≤ (tensorM w (coeffs.take i)).length ∨ coeffs.length ≤ i) :
    (tensorM w (coeffs.take i)).take n = (tensorM w coeffs).take n := by
  rcases hn with hn | hn
  · conv_rhs => rw [← List.take_append_drop i coeffs]
    simp only [tensorM, List.flatMap_append] at hn ⊢
    rw [List.take_append_of_le_length hn]
  · rw [List.take_of_length_le hn]

lemma take_append_take {α : Type} (X Y Z : List α) (n : ℕ) (h : n ≤ (X ++ Y).length) :
    ((X ++ Y).take n) = ((X ++ (Y ++ Z)).take n) := by
  rw [← List.append_assoc, List.take_append_of_le_length h]

lemma tensor_inner_spec (hs : ScalarModel F φ) (w : alloc.vec.Vec S) (coeffs : Slice S)
    (len : Usize) (i : Usize) (hi : i.val < coeffs.length) (out : alloc.vec.Vec S) (j : Usize)
    (hj : j.val ≤ w.length)
    (hout : out.val.map φ = (tensorM (w.val.map φ) ((coeffs.val.map φ).take i.val) ++
        ((w.val.map φ).take j.val).map
          (fun x => Bppp.NormLinear.sparse_mul (φ coeffs.val[i.val]) x)).take len.val)
    (hol : out.length = min (i.val * w.length + j.val) len.val) :
    bulletproofspp.norm_linear.Weights.tensor_loop0_loop0 w coeffs len out i j ⦃ r =>
      r.1 = w ∧
      r.2.val.map φ = (tensorM (w.val.map φ) ((coeffs.val.map φ).take (i.val + 1))).take len.val ∧
      r.2.length = min ((i.val + 1) * w.length) len.val ⦄ := by
  unfold bulletproofspp.norm_linear.Weights.tensor_loop0_loop0
  have ew : w.length = w.val.length := rfl
  have ec : coeffs.length = coeffs.val.length := rfl
  have hil : i.val < (coeffs.val.map φ).length := by simpa using hi
  have hrow : tensorM (w.val.map φ) ((coeffs.val.map φ).take (i.val + 1)) =
      tensorM (w.val.map φ) ((coeffs.val.map φ).take i.val) ++
        (w.val.map φ).map (fun x => Bppp.NormLinear.sparse_mul (φ coeffs.val[i.val]) x) := by
    rw [tensorM_take_succ _ _ _ hil]; simp
  have hA : (tensorM (w.val.map φ) ((coeffs.val.map φ).take i.val)).length = i.val * w.length := by
    rw [tensorM_length]; simp; left; omega
  -- `A ++ B m`: the tensor of the rows before `i`, then the first `m` entries of row `i`
  set g := fun x => Bppp.NormLinear.sparse_mul (φ coeffs.val[i.val]) x with hg
  set A := tensorM (w.val.map φ) ((coeffs.val.map φ).take i.val) with hAdef
  have hAk : ∀ m, m ≤ w.val.length →
      (A ++ ((w.val.map φ).take m).map g).length = i.val * w.length + m := by
    intro m hm
    rw [List.length_append, hA, List.length_map, List.length_take, List.length_map]
    omega
  apply loop.spec_decr_nat (fun q => w.length - q.2.2.val)
    (fun q => q.1 = w ∧ q.2.2.val ≤ w.length ∧
      q.2.1.val.map φ = (A ++ ((w.val.map φ).take q.2.2.val).map g).take len.val ∧
      q.2.1.length = min (i.val * w.length + q.2.2.val) len.val)
  · rintro ⟨w', o, k⟩ ⟨hw', hk, heq, hol'⟩
    dsimp only at hw' hk heq hol'
    subst w'
    unfold bulletproofspp.norm_linear.Weights.tensor_loop0_loop0.body
    have eo : o.length = o.val.length := rfl
    step*
    · have hkl : k.val < w.val.length := by scalar_tac
      have hlt : o.val.length < len.val := by scalar_tac
      have hnot : i.val * w.length + k.val < len.val := by omega
      apply WP.spec_bind (sparse_mul_spec hs rs rs1)
      intro x hx
      step*
      have heq' := heq.trans (List.take_of_length_le (by rw [hAk k (by omega)]; omega))
      have hj1 : j1.val = k.val + 1 := j1_post
      refine ⟨by rw [hj1, ew]; omega, ?_, ?_, by rw [hj1]; omega⟩
      · rw [out1_post, j1_post, List.map_append, heq']
        refine Eq.trans ?_ (List.take_of_length_le
          (by rw [hAk (k.val + 1) (by omega)]; omega)).symm
        rw [List.take_succ_eq_append_getElem (by simpa using hkl)]
        simp [hx, rs_post, rs1_post, hg]
      · have : out1.val.length = o.val.length + 1 := by simp [out1_post]
        show out1.val.length = _
        rw [this, j1_post, ← eo, hol']
        omega
    · have hge : len.val ≤ o.val.length := by scalar_tac
      refine ⟨?_, ?_⟩
      · rw [heq, hrow]
        have hsplit : (w.val.map φ).map g =
            ((w.val.map φ).take k.val).map g ++ ((w.val.map φ).drop k.val).map g := by
          rw [← List.map_append, List.take_append_drop]
        rw [hsplit]
        apply take_append_take
        rw [hAk k (by omega)]
        omega
      · have : (i.val + 1) * w.length = i.val * w.length + w.length := by ring
        rw [eo, this]; omega
    · have hk' : k.val = w.val.length := by scalar_tac
      have htk : (w.val.map φ).take k.val = w.val.map φ := List.take_of_length_le (by simp [hk'])
      rw [htk] at heq
      have : (i.val + 1) * w.length = i.val * w.length + w.length := by ring
      refine ⟨by rw [heq, hrow], by rw [hol', this, hk']⟩
  · exact ⟨rfl, hj, hout, hol⟩

lemma tensor_spec (hs : ScalarModel F φ) (w : alloc.vec.Vec S) (coeffs : Slice S) (len : Usize) :
    bulletproofspp.norm_linear.Weights.tensor w coeffs len ⦃ r =>
      r.val.map φ = (tensorM (w.val.map φ) (coeffs.val.map φ)).take len.val ∧
      r.length = min (coeffs.length * w.length) len.val ⦄ := by
  unfold bulletproofspp.norm_linear.Weights.tensor bulletproofspp.norm_linear.Weights.tensor_loop0
  have ew : w.length = w.val.length := rfl
  have ec : coeffs.length = coeffs.val.length := rfl
  apply loop.spec_decr_nat (fun q => coeffs.length - q.2.2.val)
    (fun q => q.1 = w ∧ q.2.2.val ≤ coeffs.length ∧
      q.2.1.val.map φ = (tensorM (w.val.map φ) ((coeffs.val.map φ).take q.2.2.val)).take len.val ∧
      q.2.1.length = min (q.2.2.val * w.length) len.val)
  · rintro ⟨w', o, i⟩ ⟨hw', hi, heq, hol⟩
    dsimp only at hw' hi heq hol
    subst w'
    unfold bulletproofspp.norm_linear.Weights.tensor_loop0.body
    have eo : o.length = o.val.length := rfl
    step*
    · have hil : i.val < coeffs.length := by scalar_tac
      apply WP.spec_bind (tensor_inner_spec hs w coeffs len i hil o 0#usize (by simp)
        (by simpa using heq) (by simpa using hol))
      rintro ⟨v, o1⟩ ⟨hv, ho1, hol1⟩
      dsimp only at hv ho1 hol1
      subst hv
      step*
    · have hge : len.val ≤ o.val.length := by scalar_tac
      refine ⟨?_, ?_⟩
      · rw [heq]; apply tensorM_take_prefix; left
        rw [tensorM_length]; simp
        have hm : min i.val coeffs.val.length = i.val := Nat.min_eq_left (by rw [← ec]; exact hi)
        rw [hm]
        rw [← eo, hol] at hge
        have := Nat.min_le_left (i.val * w.length) len.val
        rw [ew] at hge this; omega
      · rw [hol]
        have : i.val * w.length ≤ coeffs.length * w.length := Nat.mul_le_mul_right _ hi
        omega
    · have hic : i.val = coeffs.length := by scalar_tac
      refine ⟨?_, by rw [hol, hic]⟩
      rw [heq, hic, ec, ← List.length_map (f := φ), List.take_length]
  · exact ⟨rfl, by simp, by simp [tensorM], by simp⟩

/-- The model of generated fold weights. -/
def toW (φ : S → F) (w : bulletproofspp.norm_linear.Weights) : Bppp.NormLinear.Weights F :=
  ⟨w.val.map φ⟩

lemma weights_new_spec (hs : ScalarModel F φ) :
    bulletproofspp.norm_linear.Weights.new ⦃ r =>
      toW φ r = Bppp.NormLinear.Weights.new ∧ r.length = 1 ⦄ := by
  unfold bulletproofspp.norm_linear.Weights.new
  simp only [one_spec hs, bind_ok]
  step*
  simp [toW, y_post, Bppp.NormLinear.Weights.new, Bppp.one, alloc.vec.Vec.length]

lemma tensor_pair_spec (hs : ScalarModel F φ) (w : bulletproofspp.norm_linear.Weights) (f0 f1 : S)
    (hw : 2 * w.length ≤ Usize.max) :
    bulletproofspp.norm_linear.Weights.tensor_pair w f0 f1 ⦃ r =>
      toW φ r = (toW φ w).tensor_pair (φ f0) (φ f1) ∧ r.length = 2 * w.length ⦄ := by
  unfold bulletproofspp.norm_linear.Weights.tensor_pair bulletproofspp.norm_linear.Weights.len
  step*
  apply WP.spec_bind (tensor_spec hs w s i1)
  rintro r ⟨hr, hrl⟩
  simp only [WP.spec_ok]
  have hs2 : s.val = [f0, f1] := by simp [s_post]
  have hsl : s.length = 2 := by simp [Slice.length, hs2]
  refine ⟨?_, ?_⟩
  · simp only [toW, Bppp.NormLinear.Weights.tensor_pair, Bppp.NormLinear.Weights.tensor, hr, hs2]
    congr 1
    apply List.take_of_length_le
    rw [tensorM_length, i1_post]
    have : (alloc.vec.Vec.len w).val = w.val.length := rfl
    simp [this]
  · rw [hrl, hsl, i1_post]; simp

lemma scale_spec' (hs : ScalarModel F φ) (w : bulletproofspp.norm_linear.Weights) (c : S)
    (len : Usize) :
    bulletproofspp.norm_linear.Weights.scale w c len ⦃ r =>
      r.val.map φ = ((toW φ w).scale (φ c)).take len.val ∧ r.length = min w.length len.val ⦄ := by
  unfold bulletproofspp.norm_linear.Weights.scale bulletproofspp.norm_linear.Weights.scale_loop
  have ew : w.length = w.val.length := rfl
  set g := fun x => Bppp.NormLinear.sparse_mul (φ c) x with hg
  have hmod : (toW φ w).scale (φ c) = (w.val.map φ).map g := by
    simp [toW, Bppp.NormLinear.Weights.scale, hg]
  rw [hmod]
  apply loop.spec_decr_nat (fun q => w.length - q.2.2.val)
    (fun q => q.1 = w ∧ q.2.2.val ≤ w.length ∧
      q.2.1.val.map φ = (((w.val.map φ).take q.2.2.val).map g).take len.val ∧
      q.2.1.length = min q.2.2.val len.val)
  · rintro ⟨w', o, k⟩ ⟨hw', hk, heq, hol'⟩
    dsimp only at hw' hk heq hol'
    subst w'
    unfold bulletproofspp.norm_linear.Weights.scale_loop.body
    have eo : o.length = o.val.length := rfl
    step*
    · have hkl : k.val < w.val.length := by scalar_tac
      have hlt : o.val.length < len.val := by scalar_tac
      have hnot : k.val < len.val := by omega
      apply WP.spec_bind (sparse_mul_spec hs c rs)
      intro x hx
      step*
      have hlk : (((w.val.map φ).take k.val).map g).length = k.val := by simp; omega
      have heq' := heq.trans (List.take_of_length_le (by rw [hlk]; omega))
      have hj1 : j1.val = k.val + 1 := j1_post
      refine ⟨by rw [hj1, ew]; omega, ?_, ?_, by rw [hj1]; omega⟩
      · rw [out1_post, hj1, List.map_append, heq']
        refine Eq.trans ?_ (List.take_of_length_le (by simp; omega)).symm
        rw [List.take_succ_eq_append_getElem (by simpa using hkl)]
        simp [hx, rs_post, hg]
      · have : out1.val.length = o.val.length + 1 := by simp [out1_post]
        show out1.val.length = _
        rw [this, hj1, ← eo, hol']
        omega
    · have hge : len.val ≤ o.val.length := by scalar_tac
      refine ⟨?_, ?_⟩
      · rw [heq]
        conv_rhs => rw [← List.take_append_drop k.val (w.val.map φ), List.map_append]
        rw [List.take_append_of_le_length (by simp; omega)]
      · rw [hol']; omega
    · have hk' : k.val = w.val.length := by scalar_tac
      have htk : (w.val.map φ).take k.val = w.val.map φ := List.take_of_length_le (by simp [hk'])
      rw [htk] at heq
      exact ⟨heq, by rw [hol', hk', ew]⟩
  · exact ⟨rfl, by simp, by simp, by simp⟩

/-- The pairs of `scalars` and `points` whose scalar is not zero, unzipped. -/
def nonzero (sc : List F) (pts : List E) : List F × List E :=
  (((List.zip sc pts).filter fun (s, _) => s ≠ 0).map Prod.fst,
    ((List.zip sc pts).filter fun (s, _) => s ≠ 0).map Prod.snd)

lemma nonzero_take_succ (sc : List F) (pts : List E) (k : ℕ) (hk1 : k < sc.length)
    (hk2 : k < pts.length) :
    nonzero (sc.take (k + 1)) (pts.take (k + 1)) =
      if sc[k] ≠ 0 then ((nonzero (sc.take k) (pts.take k)).1 ++ [sc[k]],
        (nonzero (sc.take k) (pts.take k)).2 ++ [pts[k]])
      else nonzero (sc.take k) (pts.take k) := by
  unfold nonzero
  rw [List.take_succ_eq_append_getElem hk1, List.take_succ_eq_append_getElem hk2,
    List.zip_append (by simp; omega), List.filter_append]
  by_cases h : sc[k] = 0 <;> simp [h]

lemma push_nonzero_spec (hs : ScalarModel F φ) (sc : alloc.vec.Vec S) (pts : alloc.vec.Vec P)
    (scalars : Slice S) (points : Slice P)
    (hsc : sc.length + scalars.length ≤ Usize.max) (hpts : pts.length + scalars.length ≤ Usize.max) :
    bulletproofspp.norm_linear.push_nonzero sc pts scalars points ⦃ r =>
      r.1.val.map φ = sc.val.map φ ++ (nonzero (scalars.val.map φ) (points.val.map ψ)).1 ∧
      r.2.val.map ψ = pts.val.map ψ ++ (nonzero (scalars.val.map φ) (points.val.map ψ)).2 ∧
      r.1.length ≤ sc.length + scalars.length ∧ r.2.length ≤ pts.length + scalars.length ⦄ := by
  unfold bulletproofspp.norm_linear.push_nonzero bulletproofspp.norm_linear.push_nonzero_loop
  have es : scalars.length = scalars.val.length := rfl
  have ep : points.length = points.val.length := rfl
  set n := min scalars.val.length points.val.length with hn
  apply loop.spec_decr_nat (fun q => scalars.length - q.2.2.val)
    (fun q => q.2.2.val ≤ n ∧
      q.1.val.map φ = sc.val.map φ ++ (nonzero ((scalars.val.map φ).take q.2.2.val) ((points.val.map ψ).take q.2.2.val)).1 ∧
      q.2.1.val.map ψ = pts.val.map ψ ++ (nonzero ((scalars.val.map φ).take q.2.2.val) ((points.val.map ψ).take q.2.2.val)).2 ∧
      q.1.length ≤ sc.length + q.2.2.val ∧ q.2.1.length ≤ pts.length + q.2.2.val)
  · rintro ⟨a, b, k⟩ ⟨hk, ha, hb, hal, hbl⟩
    dsimp only at hk ha hb hal hbl
    unfold bulletproofspp.norm_linear.push_nonzero_loop.body
    simp only [hs.zero_eq, core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
      hs.eq, bind_ok, hs.φ_z]
    have ea : a.length = a.val.length := rfl
    have eb : b.length = b.val.length := rfl
    have esc : sc.length = sc.val.length := rfl
    have ept : pts.length = pts.val.length := rfl
    step*
    · have hk1 : k.val < scalars.val.length := by scalar_tac
      have hk2 : k.val < points.val.length := by scalar_tac
      have hZ := nonzero_take_succ ((scalars.val.map φ)) ((points.val.map ψ)) k.val
        (by simpa using hk1) (by simpa using hk2)
      by_cases h0 : φ rs = 0
      · have : ¬ (φ (scalars.val[k.val]) ≠ 0) := by rw [← rs_post]; simpa using h0
        simp only [h0, decide_true]
        rw [if_neg (by decide)]
        step*
        refine ⟨by scalar_tac, ?_, ?_, by scalar_tac, by scalar_tac, by scalar_tac⟩
        · rw [ha, i3_post, hZ]; simp [this]
        · rw [hb, i3_post, hZ]; simp [this]
      · have : φ (scalars.val[k.val]) ≠ 0 := by rw [← rs_post]; exact h0
        simp only [h0, decide_false]
        rw [if_pos (by decide)]
        step*
        rename_i sc2 _ hsc2 rp _ hrp _
        refine ⟨by scalar_tac, ?_, ?_, ?_, ?_, by scalar_tac⟩
        · rw [hsc2, i3_post, hZ]; simp [this, ha, rs_post]
        · rw [x_post, i3_post, hZ]; simp [this, hb, hrp]
        · simp [alloc.vec.Vec.length, hsc2]; scalar_tac
        · simp [alloc.vec.Vec.length, x_post]; scalar_tac
    all_goals
      have hkn : k.val = n := by scalar_tac
      have hZn : nonzero ((scalars.val.map φ).take k.val) ((points.val.map ψ).take k.val) =
          nonzero (scalars.val.map φ) (points.val.map ψ) := by
        simp only [nonzero, hkn, hn]
        rw [@List.zip_eq_zip_take_min _ _ (scalars.val.map φ) (points.val.map ψ)]
        simp
      exact ⟨by rw [ha, hZn], by rw [hb, hZn], by scalar_tac, by scalar_tac⟩
  · refine ⟨by simp, by simp [nonzero], by simp [nonzero], by simp, by simp⟩

lemma extend_spec (hs : ScalarModel F φ) (v : alloc.vec.Vec S) (sl : Slice S)
    (h : v.length + sl.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice groups.ristretto255.RistrettoScalar.Insts.CoreCloneClone v sl
      ⦃ r => r.val = v.val ++ sl.val ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  rw [dif_pos h]
  apply WP.spec_bind (List.clone_spec (fun x _ => hs.clone x))
  rintro l ⟨hl, -⟩
  simp [hl]

lemma gens_msm_spec (hs : ScalarModel F φ) (gens : bulletproofspp.crs.Generators)
    (hg : GensOK φ ψ gens) (sigma : S) (l n ds : Slice S) (dp : Slice P)
    (hlen : 1 + gens.h_vec.length + gens.g_vec.length ≤ Usize.max)
    (hln : 1 + l.length + n.length ≤ Usize.max) :
    bulletproofspp.crs.Generators.msm gens sigma l n ds dp ⦃ r =>
      MsmMatches ψ r ((toGens ψ gens).msm (φ sigma) (l.val.map φ) (n.val.map φ) (ds.val.map φ)
        (dp.val.map ψ)) ⦄ := by
  unfold bulletproofspp.crs.Generators.msm
  step*
  all_goals try (simp; scalar_tac; done)
  apply WP.spec_bind (extend_spec hs scalars1 l (by simp [alloc.vec.Vec.length, scalars1_post]; scalar_tac))
  intro s2 hs2
  apply WP.spec_bind (extend_spec hs s2 n (by simp [alloc.vec.Vec.length, hs2, scalars1_post]; scalar_tac))
  intro s3 hs3
  obtain ⟨r, hr, hm⟩ := hg (alloc.vec.Vec.deref s3) ds dp
  rw [hr, WP.spec_ok]
  convert hm using 2
  simp [Bppp.Generators.msm, toGens, alloc.vec.Vec.deref, hs3, hs2, scalars1_post]

/-- The model of a generated opening. -/
def toO (φ : S → F) (o : bulletproofspp.norm_linear.Opening) : Bppp.Opening F :=
  ⟨φ o.sigma, o.l.val.map φ, o.n.val.map φ⟩

lemma commit_spec (hs : ScalarModel F φ) (gens : bulletproofspp.crs.Generators)
    (hg : GensOK φ ψ gens) (o : bulletproofspp.norm_linear.Opening)
    (hl : o.l.length = gens.h_vec.length) (hn : o.n.length = gens.g_vec.length)
    (hlen : 1 + gens.h_vec.length + gens.g_vec.length ≤ Usize.max) :
    bulletproofspp.norm_linear.Generators.commit gens o ⦃ r =>
      MsmMatches ψ r ((toGens ψ gens).commit (toO φ o)) ⦄ := by
  unfold bulletproofspp.norm_linear.Generators.commit
  step*
  apply WP.spec_mono (gens_msm_spec hs gens hg o.sigma _ _ s2 s3 hlen
    (by
      have e1 : gens.h_vec.length = gens.h_vec.val.length := rfl
      have e2 : gens.g_vec.length = gens.g_vec.val.length := rfl
      have e3 : o.l.length = o.l.val.length := rfl
      have e4 : o.n.length = o.n.val.length := rfl
      simp [alloc.vec.Vec.deref, Slice.length]; omega))
  intro r hr
  convert hr using 2
  simp [Bppp.Generators.commit, toO, alloc.vec.Vec.deref, s2_post, s3_post]
  rfl

/-- The values of the model's `Weights::contract`, which never fails. -/
def contractM (w : List F) (pts : List E) : List E :=
  (Bppp.NormLinear.chunks w.length pts).map fun ch =>
    (List.zipWith (· • ·) (w.take ch.length) ch).sum

lemma chunks_length_le {α : Type} (n : ℕ) (l : List α) : ∀ ch ∈ Bppp.NormLinear.chunks n l,
    ch.length ≤ n := by
  induction l using Bppp.NormLinear.chunks.induct n with
  | case1 l h =>
    intro ch hch; rw [Bppp.NormLinear.chunks, dif_pos h] at hch; simp at hch
  | case2 l h ih =>
    intro ch hch
    rw [Bppp.NormLinear.chunks, dif_neg h] at hch
    rcases List.mem_cons.1 hch with rfl | hch
    · simp
    · exact ih ch hch

lemma mapM_ok {α β ε : Type} (f : α → Except ε β) (g : α → β) (l : List α)
    (h : ∀ x ∈ l, f x = .ok (g x)) : l.mapM f = .ok (l.map g) := by
  induction l with
  | nil => rfl
  | cons x l ih =>
    rw [List.mapM_cons, h x (by simp), ih (fun y hy => h y (by simp [hy]))]
    rfl

lemma contract_model (w : List F) (pts : List E) :
    (Bppp.NormLinear.Weights.contract ⟨w⟩ pts : Bppp.Result (List E)) = .ok (contractM w pts) := by
  unfold Bppp.NormLinear.Weights.contract contractM Bppp.NormLinear.Weights.len
  apply mapM_ok
  intro ch hch
  have hle : ch.length ≤ w.length := chunks_length_le _ _ ch hch
  have hm : min w.length ch.length = ch.length := Nat.min_eq_right hle
  simp [Bppp.multi_scalar_mul, hm]
  exact hle

lemma take_min_length {α : Type} (l : List α) (n : ℕ) : l.take (min n l.length) = l.take n := by
  rcases Nat.le_total n l.length with h | h
  · rw [Nat.min_eq_left h]
  · rw [Nat.min_eq_right h, List.take_length, List.take_of_length_le h]

lemma drop_min_length {α : Type} (l : List α) (n : ℕ) : l.drop (min n l.length) = l.drop n := by
  rcases Nat.le_total n l.length with h | h
  · rw [Nat.min_eq_left h]
  · rw [Nat.min_eq_right h, List.drop_length, List.drop_of_length_le h]

lemma contractM_drop (w : List F) (pts : List E) (k : ℕ) (hw : 0 < w.length) (hk : k < pts.length) :
    contractM w (pts.drop k) =
      (List.zipWith (· • ·) (w.take (min w.length (pts.length - k))) ((pts.drop k).take w.length)).sum ::
        contractM w (pts.drop (k + w.length)) := by
  unfold contractM
  rw [Bppp.NormLinear.chunks_cons hw (by simp; omega)]
  simp [List.drop_drop, Nat.add_comm]

lemma contract_spec (hp : PointModel φ ψ)
    (w : bulletproofspp.norm_linear.Weights) (hw : 0 < w.length) (points : Slice P)
    (hpw : points.length + w.length ≤ Usize.max) :
    bulletproofspp.norm_linear.Weights.contract w points ⦃ r =>
      ∃ out, r = .Ok out ∧ out.val.map ψ = contractM (w.val.map φ) (points.val.map ψ) ⦄ := by
  unfold bulletproofspp.norm_linear.Weights.contract bulletproofspp.norm_linear.Weights.contract_loop
    bulletproofspp.norm_linear.Weights.len
  have ew : w.length = w.val.length := rfl
  have ep : points.length = points.val.length := rfl
  have hpm : points.val.length ≤ Usize.max := points.property
  step*
  apply loop.spec_decr_nat (fun q => points.length - q.2.2.val)
    (fun q => q.1 = w ∧ q.2.2.val ≤ points.length ∧ q.2.1.length ≤ q.2.2.val ∧
      q.2.1.val.map ψ ++ contractM (w.val.map φ) ((points.val.map ψ).drop q.2.2.val) =
        contractM (w.val.map φ) (points.val.map ψ))
  · rintro ⟨w', o, st⟩ ⟨hw', hst, hol, heq⟩
    dsimp only at hw' hst hol heq
    subst w'
    unfold bulletproofspp.norm_linear.Weights.contract_loop.body bulletproofspp.norm_linear.Weights.len
    have eo : o.length = o.val.length := rfl
    have hwl : (alloc.vec.Vec.len w).val = w.val.length := rfl
    step*
    · have hstl : st.val < points.val.length := by scalar_tac
      have hend : «end».val = min (st.val + w.val.length) points.val.length := by
        rw [end_post]; simp [i2_post, hwl]
      obtain ⟨r, hr, hm⟩ := hp.msm s s1
      have hsl : (s.val.map φ).length = (s1.val.map ψ).length := by
        simp only [List.length_map]
        have h1 : s.val.length = s.length := rfl
        have h2 : s1.val.length = s1.length := rfl
        rw [h1, h2, s_post1, s1_post1, i4_post]
      unfold MsmMatches at hm
      rw [Bppp.multi_scalar_mul, if_neg (by omega)] at hm
      obtain ⟨p, rfl, hpv⟩ := hm
      rw [hr]
      simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
      step*
      refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, out1_post]; scalar_tac, ?_, by scalar_tac⟩
      rw [← heq, out1_post, contractM_drop _ _ st.val (by simpa using hw) (by simpa using hstl)]
      simp only [List.map_append, List.map_cons, List.map_nil, List.append_assoc,
        List.singleton_append]
      have hw' : (w.val.map φ).length = w.val.length := by simp
      congr 2
      · rw [hpv, s_post, s1_post]
        simp only [List.slice, List.drop_zero, Nat.sub_zero, List.map_take, List.map_drop,
          List.length_map]
        have he1 : i4.val = min w.val.length (points.val.length - st.val) := by
          rw [i4_post, hend]; omega
        have he2 : «end».val - st.val = min w.val.length (points.val.length - st.val) := by
          rw [hend]; omega
        rw [he1, he2]
        congr 1
        have hD : ((points.val.map ψ).drop st.val).length = points.val.length - st.val := by simp
        rw [← hD, take_min_length]
      · rw [hend]
        have := drop_min_length (points.val.map ψ) (st.val + w.val.length)
        simp only [List.length_map] at this ⊢
        rw [this]
    · refine ⟨o, rfl, ?_⟩
      rw [← heq, List.drop_of_length_le (by simp; scalar_tac)]
      simp [contractM, Bppp.NormLinear.chunks_nil]
  · exact ⟨rfl, by simp, by simp, by simp⟩

/-- The model of the MSM over folded bases in `LazyBases::msm`. -/
def foldedM (sigma : F) (g : E) (h_vec g_vec : List E) (h_scalars g_scalars : List F) :
    Bppp.Result E :=
  let (sc, pts) := (((sigma, g) :: List.zip h_scalars h_vec ++ List.zip g_scalars g_vec).filter
    fun (s, _) => s ≠ 0).unzip
  Bppp.multi_scalar_mul sc pts

lemma foldedM_eq (sigma : F) (g : E) (h_vec g_vec : List E) (h_scalars g_scalars : List F) :
    foldedM sigma g h_vec g_vec h_scalars g_scalars = Bppp.multi_scalar_mul
      ((if sigma ≠ 0 then [sigma] else []) ++ (nonzero h_scalars h_vec).1 ++
        (nonzero g_scalars g_vec).1)
      ((if sigma ≠ 0 then [g] else []) ++ (nonzero h_scalars h_vec).2 ++
        (nonzero g_scalars g_vec).2) := by
  unfold foldedM nonzero
  by_cases h : sigma = 0 <;> simp [h, List.filter_append]

lemma folded_msm_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ) (sigma : S) (g : P)
    (h_vec g_vec : Slice P) (h_scalars g_scalars : Slice S)
    (hlen : 1 + h_vec.length + g_vec.length ≤ Usize.max)
    (hh : h_scalars.length ≤ h_vec.length) (hg : g_scalars.length ≤ g_vec.length) :
    bulletproofspp.norm_linear.folded_msm sigma g h_vec g_vec h_scalars g_scalars ⦃ r =>
      MsmMatches ψ r (foldedM (φ sigma) (ψ g) (h_vec.val.map ψ) (g_vec.val.map ψ)
        (h_scalars.val.map φ) (g_scalars.val.map φ)) ⦄ := by
  unfold bulletproofspp.norm_linear.folded_msm
  simp only [hs.zero_eq, core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
    hs.eq, bind_ok, hs.φ_z]
  rw [foldedM_eq]
  step*
  -- the first terms, `sigma` and `g` when `sigma` is not zero
  have hfirst : ∀ (sc1 : alloc.vec.Vec S) (pts1 : alloc.vec.Vec P),
      sc1.val.map φ = (if φ sigma ≠ 0 then [φ sigma] else []) →
      pts1.val.map ψ = (if φ sigma ≠ 0 then [ψ g] else []) → sc1.length ≤ 1 → pts1.length ≤ 1 →
      (do
        let (sc2, pts2) ← bulletproofspp.norm_linear.push_nonzero sc1 pts1 h_scalars h_vec
        let (sc3, pts3) ← bulletproofspp.norm_linear.push_nonzero sc2 pts2 g_scalars g_vec
        groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsMultiScalarMul.multi_scalar_mul
          (alloc.vec.Vec.deref sc3) (alloc.vec.Vec.deref pts3)) ⦃ r =>
      MsmMatches ψ r (Bppp.multi_scalar_mul
        ((if φ sigma ≠ 0 then [φ sigma] else []) ++
          (nonzero (h_scalars.val.map φ) (h_vec.val.map ψ)).1 ++
          (nonzero (g_scalars.val.map φ) (g_vec.val.map ψ)).1)
        ((if φ sigma ≠ 0 then [ψ g] else []) ++
          (nonzero (h_scalars.val.map φ) (h_vec.val.map ψ)).2 ++
          (nonzero (g_scalars.val.map φ) (g_vec.val.map ψ)).2)) ⦄ := by
    intro sc1 pts1 h1 h2 h3 h4
    have eh : h_scalars.length = h_scalars.val.length := rfl
    have eg : g_scalars.length = g_scalars.val.length := rfl
    have ehv : h_vec.length = h_vec.val.length := rfl
    have egv : g_vec.length = g_vec.val.length := rfl
    apply WP.spec_bind (push_nonzero_spec (ψ := ψ) hs sc1 pts1 h_scalars h_vec (by omega) (by omega))
    rintro ⟨sc2, pts2⟩ ⟨h5, h6, h7, h8⟩
    dsimp only at h5 h6 h7 h8 ⊢
    apply WP.spec_bind (push_nonzero_spec (ψ := ψ) hs sc2 pts2 g_scalars g_vec (by omega) (by omega))
    rintro ⟨sc3, pts3⟩ ⟨h9, h10, -, -⟩
    dsimp only at h9 h10 ⊢
    simp only [Std.uncurry_apply_pair]
    obtain ⟨r, hr, hm⟩ := hp.msm (alloc.vec.Vec.deref sc3) (alloc.vec.Vec.deref pts3)
    rw [hr, WP.spec_ok]
    have e1 : (alloc.vec.Vec.deref sc3).val = sc3.val := by simp [alloc.vec.Vec.deref]
    have e2 : (alloc.vec.Vec.deref pts3).val = pts3.val := by simp [alloc.vec.Vec.deref]
    rw [e1, e2, h9, h10, h5, h6, h1, h2] at hm
    simpa only [List.append_assoc] using hm
  by_cases h0 : φ sigma = 0
  · rw [show (decide ¬decide (φ sigma = 0) = true) = false by simp [h0]]
    simp only [Bool.false_eq_true, ite_false, bind_ok]
    exact hfirst (alloc.vec.Vec.with_capacity S i3) (alloc.vec.Vec.with_capacity P i7)
      (by simp [h0]) (by simp [h0]) (by simp [alloc.vec.Vec.length])
      (by simp [alloc.vec.Vec.length])
  · rw [show (decide ¬decide (φ sigma = 0) = true) = true by simp [h0]]
    simp only [ite_true]
    step*
    · simp; scalar_tac
    · simp; scalar_tac
    · exact hfirst ‹alloc.vec.Vec S› x (by simp [h0, *]) (by simp [h0, x_post])
        (by simp [alloc.vec.Vec.length, *]) (by simp [alloc.vec.Vec.length, x_post])

end BpppProofs
