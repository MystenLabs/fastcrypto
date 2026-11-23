-- THIS FILE IS AI-ONLY
import bulletproofspp.Points
import bulletproofspp.Constraints
import bulletproofspp.Model.NormLinear

/-!
The generated functions of `norm_linear.rs` compute the functions of `Model/NormLinear.lean`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar

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

end BpppProofs
