-- THIS FILE IS AI-ONLY
import bulletproofspp.NormLinear

/-!
The generated `LazyBases::msm` of `norm_linear.rs` computes the model's.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

lemma contractM_length_le (w : List F) (pts : List E) (hw : 0 < w.length) :
    (contractM w pts).length ≤ pts.length := by
  unfold contractM
  rw [List.length_map]
  induction pts using Bppp.NormLinear.chunks.induct w.length with
  | case1 l h =>
    rw [Bppp.NormLinear.chunks, dif_pos h]; simp
  | case2 l h ih =>
    rw [Bppp.NormLinear.chunks, dif_neg h, List.length_cons]
    simp only [not_or] at h
    have := List.length_pos_of_ne_nil h.2
    simp only [List.length_drop] at ih
    omega

/-- What lazy bases keep between rounds: equal weight lengths between 1 and `2^3`, and points no
longer than the CRS's. -/
structure LBInv (gens : bulletproofspp.crs.Generators) (lb : bulletproofspp.norm_linear.LazyBases) :
    Prop where
  pos : 0 < lb.w_h.length
  eq : lb.w_g.length = lb.w_h.length
  le : lb.w_h.length ≤ 8
  h_le : (lbLen gens lb).1 ≤ gens.h_vec.length
  g_le : (lbLen gens lb).2 ≤ gens.g_vec.length

/-- The result of a generated `LazyBases::msm` matches the model's. -/
def LazyMatches (φ : S → F) (ψ : P → E) (gens : bulletproofspp.crs.Generators)
    (r : core.result.Result P error.FastCryptoError × bulletproofspp.norm_linear.LazyBases)
    (m : Bppp.Result (E × Bppp.NormLinear.LazyBases F E)) : Prop :=
  match m with
  | .ok (e, lbm) => ∃ p, r.1 = .Ok p ∧ ψ p = e ∧ toLB φ ψ gens r.2 = lbm ∧ LBInv gens r.2
  | .error _ => r.1 = .Err .InvalidInput

lemma lazy_msm_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (hgl : 1 + gens.h_vec.length + gens.g_vec.length + 8 ≤ Usize.max)
    (lb : bulletproofspp.norm_linear.LazyBases) (hlb : LBInv gens lb) (sigma : S) (l n : Slice S) :
    bulletproofspp.norm_linear.LazyBases.msm lb gens sigma l n ⦃ r =>
      LazyMatches φ ψ gens r ((toLB φ ψ gens lb).msm (φ sigma) (l.val.map φ) (n.val.map φ)) ⦄ := by
  obtain ⟨hpos, heqw, hle8, hhle, hgle⟩ := hlb
  unfold bulletproofspp.norm_linear.LazyBases.msm bulletproofspp.norm_linear.Weights.len
  simp only [bind_ok, bulletproofspp.norm_linear.FOLD_BATCH_ROUNDS]
  step*
  · rcases System.Platform.numBits_eq with h | h <;> simp [h]
  all_goals
    have hi1 : i1.val = 8 := by
      rw [i1_post]
      have : 8 < Usize.size := by
        rcases System.Platform.numBits_eq with h | h <;> simp [Usize.size, Usize.numBits, h]
      exact Nat.mod_eq_of_lt this
  all_goals have ewh : (alloc.vec.Vec.len lb.w_h).val = lb.w_h.length := rfl
  · rename_i hfold
    have hw8 : lb.w_h.length = 8 := by rw [← ewh, hfold, hi1]
    apply WP.spec_bind (points_spec (φ := φ) (ψ := ψ) gens lb)
    rintro ⟨g, hv, gv⟩ ⟨hpts, hplen⟩
    have hhl := congrArg Prod.fst hplen
    have hgl' := congrArg Prod.snd hplen
    simp only at hhl hgl'
    apply WP.spec_bind (contract_spec (φ := φ) hp lb.w_h hpos hv
      (by have := hhle; rw [← hhl] at this; omega))
    rintro r ⟨val, hr, hval⟩
    rw [hr]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
    apply WP.spec_bind (contract_spec (φ := φ) hp lb.w_g (by omega) gv
      (by have := hgle; rw [← hgl'] at this; omega))
    rintro r1 ⟨val1, hr1, hval1⟩
    rw [hr1]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
    apply WP.spec_bind (weights_new_spec hs)
    rintro w ⟨hw, hwl⟩
    apply WP.spec_bind (len_spec (φ := φ) (ψ := ψ) gens
      { points := .Folded g (val, val1), w_h := w, w_g := w })
    rintro ⟨h_len, g_len⟩ ⟨hlen1, -⟩
    simp only [lbLen, Prod.mk.injEq] at hlen1
    obtain ⟨hhlen, hglen⟩ := hlen1
    apply WP.spec_bind (tensor_spec hs w l h_len)
    rintro hsc ⟨hhsc, hhscl⟩
    apply WP.spec_bind (tensor_spec hs w n g_len)
    rintro gsc ⟨hgsc, hgscl⟩
    -- lengths
    have evl : val.length = val.val.length := rfl
    have evl1 : val1.length = val1.val.length := rfl
    have hvl : val.val.length ≤ hv.val.length := by
      have := congrArg List.length hval
      rw [List.length_map] at this
      rw [this]; exact (contractM_length_le _ _ (by simpa using hpos)).trans (by simp)
    have hvl1 : val1.val.length ≤ gv.val.length := by
      have := congrArg List.length hval1
      rw [List.length_map] at this
      have hwg : lb.w_g.length = lb.w_g.val.length := rfl
      rw [this]; exact (contractM_length_le _ _ (by simp; omega)).trans (by simp)
    have ehv : hv.length = hv.val.length := rfl
    have egv : gv.length = gv.val.length := rfl
    have ehg : gens.h_vec.length = gens.h_vec.val.length := rfl
    have egg : gens.g_vec.length = gens.g_vec.val.length := rfl
    have hhl2 : hv.val.length ≤ gens.h_vec.val.length := by rw [← ehv, hhl, ← ehg]; exact hhle
    have hgl2 : gv.val.length ≤ gens.g_vec.val.length := by rw [← egv, hgl', ← egg]; exact hgle
    have hhscl' : hsc.val.length ≤ val.val.length := by
      have : hsc.length = hsc.val.length := rfl
      rw [← this, hhscl, hhlen]; omega
    have hgscl' : gsc.val.length ≤ val1.val.length := by
      have : gsc.length = gsc.val.length := rfl
      rw [← this, hgscl, hglen]; omega
    apply WP.spec_bind (folded_msm_spec hs hp sigma g (alloc.vec.Vec.deref val)
      (alloc.vec.Vec.deref val1) (alloc.vec.Vec.deref hsc) (alloc.vec.Vec.deref gsc)
      (by simp [alloc.vec.Vec.deref, Slice.length]; omega)
      (by simp [alloc.vec.Vec.deref, Slice.length]; omega)
      (by simp [alloc.vec.Vec.deref, Slice.length]; omega))
    intro r2 hr2
    rw [WP.spec_ok]
    have hmodel : (toLB φ ψ gens lb).msm (φ sigma) (l.val.map φ) (n.val.map φ) =
        (foldedM (φ sigma) (ψ g) (val.val.map ψ) (val1.val.map ψ) (hsc.val.map φ)
          (gsc.val.map φ) >>= fun p =>
          pure (p, toLB φ ψ gens { points := .Folded g (val, val1), w_h := w, w_g := w })) := by
      unfold Bppp.NormLinear.LazyBases.msm
      have hlen8 : (toLB φ ψ gens lb).w_h.len = 2 ^ Bppp.FOLD_BATCH_ROUNDS := by
        simp [toLB, toW, Bppp.NormLinear.Weights.len, Bppp.FOLD_BATCH_ROUNDS]
        exact hw8
      rw [if_pos hlen8]
      have hwm : w.val.map φ = (Bppp.NormLinear.Weights.new : Bppp.NormLinear.Weights F).w := by
        have := congrArg Bppp.NormLinear.Weights.w hw; simpa [toW] using this
      simp only [← hpts]
      simp only [toLB, toW, contract_model, ← hval, ← hval1, except_ok_bind]
      simp only [Bppp.NormLinear.LazyBases.len, Bppp.NormLinear.LazyBases.points',
        Bppp.NormLinear.Weights.tensor, foldedM, hhsc, hgsc, hwm, ← hhlen, ← hglen,
        List.length_map, tensorM, pure_bind]
    unfold LazyMatches
    rw [hmodel]
    simp only [deref_val] at hr2
    unfold MsmMatches at hr2
    cases hf : foldedM (φ sigma) (ψ g) (val.val.map ψ) (val1.val.map ψ) (hsc.val.map φ)
        (gsc.val.map φ) with
    | error e => rw [hf] at hr2; simpa using hr2
    | ok e =>
      rw [hf] at hr2
      obtain ⟨p, hp1, hp2⟩ := hr2
      refine ⟨p, hp1, hp2, rfl, ?_⟩
      have ewl : w.length = w.val.length := rfl
      refine ⟨?_, rfl, ?_, ?_, ?_⟩
      · show 0 < w.length; omega
      · show w.length ≤ 8; omega
      · show val.length ≤ gens.h_vec.length; omega
      · show val1.length ≤ gens.g_vec.length; omega
  · rename_i hfold
    have hw8 : lb.w_h.length ≠ 8 := by
      intro h; apply hfold; apply UScalar.eq_of_val_eq; rw [ewh, h, hi1]
    apply WP.spec_bind (len_spec (φ := φ) (ψ := ψ) gens lb)
    rintro ⟨h_len, g_len⟩ ⟨hlen1, hlen2⟩
    have hhlen := congrArg Prod.fst hlen1
    have hglen := congrArg Prod.snd hlen1
    simp only at hhlen hglen
    apply WP.spec_bind (tensor_spec hs lb.w_h l h_len)
    rintro hsc ⟨hhsc, hhscl⟩
    apply WP.spec_bind (tensor_spec hs lb.w_g n g_len)
    rintro gsc ⟨hgsc, hgscl⟩
    have ehg : gens.h_vec.length = gens.h_vec.val.length := rfl
    have egg : gens.g_vec.length = gens.g_vec.val.length := rfl
    have hhscl' : hsc.val.length ≤ h_len.val := by
      have : hsc.length = hsc.val.length := rfl
      rw [← this, hhscl]; omega
    have hgscl' : gsc.val.length ≤ g_len.val := by
      have : gsc.length = gsc.val.length := rfl
      rw [← this, hgscl]; omega
    -- the model, up to the MSM
    have hmodel : ∀ (pt : Bppp.Result E),
        (match (toLB φ ψ gens lb).points with
          | .Crs gm => gm.msm (φ sigma) (hsc.val.map φ) (gsc.val.map φ) [] []
          | .Folded g hv gv => foldedM (φ sigma) g hv gv (hsc.val.map φ) (gsc.val.map φ)) = pt →
        (toLB φ ψ gens lb).msm (φ sigma) (l.val.map φ) (n.val.map φ) =
          (pt >>= fun p => pure (p, toLB φ ψ gens lb)) := by
      intro pt hpt
      unfold Bppp.NormLinear.LazyBases.msm
      have hlen8 : ¬ (toLB φ ψ gens lb).w_h.len = 2 ^ Bppp.FOLD_BATCH_ROUNDS := by
        simp [toLB, toW, Bppp.NormLinear.Weights.len, Bppp.FOLD_BATCH_ROUNDS]
        exact hw8
      rw [if_neg hlen8, pure_bind]
      beta_reduce
      rw [← hlen2]
      have e1 : (toLB φ ψ gens lb).w_h = toW φ lb.w_h := rfl
      have e2 : (toLB φ ψ gens lb).w_g = toW φ lb.w_g := rfl
      have t1 : List.take h_len.val ((toW φ lb.w_h).tensor (l.val.map φ)) = hsc.val.map φ := by
        rw [hhsc]; rfl
      have t2 : List.take g_len.val ((toW φ lb.w_g).tensor (n.val.map φ)) = gsc.val.map φ := by
        rw [hgsc]; rfl
      simp only [e1, e2, t1, t2]
      rw [← hpt]
      cases (toLB φ ψ gens lb).points <;> simp [foldedM]
    unfold LazyMatches
    cases hpts : lb.points with
    | Crs =>
      simp only [hpts]
      step*
      apply WP.spec_bind (gens_msm_spec hs gens hg sigma (alloc.vec.Vec.deref hsc)
        (alloc.vec.Vec.deref gsc) _ _ (by omega)
        (by simp [Slice.length]; simp [lbLen, hpts] at hhlen hglen; omega))
      intro r hr
      rw [WP.spec_ok]
      have hm := hmodel _ rfl
      simp only [toLB, hpts] at hm ⊢
      rw [hm]
      simp only [deref_val, s2_post, s3_post] at hr
      have ea : ((Std.Array.empty S).to_slice).val = [] := by simp [Std.Array.empty]
      have eb : ((Std.Array.empty P).to_slice).val = [] := by simp [Std.Array.empty]
      rw [ea, eb, List.map_nil, List.map_nil] at hr
      unfold MsmMatches at hr
      cases hm2 : (toGens ψ gens).msm (φ sigma) (hsc.val.map φ) (gsc.val.map φ) [] [] with
      | error e => rw [hm2] at hr; simpa using hr
      | ok e =>
        rw [hm2] at hr
        obtain ⟨p, hp1, hp2⟩ := hr
        exact ⟨p, hp1, hp2, rfl, ⟨hpos, heqw, hle8, hhle, hgle⟩⟩
    | Folded g p =>
      obtain ⟨hv, gv⟩ := p
      simp only [hpts]
      simp [lbLen, hpts] at hhlen hglen hhle hgle
      have ehv : hv.length = hv.val.length := rfl
      have egv : gv.length = gv.val.length := rfl
      apply WP.spec_bind (folded_msm_spec hs hp sigma g (alloc.vec.Vec.deref hv)
        (alloc.vec.Vec.deref gv) (alloc.vec.Vec.deref hsc) (alloc.vec.Vec.deref gsc)
        (by simp [Slice.length]; omega) (by simp [Slice.length]; omega)
        (by simp [Slice.length]; omega))
      intro r hr
      rw [WP.spec_ok]
      have hm := hmodel _ rfl
      simp only [toLB, hpts] at hm ⊢
      rw [hm]
      simp only [deref_val] at hr
      unfold MsmMatches at hr
      cases hm2 : foldedM (φ sigma) (ψ g) (hv.val.map ψ) (gv.val.map ψ) (hsc.val.map φ)
          (gsc.val.map φ) with
      | error e => rw [hm2] at hr; simpa using hr
      | ok e =>
        rw [hm2] at hr
        obtain ⟨p, hp1, hp2⟩ := hr
        exact ⟨p, hp1, hp2, rfl, ⟨hpos, heqw, hle8, by simp [lbLen, hpts]; omega,
          by simp [lbLen, hpts]; omega⟩⟩

end BpppProofs
