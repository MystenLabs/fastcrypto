-- THIS FILE IS AI-ONLY
import bulletproofspp.Prove
import bulletproofspp.Proofs.NormLinear

/-!
The generated `norm_linear::verify` computes the model's.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

lemma proof_shape_spec' (a b : Usize) (hab : a.val + b.val ≤ Usize.max) :
    bulletproofspp.norm_linear.proof_shape a b ⦃ r =>
      (r.1.val, r.2.val) = Bppp.NormLinear.proof_shape a.val b.val ⦄ := by
  unfold bulletproofspp.norm_linear.proof_shape bulletproofspp.norm_linear.proof_shape_loop
  apply loop.spec_decr_nat (fun q => q.1.val + q.2.1.val)
    (fun q => q.2.2.val + q.1.val + q.2.1.val ≤ a.val + b.val ∧
      ((Bppp.NormLinear.proof_shape q.1.val q.2.1.val).1 + q.2.2.val,
        (Bppp.NormLinear.proof_shape q.1.val q.2.1.val).2) =
      Bppp.NormLinear.proof_shape a.val b.val)
  · rintro ⟨x, y, k⟩ ⟨hxy, heq⟩
    dsimp only at hxy heq
    simp only [Std.uncurry_apply_pair]
    unfold bulletproofspp.norm_linear.proof_shape_loop.body
    rw [BpppProofs.is_base_case_spec x y (by omega), bind_ok]
    by_cases hb : Bppp.NormLinear.is_base_case x.val y.val = true
    · simp only [hb, ite_true, WP.spec_ok]
      rw [← heq, Bppp.NormLinear.proof_shape, dif_pos hb]
      simp
    · simp only [hb, Bool.false_eq_true, ite_false]
      have hnb : ¬ Bppp.NormLinear.is_base_case x.val y.val := by simpa using hb
      have hd := (Bppp.NormLinear.is_base_case_iff x.val y.val).not.mp hnb
      have hdec : (x.val + 1) / 2 + (y.val + 1) / 2 < x.val + y.val := by
        by_cases hx : x.val ≤ 1
        · have : ¬ x.val + y.val < 6 := fun h => hd ⟨hx, h⟩
          omega
        · omega
      step*
      have h1 : l_len1.val = (x.val + 1) / 2 := by
        rw [l_len1_post, Nat.ceilDiv_eq_add_pred_div]; rfl
      have h2 : n_len1.val = (y.val + 1) / 2 := by
        rw [n_len1_post, Nat.ceilDiv_eq_add_pred_div]; rfl
      rw [Bppp.NormLinear.proof_shape_step hnb] at heq
      refine ⟨by omega, ?_, by omega⟩
      rw [← heq, h1, h2, rounds1_post]
      simp only [Prod.mk.injEq]
      exact ⟨by omega, trivial⟩
  · simp

/-- `x` halved, rounding up, `k` times. -/
def halveN : ℕ → ℕ → ℕ
  | 0, x => x
  | k + 1, x => halveN k ((x + 1) / 2)

lemma halveN_pos : ∀ (k x : ℕ), 1 ≤ x → 1 ≤ halveN k x
  | 0, x, h => h
  | k + 1, x, h => halveN_pos k _ (by omega)

/-- The rounds of `proof_shape` halve the `l` length down to 1. -/
lemma proof_shape_halve : ∀ (a b : ℕ), 1 ≤ a →
    halveN (Bppp.NormLinear.proof_shape a b).1 a = 1 := by
  intro a b
  induction a, b using Bppp.NormLinear.proof_shape.induct with
  | case1 a b h =>
    intro ha
    rw [Bppp.NormLinear.proof_shape, dif_pos h]
    rw [Bppp.NormLinear.is_base_case_iff] at h
    simp [halveN]; omega
  | case2 a b h _ _ _ ih =>
    intro ha
    rw [Bppp.NormLinear.proof_shape_step h]
    exact ih (by omega)

/-- The model of the state of the round loop of `verify`. -/
def toVSt (φ : S → F) (c : alloc.vec.Vec S) (rho mu : S) (gammas : alloc.vec.Vec S)
    (w_h w_g : bulletproofspp.norm_linear.Weights) :
    List F × F × F × List F × Bppp.NormLinear.Weights F × Bppp.NormLinear.Weights F :=
  (c.val.map φ, φ rho, φ mu, gammas.val.map φ, toW φ w_h, toW φ w_g)

lemma verify_rounds_spec (hs : ScalarModel F φ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (rounds : alloc.vec.Vec (P × P))
    (hR : 2 * 2 ^ rounds.val.length ≤ Usize.max)
    (t : bulletproofspp.transcript.BpppTranscript) (c : alloc.vec.Vec S) (rho mu : S)
    (gammas : alloc.vec.Vec S) (w_h w_g : bulletproofspp.norm_linear.Weights) (r : Usize)
    (hr : r.val ≤ rounds.val.length) (hg : gammas.val.length = r.val)
    (hwh : w_h.length = 2 ^ r.val) (hwg : w_g.length = 2 ^ r.val)
    (hc : c.val.length < Usize.max) :
    bulletproofspp.norm_linear.verify_loop0 t rounds c rho mu gammas w_h w_g r ⦃ q => ∃ ρ',
      ((roundsψ ψ (rounds.val.drop r.val)).foldlM Bppp.NormLinear.verify_round
        (toVSt φ c rho mu gammas w_h w_g)).run (τ t) =
        .ok ((q.2.1.val.map φ, ρ', φ q.2.2.1, q.2.2.2.1.val.map φ,
          toW φ q.2.2.2.2.1, toW φ q.2.2.2.2.2), τ q.1) ∧
      q.2.2.2.1.val.length = rounds.val.length ∧ q.2.2.2.2.1.length = 2 ^ rounds.val.length ∧
      q.2.2.2.2.2.length = 2 ^ rounds.val.length ∧
      q.2.1.val.length ≤ c.val.length ∧
      q.2.1.val.length = halveN (rounds.val.length - r.val) c.val.length ⦄ := by
  unfold bulletproofspp.norm_linear.verify_loop0
  have erl : rounds.length = rounds.val.length := rfl
  apply loop.spec_decr_nat (fun q => rounds.length - q.2.2.2.2.2.2.2.val)
    (fun q => q.2.2.2.2.2.2.2.val ≤ rounds.val.length ∧
      q.2.2.2.2.1.val.length = q.2.2.2.2.2.2.2.val ∧
      q.2.2.2.2.2.1.length = 2 ^ q.2.2.2.2.2.2.2.val ∧
      q.2.2.2.2.2.2.1.length = 2 ^ q.2.2.2.2.2.2.2.val ∧
      q.2.1.val.length ≤ c.val.length ∧
      halveN (rounds.val.length - q.2.2.2.2.2.2.2.val) q.2.1.val.length =
        halveN (rounds.val.length - r.val) c.val.length ∧
      ((roundsψ ψ (rounds.val.drop q.2.2.2.2.2.2.2.val)).foldlM Bppp.NormLinear.verify_round
        (toVSt φ q.2.1 q.2.2.1 q.2.2.2.1 q.2.2.2.2.1 q.2.2.2.2.2.1 q.2.2.2.2.2.2.1)).run (τ q.1) =
      ((roundsψ ψ (rounds.val.drop r.val)).foldlM Bppp.NormLinear.verify_round
        (toVSt φ c rho mu gammas w_h w_g)).run (τ t))
  · rintro ⟨t', c', rho', mu', g', wh', wg', k⟩ ⟨hk, hgl, hwhl, hwgl, hcl, hhalf, heq⟩
    dsimp only at hk hgl hwhl hwgl hcl hhalf heq
    simp only [Std.uncurry_apply_pair]
    unfold bulletproofspp.norm_linear.verify_loop0.body
    step*
    · have hkl' : k.val < rounds.val.length := by scalar_tac
      apply WP.spec_bind (round_challenge_spec (φ := φ) ht t' x_point r_point)
      rintro ⟨gamma, t1⟩ ⟨T1, T2, hX, hRr, hG⟩
      simp only [Std.uncurry_apply_pair, one_spec hs, bind_ok]
      have egl : g'.length = g'.val.length := rfl
      step*
      have hpk : 2 * 2 ^ k.val ≤ Usize.max :=
        le_trans (Nat.mul_le_mul_left 2 (Nat.pow_le_pow_right (by norm_num) hk)) hR
      apply WP.spec_bind (tensor_pair_spec hs wh' hs.o gamma (by rw [hwhl]; exact hpk))
      rintro wh1 ⟨hwh1, hwh1l⟩
      apply WP.spec_bind (tensor_pair_spec hs wg' rho' gamma (by rw [hwgl]; exact hpk))
      rintro wg1 ⟨hwg1, hwg1l⟩
      apply WP.spec_bind (split_even_odd_spec hs c' (by omega))
      rintro ⟨c0, c1⟩ hc01
      dsimp only at hc01
      simp only [Std.uncurry_apply_pair]
      apply WP.spec_bind (vec_scalar_mul_spec hs gamma (alloc.vec.Vec.deref c1))
      intro v1 hv1
      have hsc := Bppp.NormLinear.split_even_odd_length (c'.val.map φ)
      rw [← hc01] at hsc
      simp only [List.length_map] at hsc
      have hlen : (alloc.vec.Vec.deref c0).length = (alloc.vec.Vec.deref v1).length := by
        have := congrArg List.length hv1
        simp [Bppp.vec_scalar_mul] at this
        simp [Slice.length, this]; omega
      apply WP.spec_bind (vec_add_spec hs _ _ hlen)
      intro c2 hc2
      simp only [hs.mul_eq, bind_ok]
      step*
      have hc2l : c2.val.length ≤ c'.val.length := by
        have := congrArg List.length hc2
        have h2 := congrArg List.length hv1
        simp [Bppp.vec_add, Bppp.vec_scalar_mul] at this h2
        omega
      have hc2e : c2.val.length = (c'.val.length + 1) / 2 := by
        have := congrArg List.length hc2
        have h2 := congrArg List.length hv1
        simp [Bppp.vec_add, Bppp.vec_scalar_mul] at this h2
        omega
      refine ⟨by scalar_tac, by simp [gammas1_post]; scalar_tac, by rw [hwh1l, hwhl, r1_post]; ring,
        by rw [hwg1l, hwgl, r1_post]; ring, by omega, ?_, ?_, by scalar_tac⟩
      · rw [← hhalf, r1_post, hc2e,
          show rounds.val.length - k.val = (rounds.val.length - (k.val + 1)) + 1 by omega]
        rfl
      rw [← heq, r1_post]
      conv_rhs => rw [show roundsψ ψ (rounds.val.drop k.val) =
          (ψ x_point, ψ r_point) :: roundsψ ψ (rounds.val.drop (k.val + 1)) by
        rw [List.drop_eq_getElem_cons hkl']
        simp only [roundsψ, List.map_cons]
        rw [← ‹(x_point, r_point) = rounds.val[k.val]›]]
      rw [List.foldlM_cons, StateT.run_bind]
      simp only [Bppp.NormLinear.verify_round, StateT.run_bind, hX, except_ok_bind, hRr, hG]
      simp only [StateT.run_pure, except_ok_bind, toVSt]
      congr 2
      simp only [Prod.mk.injEq]
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simp only [deref_val] at hc2 hv1 ⊢
        rw [hc2, hv1]
        have h0 := congrArg Prod.fst hc01
        have h1 := congrArg Prod.snd hc01
        simp only at h0 h1
        rw [← h0, ← h1]
      · trivial
      · simp
      · simp [gammas1_post]
      · rw [hwh1]; simp [Bppp.one]
      · exact hwg1
    · have hkv : rounds.val.length ≤ k.val := by scalar_tac
      refine ⟨φ rho', ?_, by omega, by rw [hwhl]; congr 1; omega,
        by rw [hwgl]; congr 1; omega, hcl, ?_⟩
      swap
      · rw [← hhalf, show rounds.val.length - k.val = 0 by omega]; rfl
      rw [← heq, List.drop_of_length_le (by simpa using hkv)]
      rfl
  · exact ⟨hr, hg, hwh, hwg, le_refl _, rfl, rfl⟩

lemma verify_n_spec (hs : ScalarModel F φ) (p_n : Slice S) (w_n : alloc.vec.Vec S)
    (out : alloc.vec.Vec S) (hout : out.val = []) :
    bulletproofspp.norm_linear.verify_loop1 p_n w_n out 0#usize ⦃ r =>
      r.val.map φ = List.zipWith (fun w p => w - p) (w_n.val.map φ) (p_n.val.map φ) ⦄ := by
  unfold bulletproofspp.norm_linear.verify_loop1
  have ew : w_n.length = w_n.val.length := rfl
  have ep : p_n.length = p_n.val.length := rfl
  apply WP.spec_mono (push_loop_specψ (min w_n.val.length p_n.val.length) φ
    (fun i => (w_n.val.map φ).getD i 0 - (p_n.val.map φ).getD i 0) _ _ out 0#usize
    (by simp [alloc.vec.Vec.length, hout]) (by simp))
  · intro r hr
    rw [hr, hout]
    apply List.ext_getElem (by simp)
    intro k h1 h2
    simp at h1
    simp [List.getElem?_eq_getElem (show k < w_n.val.length by omega),
      List.getElem?_eq_getElem (show k < p_n.val.length by omega)]
  · intro v i hv hi
    simp only [Std.uncurry_apply_pair]
    unfold bulletproofspp.norm_linear.verify_loop1.body
    simp only [hs.sub_eq]
    step*
    refine ⟨_, _, rfl, ⟨_, n1_post, ?_⟩, i3_post⟩
    have hi1 : i.val < w_n.val.length := by omega
    have hi2 : i.val < p_n.val.length := by omega
    simp [rs_post, rs1_post, List.getElem?_eq_getElem hi1, List.getElem?_eq_getElem hi2]
  · intro v i hv hi
    simp only [Std.uncurry_apply_pair]
    unfold bulletproofspp.norm_linear.verify_loop1.body
    by_cases h : i.val < w_n.val.length
    · have : ¬ i < p_n.len := by scalar_tac
      have h' : i < w_n.len := by scalar_tac
      simp [h', this]
    · have : ¬ i < w_n.len := by scalar_tac
      simp [this]

lemma verify_extra_spec (hs : ScalarModel F φ) (extra : Slice (S × P))
    (ds : alloc.vec.Vec S) (dp : alloc.vec.Vec P) (hds : ds.val = []) (hdp : dp.val = [])
    (hlen : extra.length + 1 ≤ Usize.max) :
    bulletproofspp.norm_linear.verify_loop2 extra ds dp 0#usize ⦃ r =>
      r.1.val.map φ = extra.val.map (fun q => -φ q.1) ∧
      r.2.val.map ψ = extra.val.map (fun q => ψ q.2) ∧
      r.1.val.length = extra.val.length ∧ r.2.val.length = extra.val.length ⦄ := by
  unfold bulletproofspp.norm_linear.verify_loop2
  have ee : extra.length = extra.val.length := rfl
  apply loop.spec_decr_nat (fun q => extra.length - q.2.2.val)
    (fun q => q.2.2.val ≤ extra.length ∧
      q.1.val.map φ = (extra.val.take q.2.2.val).map (fun q => -φ q.1) ∧
      q.2.1.val.map ψ = (extra.val.take q.2.2.val).map (fun q => ψ q.2) ∧
      q.1.val.length = q.2.2.val ∧ q.2.1.val.length = q.2.2.val)
  · rintro ⟨a, b, i⟩ ⟨hi, ha, hb, hal, hbl⟩
    dsimp only at hi ha hb hal hbl
    simp only [Std.uncurry_apply_pair]
    unfold bulletproofspp.norm_linear.verify_loop2.body
    simp only [hs.neg_eq]
    have ea : a.length = a.val.length := rfl
    have eb : b.length = b.val.length := rfl
    step*
    · have hil : i.val < extra.val.length := by scalar_tac
      have hq := ‹(_, _) = extra.val[i.val]›
      refine ⟨by scalar_tac, ?_, ?_, by simp [dynamic_scalars1_post]; omega,
        by simp [dynamic_points1_post]; omega, by scalar_tac⟩
      · rw [dynamic_scalars1_post, i2_post, List.take_succ_eq_append_getElem hil, ← hq]
        simp [ha]
      · rw [dynamic_points1_post, i2_post, List.take_succ_eq_append_getElem hil, ← hq]
        simp [hb]
    · have hie : i.val = extra.val.length := by scalar_tac
      rw [hie, List.take_length] at ha hb
      exact ⟨ha, hb, by omega, by omega⟩
  · exact ⟨by simp, by simp [hds], by simp [hdp], by simp [hds], by simp [hdp]⟩

/-- The terms that the rounds add to the verifier's MSM. -/
def roundTerms (rs : List (E × E)) (gs : List F) : List (F × E) :=
  (List.zip rs gs).flatMap fun ((x, r), g) => [(-g, x), (Bppp.one - g * g, r)]

lemma roundTerms_take_succ (rs : List (E × E)) (gs : List F) (k : ℕ) (h1 : k < rs.length)
    (h2 : k < gs.length) :
    roundTerms (rs.take (k + 1)) (gs.take (k + 1)) = roundTerms (rs.take k) (gs.take k) ++
      [(-gs[k], rs[k].1), (Bppp.one - gs[k] * gs[k], rs[k].2)] := by
  unfold roundTerms
  rw [List.take_succ_eq_append_getElem h1, List.take_succ_eq_append_getElem h2,
    List.zip_append (by simp; omega), List.flatMap_append]
  simp

lemma verify_round_terms_spec (hs : ScalarModel F φ) (rounds : alloc.vec.Vec (P × P))
    (gammas : alloc.vec.Vec S) (ds : alloc.vec.Vec S) (dp : alloc.vec.Vec P)
    (hlen : ds.val.length + 2 * rounds.val.length ≤ Usize.max)
    (hlen' : dp.val.length + 2 * rounds.val.length ≤ Usize.max) :
    bulletproofspp.norm_linear.verify_loop3 rounds gammas ds dp 0#usize ⦃ r =>
      r.1.val.map φ = ds.val.map φ ++
        (roundTerms (roundsψ ψ rounds.val) (gammas.val.map φ)).map Prod.fst ∧
      r.2.val.map ψ = dp.val.map ψ ++
        (roundTerms (roundsψ ψ rounds.val) (gammas.val.map φ)).map Prod.snd ⦄ := by
  unfold bulletproofspp.norm_linear.verify_loop3
  have er : rounds.length = rounds.val.length := rfl
  have eg : gammas.length = gammas.val.length := rfl
  set n := min rounds.val.length gammas.val.length with hn
  apply loop.spec_decr_nat (fun q => rounds.length - q.2.2.val)
    (fun q => q.2.2.val ≤ n ∧
      q.1.val.map φ = ds.val.map φ ++ (roundTerms ((roundsψ ψ rounds.val).take q.2.2.val)
        ((gammas.val.map φ).take q.2.2.val)).map Prod.fst ∧
      q.2.1.val.map ψ = dp.val.map ψ ++ (roundTerms ((roundsψ ψ rounds.val).take q.2.2.val)
        ((gammas.val.map φ).take q.2.2.val)).map Prod.snd ∧
      q.1.val.length = ds.val.length + 2 * q.2.2.val ∧
      q.2.1.val.length = dp.val.length + 2 * q.2.2.val)
  · rintro ⟨a, b, k⟩ ⟨hk, ha, hb, hal, hbl⟩
    dsimp only at hk ha hb hal hbl
    simp only [Std.uncurry_apply_pair]
    unfold bulletproofspp.norm_linear.verify_loop3.body
    simp only [hs.neg_eq, hs.mul_eq, hs.sub_eq, one_spec hs, bind_ok]
    have ea : a.length = a.val.length := rfl
    have eb : b.length = b.val.length := rfl
    step*
    · have : k.val < rounds.val.length := by scalar_tac
      simp [dynamic_scalars1_post]; omega
    · have : k.val < rounds.val.length := by scalar_tac
      simp [dynamic_points1_post]; omega
    · have hk1 : k.val < (roundsψ ψ rounds.val).length := by simp [roundsψ]; scalar_tac
      have hk2 : k.val < (gammas.val.map φ).length := by simp; scalar_tac
      have hT := roundTerms_take_succ _ _ k.val hk1 hk2
      have hxr : (roundsψ ψ rounds.val)[k.val] = (ψ x_point, ψ r_point) := by
        simp [roundsψ, ← x_point_post]
      refine ⟨by scalar_tac, ?_, ?_, ?_, ?_, by scalar_tac⟩
      · rw [dynamic_scalars2_post, dynamic_scalars1_post, r1_post, hT]
        simp only [List.map_append, ha]
        simp [hxr, gamma_post, Bppp.one]
      · rw [dynamic_points2_post, dynamic_points1_post, r1_post, hT]
        simp only [List.map_append, hb]
        simp [hxr]
      · simp [dynamic_scalars2_post, dynamic_scalars1_post, r1_post, hal]; omega
      · simp [dynamic_points2_post, dynamic_points1_post, r1_post, hbl]; omega
    all_goals
      have hkn' : k.val = n := by scalar_tac
      have e1 : (roundsψ ψ rounds.val).take k.val = (roundsψ ψ rounds.val).take n := by rw [hkn']
      have hfull : roundTerms ((roundsψ ψ rounds.val).take n) ((gammas.val.map φ).take n) =
          roundTerms (roundsψ ψ rounds.val) (gammas.val.map φ) := by
        unfold roundTerms
        rw [@List.zip_eq_zip_take_min _ _ (roundsψ ψ rounds.val) (gammas.val.map φ)]
        simp [roundsψ, hn]
      rw [hkn', hfull] at ha hb
      exact ⟨ha, hb⟩
  · exact ⟨by simp, by simp [roundTerms], by simp [roundTerms], by simp, by simp⟩

end BpppProofs
