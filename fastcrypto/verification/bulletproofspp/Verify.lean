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

lemma proof_shape_le : ∀ (a b : ℕ), (Bppp.NormLinear.proof_shape a b).1 ≤ a + b := by
  intro a b
  induction a, b using Bppp.NormLinear.proof_shape.induct with
  | case1 a b h => rw [Bppp.NormLinear.proof_shape, dif_pos h]; simp
  | case2 a b h _ _ _ ih =>
    rw [Bppp.NormLinear.proof_shape_step h]
    have hd := (Bppp.NormLinear.is_base_case_iff a b).not.mp h
    dsimp only
    by_cases ha : a ≤ 1
    · have : ¬ a + b < 6 := fun h' => hd ⟨ha, h'⟩
      omega
    · omega

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

@[simp] lemma except_throw {ε α : Type} (e : ε) : (throw e : Except ε α) = .error e := rfl

/-- The generated error of a model error. -/
def errMap : Bppp.Error → error.FastCryptoError
  | .InvalidInput => .InvalidInput
  | .InvalidProof => .InvalidProof
  | .GeneralOpaqueError => .GeneralOpaqueError

/-- The result of a generated function returning `FastCryptoResult<()>` and the transcript
matches the model's run: success with the same transcript, or the same error. -/
def UnitMatches (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (r : core.result.Result Unit error.FastCryptoError × bulletproofspp.transcript.BpppTranscript)
    (m : Except Bppp.Error (Unit × Bppp.BpppTranscript F E)) : Prop :=
  match m with
  | .ok (_, T) => r.1 = .Ok () ∧ τ r.2 = T
  | .error e => r.1 = .Err (errMap e)

/-- The model of a generated pair of a scalar and a point. -/
def pairψ (φ : S → F) (ψ : P → E) (q : S × P) : F × E := (φ q.1, ψ q.2)

lemma msm_err (gens : Bppp.Generators E) (sigma : F) (l n ds : List F) (dp : List E) :
    ∀ e, gens.msm sigma l n ds dp = .error e → e = .InvalidInput := by
  intro e h
  unfold Bppp.Generators.msm Bppp.mixed_multi_scalar_mul at h
  split_ifs at h
  · cases h; rfl

/-- The end of `verify`: the final MSM is accepted exactly when it is zero. -/
lemma verify_tail (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (x : core.result.Result P error.FastCryptoError) (M : Bppp.Result E)
    (hM : MsmMatches ψ x M) (hMe : ∀ e, M = .error e → e = .InvalidInput)
    (t4 : bulletproofspp.transcript.BpppTranscript) :
    (do
      let cf ← core.result.Result.Insts.CoreOpsTry.branch x
      match cf with
        | core.ops.control_flow.ControlFlow.Continue val => do
          let rp ← groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElement.zero
          let b ← groups.ristretto255.RistrettoPoint.Insts.CoreCmpPartialEqRistrettoPoint.eq val rp
          if b = true then ok (core.result.Result.Ok (), t4)
            else ok (core.result.Result.Err error.FastCryptoError.InvalidProof, t4)
        | core.ops.control_flow.ControlFlow.Break residual => do
          let r1 ←
            core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual Unit
                (core.convert.FromSame error.FastCryptoError) residual
          ok (r1, t4)) ⦃ r =>
      UnitMatches τ r (((liftM M : StateT (Bppp.BpppTranscript F E) (Except Bppp.Error) E).run
          (τ t4)) >>= fun p => StateT.run (if p.1 = 0 then StateT.pure ()
            else throw Bppp.Error.InvalidProof) p.2) ⦄ := by
  rcases M with e | e
  · have he := hMe e rfl
    subst he
    simp only [MsmMatches] at hM
    subst hM
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, except_error_bind,
      UnitMatches, errMap]
  · obtain ⟨q, rfl, hqe⟩ := hM
    obtain ⟨z, hz, hz0⟩ := hp.zero
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok, hz, hp.eq, hz0, hqe,
      liftM_ok_run, except_ok_bind]
    by_cases h0 : e = 0
    · simp only [h0, decide_true, if_true, WP.spec_ok]
      exact ⟨rfl, rfl⟩
    · simp only [h0, decide_false, Bool.false_eq_true, if_false, WP.spec_ok]
      rfl

lemma verify_spec (hs : ScalarModel F φ) (hp : PointModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (gens : bulletproofspp.crs.Generators) (hg : GensOK φ ψ gens)
    (hgl : 1 + gens.h_vec.length + gens.g_vec.length + 8 ≤ Usize.max)
    (hh1 : 1 ≤ gens.h_vec.length)
    (hR : 2 * 2 ^ (Bppp.NormLinear.proof_shape gens.h_vec.length gens.g_vec.length).1 ≤ Usize.max)
    (t : bulletproofspp.transcript.BpppTranscript) (c : Slice S) (p_s : S) (p_n : Slice S)
    (extra : Slice (S × P))
    (hex : extra.length + 2 * gens.h_vec.length + 2 * gens.g_vec.length ≤ Usize.max)
    (rho : S) (proof : bulletproofspp.norm_linear.NormLinearProof) :
    bulletproofspp.norm_linear.verify t gens c p_s p_n extra rho proof ⦃ r =>
      UnitMatches τ r ((Bppp.NormLinear.verify (toGens ψ gens) (c.val.map φ) (φ p_s)
        (p_n.val.map φ) (extra.val.map (pairψ φ ψ)) (φ rho) (toProof φ ψ proof)).run (τ t)) ⦄ := by
  unfold bulletproofspp.norm_linear.verify
  have ec : c.len.val = c.val.length := rfl
  have ep : p_n.len.val = p_n.val.length := rfl
  have eh : gens.h_vec.len.val = gens.h_vec.val.length := rfl
  have eg : gens.g_vec.len.val = gens.g_vec.val.length := rfl
  have ehl : gens.h_vec.length = gens.h_vec.val.length := rfl
  have egl : gens.g_vec.length = gens.g_vec.val.length := rfl
  unfold Bppp.NormLinear.verify
  by_cases hc : c.val.length = gens.h_vec.val.length
  · have : (c.len != gens.h_vec.len) = false := by
      simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [ec, eh, hc]
    rw [if_neg (by simp [this])]
    by_cases hpn : p_n.val.length = gens.g_vec.val.length
    · have : (p_n.len != gens.g_vec.len) = false := by
        simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [ep, eg, hpn]
      rw [if_neg (by simp [this])]
      apply WP.spec_bind (proof_shape_spec' gens.h_vec.len gens.g_vec.len (by rw [eh, eg]; omega))
      rintro ⟨R, NL⟩ hRN
      simp only [Std.uncurry_apply_pair]
      rw [eh, eg] at hRN
      have hmodel1 : ¬ ((c.val.map φ).length ≠ (toGens ψ gens).h_vec.length ∨
          (p_n.val.map φ).length ≠ (toGens ψ gens).g_vec.length) := by
        simp [toGens, hc, hpn]
      simp only [hmodel1, if_false, toGens, List.length_map]
      rw [← hRN]
      have er : proof.rounds.len.val = proof.rounds.val.length := rfl
      have en : proof.n_final.len.val = proof.n_final.val.length := rfl
      by_cases hr : proof.rounds.val.length = R.val ∧ proof.n_final.val.length = NL.val
      · obtain ⟨hr1, hr2⟩ := hr
        have h1 : (proof.rounds.len != R) = false := by
          simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [er, hr1]
        have h2 : (proof.n_final.len != NL) = false := by
          simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [en, hr2]
        rw [if_neg (by simp [h1]), if_neg (by simp [h2])]
        have hmodel2 : ¬ ((toProof φ ψ proof).rounds.length ≠ R.val ∨
            (toProof φ ψ proof).n_final.length ≠ NL.val) := by
          simp [toProof, roundsψ, hr1, hr2]
        simp only [hmodel2, if_false]
        have hRv : (Bppp.NormLinear.proof_shape gens.h_vec.val.length gens.g_vec.val.length).1 =
            R.val := by rw [← hRN]
        have hRle : R.val ≤ gens.h_vec.val.length + gens.g_vec.val.length := by
          rw [← hRv]; exact proof_shape_le _ _
        apply WP.spec_bind (alloc.slice.Slice.to_vec_spec _ c (fun x _ => hs.clone x))
        intro c1 hc1
        have hc1v : c1.val = c.val := by
          have := congrArg (fun s : Slice S => s.val) hc1; rw [this]; rfl
        simp only [hs.mul_eq, bind_ok]
        apply WP.spec_bind (weights_new_spec hs)
        rintro w ⟨hw, hwl⟩
        obtain ⟨t1, h1, m1⟩ := ht.domain_sep t .NormLinear
        rw [h1, bind_ok]
        apply WP.spec_bind (verify_rounds_spec (ψ := ψ) hs ht proof.rounds
          (by rw [hr1, ← hRv, ← ehl, ← egl]; exact hR) t1 c1 rho (hs.mulF rho rho)
          (alloc.vec.Vec.with_capacity S R) w w 0#usize (by simp) (by simp) (by simp [hwl])
          (by simp [hwl]) (by rw [hc1v, hc]; omega))
        rintro ⟨t2, c2, mu1, gammas1, w_h1, w_g⟩ ⟨ρ', hfold, hg1, hwh1, hwg1, -, hc2⟩
        dsimp only at hfold hg1 hwh1 hwg1 hc2
        simp only [Std.uncurry_apply_pair]
        have hc2l : c2.val.length = 1 := by
          rw [hc2, hc1v, hc, show ((0#usize : Usize).val) = 0 from rfl, Nat.sub_zero, hr1, ← hRv]
          exact proof_shape_halve _ _ (by omega)
        simp only [core.slice.raw.from_ref, bind_ok]
        obtain ⟨t3, h3, m3⟩ := ht.append_scalars t2 .LFinal (Slice.from [proof.l_final] (by scalar_tac))
        obtain ⟨t4, h4, m4⟩ := ht.append_scalars t3 .NFinal (alloc.vec.Vec.deref proof.n_final)
        rw [h3, bind_ok, h4, bind_ok]
        have ec2 : c2.len.val = c2.val.length := rfl
        step*
        apply WP.spec_bind (weighted_norm_spec hs (alloc.vec.Vec.deref proof.n_final) mu1)
        intro rs2 hrs2
        simp only [hs.add_eq, bind_ok]
        apply WP.spec_bind (scale_spec' hs w_h1 proof.l_final gens.h_vec.len)
        rintro l ⟨hl, hll⟩
        apply WP.spec_bind (tensor_spec hs w_g (alloc.vec.Vec.deref proof.n_final) gens.g_vec.len)
        rintro w_n ⟨hwn, hwnl⟩
        apply WP.spec_bind (verify_n_spec hs p_n w_n _ (by simp))
        intro n1 hn1
        have eex : extra.len.val = extra.val.length := rfl
        have eel : extra.length = extra.val.length := rfl
        step*
        apply WP.spec_bind (verify_extra_spec (ψ := ψ) hs extra _ _ (by simp) (by simp) (by omega))
        rintro ⟨ds1, dp1⟩ ⟨hds1, hdp1, hds1l, hdp1l⟩
        simp only [Std.uncurry_apply_pair]
        apply WP.spec_bind (verify_round_terms_spec (ψ := ψ) hs proof.rounds gammas1 ds1 dp1
          (by rw [hds1l, hr1]; omega) (by rw [hdp1l, hr1]; omega))
        rintro ⟨ds2, dp2⟩ ⟨hds2, hdp2⟩
        simp only [Std.uncurry_apply_pair, hs.sub_eq, bind_ok]
        -- the model's run up to the final MSM
        rw [if_neg (by simp [hc, hpn])]
        have h00 : ((0#usize : Usize).val) = 0 := rfl
        simp only [toVSt, hc1v, hw, hs.φ_mulF, with_capacity_val, List.map_nil] at hfold
        rw [h00, List.drop_zero] at hfold
        change StateT.run (Bppp.BpppTranscript.domain_sep "norm_linear") (τ t) = _ at m1
        change StateT.run (Bppp.BpppTranscript.append_scalars "l_final" [φ proof.l_final]) (τ t2) = _
          at m3
        rw [show (alloc.vec.Vec.deref proof.n_final).val = proof.n_final.val by
          simp [alloc.vec.Vec.deref]] at m4
        change StateT.run (Bppp.BpppTranscript.append_scalars "n_final" (proof.n_final.val.map φ))
          (τ t3) = _ at m4
        simp only [toProof, StateT.run_bind, m1, except_ok_bind, hfold, m3, m4]
        have hlv : l.val.length ≤ gens.h_vec.val.length := by
          have : l.length = l.val.length := rfl
          omega
        have hn1l := congrArg List.length hn1
        have hwnl' := congrArg List.length hwn
        simp only [List.length_map, List.length_zipWith, List.length_take] at hn1l hwnl'
        have : w_n.length = w_n.val.length := rfl
        have : n1.length = n1.val.length := rfl
        apply WP.spec_bind (gens_msm_spec hs gens hg _ (alloc.vec.Vec.deref l)
          (alloc.vec.Vec.deref n1) (alloc.vec.Vec.deref ds2) (alloc.vec.Vec.deref dp2) (by omega)
          (by simp only [deref_val, Slice.length]; omega))
        intro r hr
        simp only at hds1 hdp1 hds2 hdp2
        convert verify_tail hp r _ hr (msm_err _ _ _ _ _ _) t4 using 7
        case e'_3.e'_5.e'_6 => rfl
        case e'_3.e'_5.e'_7 =>
          obtain ⟨x0, hx0⟩ := List.length_eq_one_iff.mp hc2l
          simp only [hx0] at rs_post
          simp [hx0, rs_post, hrs2]
        case e'_3.e'_5.e'_8 => rw [deref_val, hl, eh]
        case e'_3.e'_5.e'_9 => rw [deref_val, hn1, hwn, eg, deref_val]; rfl
        case e'_3.e'_5.e'_10 =>
          rw [deref_val, hds2, hds1, List.map_append]
          congr 1
          simp [pairψ]
        case e'_3.e'_5.e'_11 =>
          rw [deref_val, hdp2, hdp1, List.map_append]
          congr 1
          simp [pairψ]
      · rw [not_and_or] at hr
        rcases hr with hr | hr
        · have h1 : (proof.rounds.len != R) = true := by
            simp only [bne_iff_ne, ne_eq]; intro h; apply hr; rw [← er, h]
          rw [if_pos h1]
          simp [UnitMatches, toProof, roundsψ, hr, errMap, hc, hpn]
        · by_cases hr1 : proof.rounds.val.length = R.val
          · have h1 : (proof.rounds.len != R) = false := by
              simp only [bne_eq_false_iff_eq]; apply UScalar.eq_of_val_eq; rw [er, hr1]
            have h2 : (proof.n_final.len != NL) = true := by
              simp only [bne_iff_ne, ne_eq]; intro h; apply hr; rw [← en, h]
            rw [if_neg (by simp [h1]), if_pos h2]
            simp [UnitMatches, toProof, roundsψ, hr, hr1, errMap, hc, hpn]
          · have h1 : (proof.rounds.len != R) = true := by
              simp only [bne_iff_ne, ne_eq]; intro h; apply hr1; rw [← er, h]
            rw [if_pos h1]
            simp [UnitMatches, toProof, roundsψ, hr1, errMap, hc, hpn]
    · have : (p_n.len != gens.g_vec.len) = true := by
        simp only [bne_iff_ne, ne_eq]; intro h; apply hpn; rw [← ep, ← eg, h]
      rw [if_pos this]
      simp [UnitMatches, toGens, hc, hpn, errMap]
  · have : (c.len != gens.h_vec.len) = true := by
      simp only [bne_iff_ne, ne_eq]; intro h; apply hc; rw [← ec, ← eh, h]
    rw [if_pos this]
    simp [UnitMatches, toGens, hc, errMap]

end BpppProofs
