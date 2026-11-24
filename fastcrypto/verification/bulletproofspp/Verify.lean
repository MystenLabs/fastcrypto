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
      q.2.1.val.length ≤ c.val.length ⦄ := by
  unfold bulletproofspp.norm_linear.verify_loop0
  have erl : rounds.length = rounds.val.length := rfl
  apply loop.spec_decr_nat (fun q => rounds.length - q.2.2.2.2.2.2.2.val)
    (fun q => q.2.2.2.2.2.2.2.val ≤ rounds.val.length ∧
      q.2.2.2.2.1.val.length = q.2.2.2.2.2.2.2.val ∧
      q.2.2.2.2.2.1.length = 2 ^ q.2.2.2.2.2.2.2.val ∧
      q.2.2.2.2.2.2.1.length = 2 ^ q.2.2.2.2.2.2.2.val ∧
      q.2.1.val.length ≤ c.val.length ∧
      ((roundsψ ψ (rounds.val.drop q.2.2.2.2.2.2.2.val)).foldlM Bppp.NormLinear.verify_round
        (toVSt φ q.2.1 q.2.2.1 q.2.2.2.1 q.2.2.2.2.1 q.2.2.2.2.2.1 q.2.2.2.2.2.2.1)).run (τ q.1) =
      ((roundsψ ψ (rounds.val.drop r.val)).foldlM Bppp.NormLinear.verify_round
        (toVSt φ c rho mu gammas w_h w_g)).run (τ t))
  · rintro ⟨t', c', rho', mu', g', wh', wg', k⟩ ⟨hk, hgl, hwhl, hwgl, hcl, heq⟩
    dsimp only at hk hgl hwhl hwgl hcl heq
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
      refine ⟨by scalar_tac, by simp [gammas1_post]; scalar_tac, by rw [hwh1l, hwhl, r1_post]; ring,
        by rw [hwg1l, hwgl, r1_post]; ring, by omega, ?_, by scalar_tac⟩
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
        by rw [hwgl]; congr 1; omega, hcl⟩
      rw [← heq, List.drop_of_length_le (by simpa using hkv)]
      rfl
  · exact ⟨hr, hg, hwh, hwg, le_refl _, rfl⟩

end BpppProofs
