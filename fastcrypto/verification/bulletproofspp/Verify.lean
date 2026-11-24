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
