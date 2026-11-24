-- THIS FILE IS AI-ONLY
import bulletproofspp.CircuitVerify
import bulletproofspp.Model.RangeProof

/-!
The functions of `range_proof.rs` compute the functions of `Model/RangeProof.lean`.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

lemma proof_shape_one_pow (j : ℕ) :
    2 ^ (Bppp.NormLinear.proof_shape 1 (2 ^ j)).1 ≤ 2 ^ j := by
  induction j with
  | zero => rw [Bppp.NormLinear.proof_shape, dif_pos (by decide)]
  | succ j ih =>
    by_cases hb : Bppp.NormLinear.is_base_case 1 (2 ^ (j + 1)) = true
    · rw [Bppp.NormLinear.proof_shape, dif_pos hb]
      simp
    · have : (2 ^ (j + 1) + 1) / 2 = 2 ^ j := by rw [pow_succ]; omega
      have e : (Bppp.NormLinear.proof_shape 1 (2 ^ (j + 1))).1 =
          (Bppp.NormLinear.proof_shape 1 (2 ^ j)).1 + 1 := by
        rw [Bppp.NormLinear.proof_shape, dif_neg hb, show (1 + 1) / 2 = 1 from rfl, this]
      rw [e, pow_succ, pow_succ]
      omega

lemma proof_shape_eight_pow (k : ℕ) (hk : 3 ≤ k) :
    2 ^ (Bppp.NormLinear.proof_shape 8 (2 ^ k)).1 ≤ 2 ^ k := by
  obtain ⟨j, rfl⟩ : ∃ j, k = j + 3 := ⟨k - 3, by omega⟩
  have step : ∀ (a b : ℕ), Bppp.NormLinear.is_base_case a b = false →
      (Bppp.NormLinear.proof_shape a b).1 =
        (Bppp.NormLinear.proof_shape ((a + 1) / 2) ((b + 1) / 2)).1 + 1 := by
    intro a b h
    rw [Bppp.NormLinear.proof_shape, dif_neg (by simp [h])]
  have hhalf : ∀ i, (2 ^ (i + 1) + 1) / 2 = 2 ^ i := fun i => by rw [pow_succ]; omega
  rw [step 8 _ (by rw [Bool.eq_false_iff, ne_eq, Bppp.NormLinear.is_base_case_iff]; omega),
    show (8 + 1) / 2 = 4 from rfl, show j + 3 = (j + 2) + 1 from rfl, hhalf,
    step 4 _ (by rw [Bool.eq_false_iff, ne_eq, Bppp.NormLinear.is_base_case_iff]; omega),
    show (4 + 1) / 2 = 2 from rfl, show j + 2 = (j + 1) + 1 from rfl, hhalf,
    step 2 _ (by rw [Bool.eq_false_iff, ne_eq, Bppp.NormLinear.is_base_case_iff]; omega),
    show (2 + 1) / 2 = 1 from rfl, hhalf]
  have := proof_shape_one_pow j
  rw [pow_add, pow_add] at *
  simp only [pow_succ, pow_zero, one_mul] at *
  omega

lemma pow_clog_le_two_mul (x : ℕ) (hx : 2 ≤ x) : 2 ^ Nat.clog 2 x ≤ 2 * x := by
  have h1 := Nat.pow_pred_clog_lt_self 2 (by omega : 1 < x)
  have h2 := Nat.clog_pos (by norm_num : 1 < 2) (by omega : 1 < x)
  obtain ⟨k, hk⟩ : ∃ k, Nat.clog 2 x = k + 1 := ⟨Nat.clog 2 x - 1, by omega⟩
  rw [hk] at h1 ⊢
  have h1' : 2 ^ k < x := by simpa using h1
  rw [pow_succ]
  omega

lemma four_le_clog (x : ℕ) (hx : 16 ≤ x) : 4 ≤ Nat.clog 2 x := by
  have := Nat.clog_mono_right 2 hx
  rwa [show (16 : ℕ) = 2 ^ 4 from rfl, Nat.clog_pow 2 4 (by norm_num)] at this

lemma params_new_spec (range : pedersen.Range) (m : Usize) (hm : 64 * m.val + 64 ≤ Usize.max) :
    bulletproofspp.circuit.CircuitParams.new range m ⦃ r =>
      match Bppp.CircuitParams.new (toRange range) m.val with
      | .ok pm => ∃ p, r = .Ok p ∧ ParamsOK pm p ∧ pm.range = toRange p.range ∧
          p.range = range ∧ p.d.val ≤ 16 ∧ p.n_d.val ≤ p.nm.val ∧
          (∃ k, 4 ≤ k ∧ p.nm.val = 2 ^ k) ∧ p.nm.val ≤ 32 * m.val + 32
      | .error _ => r = .Err .InvalidInput ⦄ := by
  unfold bulletproofspp.circuit.CircuitParams.new
  by_cases h0 : m = 0#usize
  · have : m.val = 0 := by rw [h0]; rfl
    simp [h0, Bppp.CircuitParams.new, this]
  have hm0 : m.val ≠ 0 := fun h => h0 (UScalar.eq_of_val_eq (by rw [h]; rfl))
  simp only [h0, if_false]
  have hlog : core.num.U64.ilog2 bulletproofspp.crs.BASE = ok 4#u32 := by
    simp [core.num.U64.ilog2, bulletproofspp.crs.BASE]; rfl
  simp only [hlog, bind_ok]
  have hmodel : ∀ r : pedersen.Range, Bppp.CircuitParams.new (toRange r) m.val =
      .ok ⟨toRange r, m.val, (toRange r).bits / 4, m.val * ((toRange r).bits / 4),
        2 ^ Nat.clog 2 (max (m.val * ((toRange r).bits / 4)) 16)⟩ := by
    intro r
    simp [Bppp.CircuitParams.new, hm0, Bppp.next_power_of_two, Bppp.BASE]
  rw [hmodel]
  have hB : (UScalar.cast UScalarTy.Usize bulletproofspp.crs.BASE).val = 16 := by
    simp only [bulletproofspp.crs.BASE, UScalar.cast_val_eq]
    rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
  have hmax : 4294967295 ≤ Usize.max := by
    cases System.Platform.numBits_eq <;> simp [Usize.max, Usize.numBits, *]
  cases range <;> simp only [pedersen.Range.bits, bind_ok, toRange, Bppp.Range.bits] <;> step*
  all_goals
    have hi2 : i2.val = 4 := by rw [i2_post]; simp
    have hi3 : i3.val = 16 := by rw [i3_post]; exact hB
    have hi4 : i4.val = max n_d.val 16 := by
      rw [i4_post, core.cmp.impls.OrdUsize.max_val, hi3]
    rw [hi2] at d_post
    norm_num at d_post
    rw [d_post] at n_d_post
    have hx : 16 ≤ i4.val := by rw [hi4]; exact le_max_right _ _
    have hle := pow_clog_le_two_mul i4.val (by omega)
    have hge := Nat.le_pow_clog (by norm_num : 1 < 2) i4.val
    have hk := four_le_clog i4.val hx
    have hpow : 2 ^ Nat.clog 2 i4.val ≤ Usize.max := by
      rw [hi4] at hle; rw [hi4]; omega
    have hnmv : (UScalar.mk (BitVec.ofNat UScalarTy.Usize.numBits (2 ^ Nat.clog 2 i4.val)) :
        Usize).val = 2 ^ Nat.clog 2 i4.val := by
      show (BitVec.ofNat _ _).toNat = _
      rw [BitVec.toNat_ofNat]
      apply Nat.mod_eq_of_lt
      have h1 : Usize.max = 2 ^ UScalarTy.Usize.numBits - 1 := by
        cases System.Platform.numBits_eq <;> simp [Usize.max, Usize.numBits, UScalarTy.numBits, *]
      have h2 : 0 < 2 ^ UScalarTy.Usize.numBits := by positivity
      omega
    rw [core.num.Usize.next_power_of_two, if_pos hpow, bind_ok, WP.spec_ok]
    refine ⟨_, rfl, ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩, rfl, rfl, ?_, ?_, ⟨_, hk, ?_⟩, ?_⟩ <;>
      simp only [hi4, n_d_post] at hnmv hle hge hk hpow hx <;>
      simp only [hnmv, hi4, n_d_post, d_post, Nat.reduceDiv] <;> omega

end BpppProofs
