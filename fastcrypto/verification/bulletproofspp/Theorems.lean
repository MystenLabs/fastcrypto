-- THIS FILE IS AI-ONLY
import bulletproofspp.Correctness
import bulletproofspp.Soundness
import bulletproofspp.ZeroKnowledge
import bulletproofspp.Proofs.Hygiene
import bulletproofspp.RangeProof

/-!
# Theorems about the Rust code

The theorems about the model (`RangeProof.completeness`, `RangeProof.verify_extract`,
`RangeProof.zero_knowledge`, `RangeProof.verify_batch_local`, `RangeProof.challenge_decodes`,
`RangeProof.challengeLogs_nodup`) are in `Correctness.lean`, `Soundness.lean`,
`ZeroKnowledge.lean` and `Proofs/Hygiene.lean`. The theorems below link them to the Lean
translation of the Rust code in `Generated/`: the translated prover outputs the model's proof for
some draws of its random number generator, the translated verifier accepts exactly when the
model's does, and so honest proofs of the translated prover are accepted by the translated
verifier.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

/-- The models of scalars, points, the transcript and the generators that the theorems assume:
see `Scalar.lean`, `Points.lean`, `Circuit.lean` and `RangeProof.lean`. -/
structure Models (φ : S → F) (ψ : P → E)
    (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (oracle : List (Bppp.Entry F E) → F) (G H : E) : Prop where
  scalar : ScalarModel F φ
  point : PointModel φ ψ
  transcript : TranscriptModel φ ψ τ
  transcript_init : TranscriptInit τ oracle
  pedersen : PedersenModel φ ψ G H
  rand : RandOK
  gens : GensNewModel φ ψ G H

/-- `RangeProof::prove_batch` outputs the proof of the model's `RangeProof.prove_batch`, for some
draws of the random number generator, or fails exactly when it does. -/
theorem RangeProof.prove_batch_refines {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (values : Slice U64) (blindings : Slice pedersen.Blinding)
    (range : pedersen.Range) (dst : Slice U8) (rng : R)
    (hsize : 256 * values.length + 256 ≤ Usize.max) :
    bulletproofspp.range_proof.RangeProof.prove_batch inst values blindings range dst rng ⦃ r =>
      ∃ rnd : Bppp.Circuit.Randomness F,
        match Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
            (blindings.val.map φ) (toRange range) (dst.val.map (·.val)) rnd with
        | .ok rp => ∃ rp', r.1 = .Ok rp' ∧ toRP φ ψ rp' = rp
        | .error _ => ∃ e, r.1 = .Err e ⦄ :=
  prove_batch_spec hm.scalar hm.point hm.transcript hm.transcript_init hm.pedersen hm.rand hm.gens
    inst values blindings range dst rng hsize

/-- `RangeProof::verify_batch` accepts exactly when the model's `RangeProof.verify_batch` does. -/
theorem RangeProof.verify_batch_refines
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H)
    (rp : bulletproofspp.range_proof.RangeProof) (commitments : Slice pedersen.PedersenCommitment)
    (range : pedersen.Range) (dst : Slice U8)
    (hsize : 256 * commitments.length + 256 ≤ Usize.max) :
    bulletproofspp.range_proof.RangeProof.verify_batch rp commitments range dst ⦃ r =>
      r = .Ok () ↔ (toRP φ ψ rp).verify_batch oracle (genM ψ) (commitments.val.map (toPC ψ))
          (toRange range) (dst.val.map (·.val)) = .ok () ⦄ := by
  apply WP.spec_mono (verify_batch_spec hm.scalar hm.point hm.transcript hm.transcript_init
    hm.gens rp commitments range dst hsize)
  intro r hr
  split at hr
  · rename_i h; exact ⟨fun _ => h, fun _ => hr⟩
  · rename_i e h
    obtain ⟨e', rfl⟩ := hr
    simp [h]

lemma usize_ofNat_val (x : ℕ) (hx : x ≤ Usize.max) : (⟨BitVec.ofNat _ x⟩ : Usize).val = x := by
  show (BitVec.ofNat _ _).toNat = _
  rw [BitVec.toNat_ofNat]
  apply Nat.mod_eq_of_lt
  have h1 : Usize.max = 2 ^ UScalarTy.Usize.numBits - 1 := by
    cases System.Platform.numBits_eq <;> simp [Usize.max, Usize.numBits, UScalarTy.numBits, *]
  have h2 : 0 < 2 ^ UScalarTy.Usize.numBits := by positivity
  omega

/-- **Completeness of the Rust code.** For values in `range` and blindings of the same length,
`RangeProof::prove_batch` returns a proof, for every state of the random number generator, and
`RangeProof::verify_batch` accepts it for the Pedersen commitments to the values. This needs a
transcript hash that never outputs `-j` for `j < 16`. -/
theorem RangeProof.completeness_rust
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (values : Slice U64) (blindings : Slice pedersen.Blinding)
    (range : pedersen.Range) (dst : Slice U8) (rng : R)
    (commitments : Slice pedersen.PedersenCommitment)
    (hvals : values.val ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values.val, (toRange range).is_in_range v.val)
    (hcs : commitments.val.map (toPC ψ) =
      Bppp.RangeProof.commitments G H (values.val.map (·.val)) (blindings.val.map φ))
    (hsize : 256 * values.length + 256 ≤ Usize.max)
    (horacle : ∀ log, ∀ j : ℕ, j < 16 → oracle log + j ≠ 0) :
    bulletproofspp.range_proof.RangeProof.prove_batch inst values blindings range dst rng ⦃ r =>
      ∃ rp, r.1 = .Ok rp ∧
        bulletproofspp.range_proof.RangeProof.verify_batch rp commitments range dst ⦃ v =>
          v = .Ok () ⦄ ⦄ := by
  have evl : values.length = values.val.length := rfl
  have ebl : blindings.length = blindings.val.length := rfl
  have hm0 : (values.val.map (·.val)).length ≠ 0 := by simpa using hvals
  obtain ⟨params, hpn, -, hpr, hpm, -⟩ := Bppp.RangeProof.params_new (toRange range) _ hm0
  -- the generators for `params.nm`
  have hnm : ∃ k, 4 ≤ k ∧ params.nm = 2 ^ k ∧ params.nm ≤ 32 * values.length + 32 := by
    have hp := hpn
    simp only [Bppp.CircuitParams.new, hm0, if_false, Except.ok.injEq] at hp
    subst hp
    have hd : (toRange range).bits / Nat.log2 Bppp.BASE ≤ 16 := by
      cases range <;> simp [toRange, Bppp.Range.bits, Bppp.BASE] <;> decide
    have hmx : 16 ≤ max ((values.val.map (·.val)).length * ((toRange range).bits /
        Nat.log2 Bppp.BASE)) Bppp.BASE := le_max_right _ _
    refine ⟨_, four_le_clog _ hmx, rfl, ?_⟩
    have := pow_clog_le_two_mul (max ((values.val.map (·.val)).length *
      ((toRange range).bits / Nat.log2 Bppp.BASE)) Bppp.BASE) (by simp only [Bppp.BASE] at hmx ⊢; omega)
    simp only [Bppp.next_power_of_two]
    simp only [List.length_map] at this hmx ⊢
    rw [evl]
    have : values.val.length * ((toRange range).bits / Nat.log2 Bppp.BASE) ≤
        values.val.length * 16 := Nat.mul_le_mul_left _ hd
    simp only [Bppp.BASE] at *
    omega
  obtain ⟨k, hk4, hkk, hnmle⟩ := hnm
  have hnmmax : params.nm ≤ Usize.max := by omega
  have hnv := usize_ofNat_val params.nm hnmmax
  obtain ⟨a, ha⟩ := hm.gens.ok_pow ⟨BitVec.ofNat _ params.nm⟩ ⟨k, hk4, by rw [hnv, hkk]⟩
  obtain ⟨g, hdg, -, -, hh, hgl, hgH, hhG⟩ := hm.gens.gens _ _ ha
  have hgen : GenAt params.nm g := ⟨a, hnmmax, ha, hdg⟩
  have hgens := genM_ok (ψ := ψ) _ _ hgen
  rw [hnv] at hgl
  -- the model's completeness, for the draws of the translated prover
  apply WP.spec_mono (RangeProof.prove_batch_refines hm inst values blindings range dst rng hsize)
  rintro r ⟨rnd, hr⟩
  obtain ⟨proof, hprove, hverify⟩ := Bppp.RangeProof.completeness oracle (genM ψ) G H
    (values.val.map (·.val)) (blindings.val.map φ) (toRange range) (dst.val.map (·.val)) rnd
    (toGens ψ g) params (by simpa using hvals) (by simp only [List.length_map]; exact hb)
    (by simpa using hrange) hpn hgens (by simpa [toGens, Bppp.H_LEN] using hh) (by simpa [toGens] using hgl)
    (by simpa [toGens] using hgH) (by simpa [toGens] using hhG) horacle
  rw [hprove] at hr
  obtain ⟨rp, h1, h2⟩ := hr
  refine ⟨rp, h1, ?_⟩
  have hcl : commitments.length = values.length := by
    have := congrArg List.length hcs
    simp only [List.length_map, Bppp.RangeProof.commitments, List.length_zip, Bppp.to_scalars] at this
    show commitments.val.length = _
    rw [this, evl, ← ebl, hb, evl, min_self]
  apply WP.spec_mono (RangeProof.verify_batch_refines hm rp commitments range dst (by omega))
  intro v hv
  rw [h2, hcs] at hv
  exact hv.mpr hverify

end BpppProofs
