-- THIS FILE IS AI-ONLY
import bulletproofspp.Proofs.Correctness
import bulletproofspp.Proofs.Soundness
import bulletproofspp.Proofs.ZeroKnowledge
import bulletproofspp.Proofs.Model.Hygiene
import bulletproofspp.Proofs.RangeProof

/-!
Lemmas for the theorems about the Rust code in `Theorems.lean`: the generators for a batch, and
the Rust prover as a function of the draws of its random number generator.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

/-- `RangeProof::prove_batch` outputs the proof of the model's `RangeProof.prove_batch` for the
draws `rngD` of its random number generator, or fails exactly when it does. -/
lemma prove_batch_refines_spec {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (values : Slice U64) (blindings : Slice pedersen.Blinding)
    (range : pedersen.Range) (dst : Slice U8) (rng : R) (params : Bppp.CircuitParams)
    (hparams : Bppp.CircuitParams.new (toRange range) values.val.length = .ok params)
    (hsize : 256 * values.length + 256 ≤ Usize.max) :
    bulletproofspp.range_proof.RangeProof.prove_batch inst values blindings range dst rng ⦃ r =>
      match Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
          (blindings.val.map φ) (toRange range) (dst.val.map (·.val))
          (rngD φ hm.rand inst rng params.nm) with
      | .ok rp => ∃ rp', r.1 = .Ok rp' ∧ toRP φ ψ rp' = rp
      | .error _ => ∃ e, r.1 = .Err e ⦄ := by
  apply WP.spec_mono (prove_batch_spec hm.scalar hm.point hm.transcript hm.transcript_init
    hm.pedersen hm.rand hm.gens inst values blindings range dst rng hsize)
  intro r hr
  exact hr params.nm (fun pm h => by rw [hparams] at h; cases h; rfl)

lemma usize_ofNat_val (x : ℕ) (hx : x ≤ Usize.max) : (⟨BitVec.ofNat _ x⟩ : Usize).val = x := by
  show (BitVec.ofNat _ _).toNat = _
  rw [BitVec.toNat_ofNat]
  apply Nat.mod_eq_of_lt
  have h1 : Usize.max = 2 ^ UScalarTy.Usize.numBits - 1 := by
    cases System.Platform.numBits_eq <;> simp [Usize.max, Usize.numBits, UScalarTy.numBits, *]
  have h2 : 0 < 2 ^ UScalarTy.Usize.numBits := by positivity
  omega

/-- For a batch of `m ≥ 1` values of valid size, the model's `CircuitParams::new` succeeds, and
`Generators::new` returns generators of the right shape for its `nm`. -/
lemma gens_for {G H : E} (hgn : GensNewModel φ ψ G H) (range : pedersen.Range) (m : ℕ)
    (hm0 : m ≠ 0) (hsize : 256 * m + 256 ≤ Usize.max) :
    ∃ params g, Bppp.CircuitParams.new (toRange range) m = .ok params ∧ params.Valid ∧
      params.range = toRange range ∧ params.m = m ∧ 16 ^ params.d = 2 ^ (toRange range).bits ∧
      genM ψ params.nm = .ok (toGens ψ g) ∧ g.h_vec.length = 8 ∧ g.g_vec.length = params.nm ∧
      ψ g.g = H ∧ (g.h_vec.val.map ψ).getD 0 0 = G := by
  obtain ⟨params, hpn, hv, hpr, hpm, h16⟩ := Bppp.RangeProof.params_new (toRange range) m hm0
  have hnm : ∃ k, 4 ≤ k ∧ params.nm = 2 ^ k ∧ params.nm ≤ 32 * m + 32 := by
    have hp := hpn
    simp only [Bppp.CircuitParams.new, hm0, if_false, Except.ok.injEq] at hp
    subst hp
    have hd : (toRange range).bits / Nat.log2 Bppp.BASE ≤ 16 := by
      cases range <;> simp [toRange, Bppp.Range.bits, Bppp.BASE] <;> decide
    have hmx : 16 ≤ max (m * ((toRange range).bits / Nat.log2 Bppp.BASE)) Bppp.BASE :=
      le_max_right _ _
    refine ⟨_, four_le_clog _ hmx, rfl, ?_⟩
    have := pow_clog_le_two_mul (max (m * ((toRange range).bits / Nat.log2 Bppp.BASE)) Bppp.BASE)
      (by simp only [Bppp.BASE] at hmx ⊢; omega)
    simp only [Bppp.next_power_of_two]
    have : m * ((toRange range).bits / Nat.log2 Bppp.BASE) ≤ m * 16 := Nat.mul_le_mul_left _ hd
    simp only [Bppp.BASE] at *
    omega
  obtain ⟨k, hk4, hkk, hnmle⟩ := hnm
  have hnmmax : params.nm ≤ Usize.max := by omega
  have hnv := usize_ofNat_val params.nm hnmmax
  obtain ⟨a, ha⟩ := hgn.ok_pow ⟨BitVec.ofNat _ params.nm⟩ ⟨k, hk4, by rw [hnv, hkk]⟩
  obtain ⟨g, hdg, -, -, hh, hgl, hgH, hhG⟩ := hgn.gens _ _ ha
  rw [hnv] at hgl
  exact ⟨params, g, hpn, hv, hpr, hpm, h16, genM_ok _ _ ⟨a, hnmmax, ha, hdg⟩, hh, hgl, hgH, hhG⟩

section ZK

variable [Fintype F] [SampleableType F]

/-- The value of a computation that succeeds, or `d`. -/
noncomputable def resultOr {α : Type} (m : Result α) (d : α) : α := by
  classical exact if h : ∃ v, m = ok v then h.choose else d

lemma resultOr_ok {α : Type} {m : Result α} {v d : α} (h : m = ok v) : resultOr m d = v := by
  unfold resultOr
  rw [dif_pos ⟨v, h⟩]
  exact Result.ok_injective ((⟨v, h⟩ : ∃ v, m = ok v).choose_spec.symm.trans h)

/-- The model of a result of `RangeProof::prove_batch`, with every failure as
`GeneralOpaqueError`. -/
def toRes (φ : S → F) (ψ : P → E)
    (r : core.result.Result bulletproofspp.range_proof.RangeProof error.FastCryptoError) :
    Bppp.Result (Bppp.RangeProof F E) :=
  match r with
  | .Ok rp => .ok (toRP φ ψ rp)
  | .Err _ => .error .GeneralOpaqueError

/-- The result of `RangeProof::prove_batch` from the state `rng` of the random number generator. -/
noncomputable def rustProve {R : Type} (inst : traits.AllowedRng R) (values : Slice U64)
    (blindings : Slice pedersen.Blinding) (range : pedersen.Range) (dst : Slice U8) (rng : R) :
    core.result.Result bulletproofspp.range_proof.RangeProof error.FastCryptoError :=
  (resultOr (bulletproofspp.range_proof.RangeProof.prove_batch inst values blindings range dst rng)
    (.Err .InvalidInput, rng)).1

/-- With valid inputs, the model's `prove_batch` can only fail with `GeneralOpaqueError`. -/
lemma model_prove_error (oracle : List (Bppp.Entry F E) → F) (G H : E) (values : List ℕ)
    (blindings : List F) (range : Bppp.Range) (dst : List ℕ) (rnd : Bppp.Circuit.Randomness F)
    (params : Bppp.CircuitParams) (gm : Bppp.Generators E) (hvals : values ≠ [])
    (hb : blindings.length = values.length) (hrange : ∀ v ∈ values, range.is_in_range v)
    (hpn : Bppp.CircuitParams.new range values.length = .ok params)
    (hgens : genM ψ params.nm = .ok gm) (e : Bppp.Error)
    (h : Bppp.RangeProof.prove_batch oracle (genM ψ) G H values blindings range dst rnd =
      .error e) : e = .GeneralOpaqueError := by
  have hc : ¬(values = [] ∨ values.length ≠ blindings.length ∨
      values.any (fun v => !range.is_in_range v)) := by
    simp [hvals, hb]; intro v hv'; simpa using hrange v hv'
  simp only [Bppp.RangeProof.prove_batch, hc, if_false, Bppp.RangeProof.setup, hpn, hgens,
    except_ok_bind, pure_bind] at h
  split at h
  · cases h
  · cases h; rfl

lemma rust_prove_eq {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (values : Slice U64) (blindings : Slice pedersen.Blinding)
    (range : pedersen.Range) (dst : Slice U8) (params : Bppp.CircuitParams)
    (gm : Bppp.Generators E) (hvals : values.val ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values.val, (toRange range).is_in_range v.val)
    (hparams : Bppp.CircuitParams.new (toRange range) values.val.length = .ok params)
    (hgens : genM ψ params.nm = .ok gm) (hsize : 256 * values.length + 256 ≤ Usize.max)
    (rng : R) :
    toRes φ ψ (rustProve inst values blindings range dst rng) =
      Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
        (blindings.val.map φ) (toRange range) (dst.val.map (·.val))
        (rngD φ hm.rand inst rng params.nm) := by
  obtain ⟨v, hv, hpost⟩ := spec_eq_ok' (prove_batch_refines_spec hm inst values blindings
    range dst rng params hparams hsize)
  unfold rustProve
  rw [resultOr_ok hv]
  split at hpost
  · rename_i rp hrp
    obtain ⟨rp', h1, h2⟩ := hpost
    rw [hrp, h1, ← h2]; rfl
  · rename_i e he
    obtain ⟨e', h1⟩ := hpost
    rw [he, h1, model_prove_error (ψ := ψ) oracle G H _ _ _ _ _ params gm (by simpa using hvals)
      (by simp only [List.length_map]; exact hb) (by simpa using hrange) (by simpa using hparams)
      hgens e he]
    rfl

/-- The model's masks and blindings from the first `16 + nm` draws: the blindings of `C_O`,
`C_L`, `C_R` are draws `0, ..., 14`, `n_S` the next `nm` and `ℓ_S` the last. -/
def xOf (nm : ℕ) (f : Fin (15 + nm + 1) → F) : ((Fin nm → F) × F) × (Fin 15 → F) :=
  ((fun k => f ⟨15 + k, by omega⟩, f ⟨15 + nm, by omega⟩), fun i => f ⟨i, by omega⟩)

lemma xOf_bijective (nm : ℕ) : Function.Bijective (xOf (F := F) nm) := by
  rw [Fintype.bijective_iff_injective_and_card]
  refine ⟨fun f f' h => ?_, ?_⟩
  · simp only [xOf, Prod.mk.injEq] at h
    obtain ⟨⟨h1, h2⟩, h3⟩ := h
    funext j
    rcases Nat.lt_or_ge j.val 15 with hj | hj
    · have := congrFun h3 ⟨j, hj⟩
      simpa using this
    rcases Nat.lt_or_ge j.val (15 + nm) with hj' | hj'
    · have := congrFun h1 ⟨j - 15, by omega⟩
      have e : (⟨15 + (j.val - 15), by omega⟩ : Fin (15 + nm + 1)) = j := Fin.ext (by simp; omega)
      simpa only [e] using this
    · have e : (⟨15 + nm, by omega⟩ : Fin (15 + nm + 1)) = j := Fin.ext (by simp; omega)
      rw [← e]; exact h2
  · simp only [Fintype.card_fun, Fintype.card_prod, Fintype.card_fin, pow_add, pow_one]
    ring

lemma rngD_eq (hr : RandOK) {R : Type} (inst : traits.AllowedRng R) (rng : R)
    (params : Bppp.CircuitParams) (hv : params.Valid) :
    rngD φ hr inst rng params.nm =
      Bppp.Circuit.rngOf params hv (xOf params.nm (fun i => φ (rdraw hr inst i rng))) := by
  simp only [rngD, Bppp.Circuit.rngOf, xOf, Bppp.Circuit.Randomness.mk.injEq, true_and]
  refine ⟨funext fun k => ?_, trivial⟩
  split_ifs <;> rfl

end ZK

end BpppProofs
