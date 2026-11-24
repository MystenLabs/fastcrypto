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

/-- `RangeProof::prove_batch` outputs the proof of the model's `RangeProof.prove_batch` for the
draws `rngD` of its random number generator, or fails exactly when it does. -/
theorem RangeProof.prove_batch_refines {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
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
  obtain ⟨params, g, hpn, -, -, -, -, hgens, hh, hgl, hgH, hhG⟩ :=
    gens_for hm.gens range _ hm0 (by rw [List.length_map, ← evl]; exact hsize)
  apply WP.spec_mono (RangeProof.prove_batch_refines hm inst values blindings range dst rng params
    (by simpa using hpn) hsize)
  intro r hr
  obtain ⟨proof, hprove, hverify⟩ := Bppp.RangeProof.completeness oracle (genM ψ) G H
    (values.val.map (·.val)) (blindings.val.map φ) (toRange range) (dst.val.map (·.val))
    (rngD φ hm.rand inst rng params.nm) (toGens ψ g) params (by simpa using hvals)
    (by simp only [List.length_map]; exact hb) (by simpa using hrange) hpn hgens
    (by simpa [toGens, Bppp.H_LEN] using hh) (by simpa [toGens] using hgl)
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

/-! ## Zero-knowledge -/

section ZK

variable [Fintype F] [SampleableType F]

/-- **An ideal random number generator.** `D` is a distribution of states of the random number
generator under which, for every `n`, the first `n` draws of `RistrettoScalar::rand`, mapped to
`F` by `φ`, are uniform and independent. -/
def IdealRng (φ : S → F) (hr : RandOK) {R : Type} (inst : traits.AllowedRng R) (D : ProbComp R) :
    Prop :=
  ∀ n, (fun rng => fun i : Fin n => φ (rdraw hr inst i rng)) <$> D =ᵈ
    ($ᵗ (Fin n → F) : ProbComp (Fin n → F))

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
  obtain ⟨v, hv, hpost⟩ := spec_eq_ok' (RangeProof.prove_batch_refines hm inst values blindings
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

/-- **The prover's distribution.** With valid inputs and an ideal random number generator,
`RangeProof::prove_batch` has the distribution, under the models, of the model's `prove_batch`
with uniform masks and blindings, for any transcript hash. -/
theorem RangeProof.prove_batch_distribution
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} {G H : E} (hm : Models φ ψ τ oracle G H) {R : Type}
    (inst : traits.AllowedRng R) (D : ProbComp R) (hD : IdealRng φ hm.rand inst D)
    (values : Slice U64) (blindings : Slice pedersen.Blinding) (range : pedersen.Range)
    (dst : Slice U8) (params : Bppp.CircuitParams) (hv : params.Valid)
    (hparams : Bppp.CircuitParams.new (toRange range) values.val.length = .ok params)
    (hvals : values.val ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values.val, (toRange range).is_in_range v.val)
    (hsize : 256 * values.length + 256 ≤ Usize.max) :
    (fun rng => toRes φ ψ (rustProve inst values blindings range dst rng)) <$> D =ᵈ
      (fun x => Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
        (blindings.val.map φ) (toRange range) (dst.val.map (·.val))
        (Bppp.Circuit.rngOf params hv x)) <$>
        ($ᵗ (Bppp.Spec.Masks F (params.toSpec hv) × (Fin 15 → F))) := by
  have evl : values.length = values.val.length := rfl
  have hm0 : (values.val.map (·.val)).length ≠ 0 := by simpa using hvals
  obtain ⟨params', g, hpn, -, -, -, -, hgens, -⟩ :=
    gens_for hm.gens range _ hm0 (by rw [List.length_map, ← evl]; exact hsize)
  rw [List.length_map, hparams] at hpn
  cases hpn
  set model := fun x : Bppp.Spec.Masks F (params.toSpec hv) × (Fin 15 → F) =>
    Bppp.RangeProof.prove_batch oracle (genM ψ) G H (values.val.map (·.val))
      (blindings.val.map φ) (toRange range) (dst.val.map (·.val)) (Bppp.Circuit.rngOf params hv x)
  set xO : (Fin (15 + params.nm + 1) → F) → Bppp.Spec.Masks F (params.toSpec hv) × (Fin 15 → F) :=
    fun f => xOf params.nm f
  have hxO : Function.Bijective xO := xOf_bijective params.nm
  have hfun : (fun rng => toRes φ ψ (rustProve inst values blindings range dst rng)) =
      (model ∘ xO) ∘ (fun rng => fun i : Fin (15 + params.nm + 1) =>
        φ (rdraw hm.rand inst i rng)) := by
    funext rng
    rw [rust_prove_eq hm inst values blindings range dst params _ hvals hb hrange hparams hgens
      hsize rng, rngD_eq]
    rfl
  rw [hfun, LawfulFunctor.comp_map]
  refine ((hD _).map _).trans ?_
  rw [LawfulFunctor.comp_map]
  exact (SampleableType.map_uniformSample_evalDistEq_of_bijective hxO).map _

/-- **Zero-knowledge of the Rust prover**, per challenge. If the transcript hash returns the
challenges `c` of an honest verifier, then with valid inputs and an ideal random number generator
the output of `RangeProof::prove_batch`, under the models, has the distribution of the response
at `c` of `protocol`, the model's protocol whose transcripts `RangeProof.zero_knowledge`
simulates. -/
theorem RangeProof.zero_knowledge_rust
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E} {G H : E}
    (params : Bppp.CircuitParams) (hv : params.Valid)
    (c : Bppp.RangeProof.Chal F (Bppp.RangeProof.rounds params))
    (hm : Models φ ψ τ (fun l => Bppp.RangeProof.chalOracle c (Bppp.BpppTranscript.chalLabels l))
      G H) {R : Type}
    (inst : traits.AllowedRng R) (D : ProbComp R) (hD : IdealRng φ hm.rand inst D)
    (values : Slice U64) (blindings : Slice pedersen.Blinding) (range : pedersen.Range)
    (dst : Slice U8) (V : List (Bppp.PedersenCommitment E))
    (hparams : Bppp.CircuitParams.new (toRange range) values.val.length = .ok params)
    (hvals : values.val ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values.val, (toRange range).is_in_range v.val)
    (hsize : 256 * values.length + 256 ≤ Usize.max) :
    (fun rng => toRes φ ψ (rustProve inst values blindings range dst rng)) <$> D =ᵈ
      (Bppp.RangeProof.protocol (genM ψ) G H (toRange range) (dst.val.map (·.val)) params hv
        values.val.length).respond V (values.val.map (·.val), blindings.val.map φ) () c :=
  RangeProof.prove_batch_distribution hm inst D hD values blindings range dst params hv hparams
    hvals hb hrange hsize

end ZK

end BpppProofs
