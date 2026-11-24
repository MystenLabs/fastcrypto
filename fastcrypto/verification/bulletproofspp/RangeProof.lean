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

/-- `BpppTranscript::new`, `append_message` and `append_u64` act as the model's, through `τ`, with
`oracle` as the hash of the Merlin transcript. -/
structure TranscriptInit (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (oracle : List (Bppp.Entry F E) → F) : Prop where
  new : ∀ l, ∃ t, bulletproofspp.transcript.BpppTranscript.new l = ok t ∧
    τ t = Bppp.BpppTranscript.new oracle (labelStr l)
  append_message : ∀ t l (m : Slice U8), ∃ t',
    bulletproofspp.transcript.BpppTranscript.append_message t l m = ok t' ∧
    τ t' = { τ t with log := (τ t).log ++ [.message (labelStr l) (m.val.map (·.val))] }
  append_u64 : ∀ t l (v : U64), ∃ t',
    bulletproofspp.transcript.BpppTranscript.append_u64 t l v = ok t' ∧
    τ t' = { τ t with log := (τ t).log ++ [.message (labelStr l) (Bppp.BpppTranscript.u64_le_bytes v.val)] }

/-- `Generators::new` does not panic, and the generators it returns have the right shape,
precomputed MSM tables over themselves (`GensOK`) and the Pedersen bases. -/
structure GensNewModel (φ : S → F) (ψ : P → E) : Prop where
  total : ∀ n, ∃ r, bulletproofspp.crs.cached_generators n = ok r
  gens : ∀ n a, bulletproofspp.crs.cached_generators n = ok (.Ok a) → ∃ g,
    alloc.sync.Arc.Insts.CoreOpsDerefDeref.deref alloc.alloc.Global a = ok g ∧ GensOK φ ψ g ∧
    bulletproofspp.crs.compatible_with_pedersen_commitments g = ok true ∧
    g.h_vec.length = 8 ∧ g.g_vec.length = n.val

/-- The generators `Generators::new` returns for `n`, if it returns some. -/
def GenAt (n : ℕ) (g : bulletproofspp.crs.Generators) : Prop :=
  ∃ a, n ≤ Usize.max ∧
    bulletproofspp.crs.cached_generators ⟨BitVec.ofNat _ n⟩ = ok (.Ok a) ∧
    alloc.sync.Arc.Insts.CoreOpsDerefDeref.deref alloc.alloc.Global a = ok g

/-- The model's `generators`: `Generators::new` under `ψ`. -/
noncomputable def genM (ψ : P → E) (n : ℕ) : Bppp.Result (Bppp.Generators E) := by
  classical
  exact if h : ∃ g, GenAt n g then .ok (toGens ψ h.choose) else .error .InvalidInput

lemma genM_ok (n : ℕ) (g : bulletproofspp.crs.Generators) (h : GenAt n g) :
    genM ψ n = .ok (toGens ψ g) := by
  unfold genM
  rw [dif_pos ⟨g, h⟩]
  generalize hc : (⟨g, h⟩ : ∃ g, GenAt n g).choose = g'
  have hs : GenAt n g' := hc ▸ (⟨g, h⟩ : ∃ g, GenAt n g).choose_spec
  unfold GenAt at hs h
  obtain ⟨a', -, ha', hdg'⟩ := hs
  obtain ⟨a, -, ha, hg⟩ := h
  rw [ha] at ha'
  have haa := Result.ok_injective ha'
  simp only [core.result.Result.Ok.injEq] at haa
  subst haa
  rw [hg] at hdg'
  rw [Result.ok_injective hdg']

lemma genM_err (n : ℕ) (h : ¬ ∃ g, GenAt n g) : genM ψ n = .error .InvalidInput := by
  unfold genM
  rw [dif_neg h]

lemma usize_of_val (x : Usize) : (⟨BitVec.ofNat _ x.val⟩ : Usize) = x := by
  apply UScalar.eq_of_val_eq
  show (BitVec.ofNat _ _).toNat = _
  rw [BitVec.toNat_ofNat]
  exact Nat.mod_eq_of_lt x.hBounds

lemma transcript_spec {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} (hti : TranscriptInit τ oracle) (dst : Slice U8)
    (n_bits m : Usize) :
    bulletproofspp.range_proof.transcript dst n_bits m ⦃ t =>
      τ t = Bppp.RangeProof.transcript oracle (dst.val.map (·.val)) n_bits.val m.val ⦄ := by
  unfold bulletproofspp.range_proof.transcript
  obtain ⟨t0, h0, m0⟩ := hti.new .RangeProof
  obtain ⟨t1, h1, m1⟩ := hti.append_message t0 .Dst dst
  obtain ⟨t2, h2, m2⟩ := hti.append_u64 t1 .NBits (UScalar.cast .U64 n_bits)
  obtain ⟨t3, h3, m3⟩ := hti.append_u64 t2 .M (UScalar.cast .U64 m)
  simp only [h0, h1, h2, h3, bind_ok, lift, WP.spec_ok]
  rw [m3, m2, m1, m0]
  simp [Bppp.RangeProof.transcript, labelStr, Bppp.BpppTranscript.new]

lemma range_bits_val (r : pedersen.Range) :
    ∃ i, pedersen.Range.bits r = ok i ∧ i.val = (toRange r).bits := by
  cases r <;> exact ⟨_, rfl, rfl⟩

/-- The model of the result of a generated `setup`. -/
def SetupOK (φ : S → F) (ψ : P → E) (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (m : Usize) (r : bulletproofspp.circuit.CircuitParams × alloc.sync.Arc bulletproofspp.crs.Generators ×
      bulletproofspp.transcript.BpppTranscript)
    (x : Bppp.CircuitParams × Bppp.Generators E × Bppp.BpppTranscript F E) : Prop :=
  ∃ g, alloc.sync.Arc.Insts.CoreOpsDerefDeref.deref alloc.alloc.Global r.2.1 = ok g ∧
    toGens ψ g = x.2.1 ∧ τ r.2.2 = x.2.2 ∧ ParamsOK x.1 r.1 ∧ x.1.range = toRange r.1.range ∧
    r.1.d.val ≤ 16 ∧ r.1.n_d.val ≤ r.1.nm.val ∧ (∃ k, 4 ≤ k ∧ r.1.nm.val = 2 ^ k) ∧
    r.1.nm.val ≤ 32 * m.val + 32 ∧ GensOK φ ψ g ∧
    bulletproofspp.crs.compatible_with_pedersen_commitments g = ok true ∧
    g.h_vec.length = 8 ∧ g.g_vec.length = r.1.nm.val

lemma setup_spec (hgn : GensNewModel φ ψ)
    {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    {oracle : List (Bppp.Entry F E) → F} (hti : TranscriptInit τ oracle) (range : pedersen.Range)
    (m : Usize) (hm : 64 * m.val + 64 ≤ Usize.max) (dst : Slice U8) :
    bulletproofspp.range_proof.setup range m dst ⦃ r =>
      match Bppp.RangeProof.setup oracle (genM ψ) (toRange range) m.val (dst.val.map (·.val)) with
      | .ok x => ∃ y, r = .Ok y ∧ SetupOK φ ψ τ m y x
      | .error _ => ∃ e, r = .Err e ⦄ := by
  unfold bulletproofspp.range_proof.setup
  apply WP.spec_bind (params_new_spec range m hm)
  intro r hr
  simp only [Bppp.RangeProof.setup]
  split at hr
  rotate_left
  · rename_i e he
    subst hr
    rw [he, except_error_bind]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact ⟨_, rfl⟩
  rename_i pm hpm
  obtain ⟨p, rfl, hpo, hpr, hprange, hd, hnd, hk, hnm⟩ := hr
  rw [hpm, except_ok_bind]
  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_ok]
  unfold bulletproofspp.crs.Generators.new
  obtain ⟨rg, hrg⟩ := hgn.total p.nm
  have hpnm : pm.nm = p.nm.val := hpo.nm
  rw [hrg, bind_ok]
  rcases rg with a | e
  · obtain ⟨g, hdg, hgok, hcomp, hh, hgl⟩ := hgn.gens _ _ hrg
    have hgen : GenAt pm.nm g := ⟨a, by rw [hpnm]; scalar_tac,
      by rw [hpnm, usize_of_val]; exact hrg, hdg⟩
    rw [genM_ok _ _ hgen, except_ok_bind]
    simp only [bind_ok]
    obtain ⟨i, hi, hiv⟩ := range_bits_val range
    rw [hi, bind_ok]
    apply WP.spec_bind (transcript_spec hti dst i m)
    intro t ht
    rw [WP.spec_ok]
    refine ⟨_, rfl, g, hdg, rfl, ?_, hpo, hpr, hd, hnd, hk, hnm, hgok, hcomp, hh, hgl⟩
    show τ t = _
    rw [ht, hiv]
  · have hne : ¬ ∃ g, GenAt pm.nm g := by
      rintro ⟨g, a, -, ha, -⟩
      rw [hpnm, usize_of_val, hrg] at ha
      have := Result.ok_injective ha
      cases this
    rw [genM_err _ hne, except_error_bind]
    simp only [bind_ok,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    exact ⟨_, rfl⟩

end BpppProofs
