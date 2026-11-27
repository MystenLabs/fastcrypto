import bulletproofspp.Generated.Funs
import bulletproofspp.Model.Crs
import bulletproofspp.Model.Transcript
import VCVio.OracleComp.Constructions.SampleableType.Measure
import VCVio.EvalDist.EvalDistEq
import Mathlib.Tactic

/-!
The assumptions that the theorems in `Theorems.lean` take, beyond the model in `Model/`: what
they assume about the code that the translation leaves opaque (scalars, points, the
transcript, Pedersen commitments, the random number generator and `Generators::new`). A reviewer
reads this file, `Theorems.lean` and `Model/`; the files in `Proofs/` are lemmas, which Lean
checks.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

/-! ## Scalars -/

/-- `RistrettoScalar` as a field `F`: its operations return, and `φ` maps them to `F`'s. `==`
is equality in `F`, so `φ` is injective up to what the code can observe. -/
structure ScalarModel (F : Type) [Field F] [DecidableEq F] (φ : groups.ristretto255.RistrettoScalar → F) : Prop where
  zero : ∃ z, groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsGroupElement.zero = ok z ∧
    φ z = 0
  one : ∃ o, groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsGroupElement.generator =
    ok o ∧ φ o = 1
  add : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddRistrettoScalarRistrettoScalar.add
      a b = ok c ∧ φ c = φ a + φ b
  mul : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulRistrettoScalarRistrettoScalar.mul
      a b = ok c ∧ φ c = φ a * φ b
  add_assign : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddAssignRistrettoScalar.add_assign
      a b = ok c ∧ φ c = φ a + φ b
  mul_assign : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithMulAssignRistrettoScalar.mul_assign
      a b = ok c ∧ φ c = φ a * φ b
  add_ref : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithAddShared0RistrettoScalarRistrettoScalar.add
      a b = ok c ∧ φ c = φ a + φ b
  neg : ∀ a, ∃ c, groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithNegRistrettoScalar.neg a =
    ok c ∧ φ c = -φ a
  sub : ∀ a b, ∃ c,
    groups.ristretto255.RistrettoScalar.Insts.CoreOpsArithSubRistrettoScalarRistrettoScalar.sub
      a b = ok c ∧ φ c = φ a - φ b
  eq : ∀ a b, groups.ristretto255.RistrettoScalar.Insts.CoreCmpPartialEqRistrettoScalar.eq a b =
    ok (decide (φ a = φ b))
  clone : ∀ a, groups.ristretto255.RistrettoScalar.Insts.CoreCloneClone.clone a = ok a
  from_u64 : ∀ x : U64, ∃ s, groups.ristretto255.RistrettoScalar.Insts.CoreConvertFrom.from
    curve25519_dalek.scalar.Scalar.Insts.CoreConvertFromU64 x = ok s ∧ φ s = (x.val : F)
  inverse_zero : ∀ a, φ a = 0 →
    groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.inverse a =
      ok (.Err .InvalidInput)
  inverse : ∀ a, φ a ≠ 0 → ∃ b,
    groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.inverse a = ok (.Ok b) ∧
      φ b = (φ a)⁻¹

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

/-! ## Points, generators, the transcript and Pedersen commitments -/

/-- The result of a generated MSM matches the model's: the same point under `ψ`, or the same
`InvalidInput` error. -/
def MsmMatches (ψ : P → E) (r : core.result.Result P error.FastCryptoError) (m : Bppp.Result E) :
    Prop :=
  match m with
  | .ok e => ∃ p, r = .Ok p ∧ ψ p = e
  | .error _ => r = .Err .InvalidInput

/-- `RistrettoPoint` as an `F`-module `E`, through `ψ`: `zero` is `0`, `==` is equality in `E`,
and `multi_scalar_mul` computes `Bppp.multi_scalar_mul`. -/
structure PointModel (φ : S → F) (ψ : P → E) : Prop where
  zero : ∃ z, groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsGroupElement.zero = ok z ∧
    ψ z = 0
  eq : ∀ a b, groups.ristretto255.RistrettoPoint.Insts.CoreCmpPartialEqRistrettoPoint.eq a b =
    ok (decide (ψ a = ψ b))
  msm : ∀ (sc : Slice S) (pts : Slice P), ∃ r,
    groups.ristretto255.RistrettoPoint.Insts.FastcryptoGroupsMultiScalarMul.multi_scalar_mul
      sc pts = ok r ∧ MsmMatches ψ r (Bppp.multi_scalar_mul (sc.val.map φ) (pts.val.map ψ))

/-- The model of generated generators: their points under `ψ`. -/
def toGens (ψ : P → E) (gens : bulletproofspp.crs.Generators) : Bppp.Generators E :=
  ⟨ψ gens.g, gens.h_vec.val.map ψ, gens.g_vec.val.map ψ⟩

/-- The precomputed tables of `gens` are those of `[g, h_vec.., g_vec..]`: the mixed MSM over them
computes `Bppp.mixed_multi_scalar_mul` over these points. `Generators::from_parts` builds them
so. -/
def GensOK (φ : S → F) (ψ : P → E) (gens : bulletproofspp.crs.Generators) : Prop :=
  ∀ (s ds : Slice S) (dp : Slice P), ∃ r,
    groups.ristretto255.RistrettoPrecomputation.Insts.FastcryptoGroupsMixedMultiScalarMulRistrettoPoint.mixed_multi_scalar_mul
      gens.precomp s ds dp = ok r ∧
    MsmMatches ψ r (Bppp.mixed_multi_scalar_mul ((gens.g :: gens.h_vec.val ++ gens.g_vec.val).map ψ)
      (s.val.map φ) (ds.val.map φ) (dp.val.map ψ))

/-- The bytes of a transcript label, as the model's string. -/
def labelStr : bulletproofspp.transcript.Label → String
  | .RangeProof => "fastcrypto-bppp-range-proof-01"
  | .Dst => "dst"
  | .NBits => "n_bits"
  | .M => "m"
  | .Circuit => "bppp_circuit"
  | .V => "V"
  | .CL => "C_L"
  | .CO => "C_O"
  | .CR => "C_R"
  | .CS => "C_S"
  | .Alpha => "alpha"
  | .Rho => "rho"
  | .Lambda => "lambda"
  | .Beta => "beta"
  | .Tau => "tau"
  | .NormLinear => "norm_linear"
  | .X => "X"
  | .R => "R"
  | .Gamma => "gamma"
  | .LFinal => "l_final"
  | .NFinal => "n_final"

/-- The Merlin transcript as the model's, through `τ`: each method of `BpppTranscript` returns
and does to `τ t` what the model's does. -/
structure TranscriptModel (φ : S → F) (ψ : P → E)
    (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E) : Prop where
  domain_sep : ∀ t l, ∃ t', bulletproofspp.transcript.BpppTranscript.domain_sep t l = ok t' ∧
    (Bppp.BpppTranscript.domain_sep (labelStr l)).run (τ t) = .ok ((), τ t')
  append_point : ∀ t l p, ∃ t',
    bulletproofspp.transcript.BpppTranscript.append_point t l p = ok t' ∧
    (Bppp.BpppTranscript.append_point (labelStr l) (ψ p)).run (τ t) = .ok ((), τ t')
  append_scalars : ∀ t l s, ∃ t',
    bulletproofspp.transcript.BpppTranscript.append_scalars t l s = ok t' ∧
    (Bppp.BpppTranscript.append_scalars (labelStr l) (s.val.map φ)).run (τ t) = .ok ((), τ t')
  append_commits : ∀ t l (cs : Slice pedersen.PedersenCommitment), ∃ t',
    bulletproofspp.transcript.BpppTranscript.append_commits t l cs = ok t' ∧
    (Bppp.BpppTranscript.append_commits (labelStr l) (cs.val.map fun c => ⟨ψ c⟩)).run (τ t) =
      .ok ((), τ t')
  challenge_scalar : ∀ t l, ∃ c t',
    bulletproofspp.transcript.BpppTranscript.challenge_scalar t l = ok (c, t') ∧
    (Bppp.BpppTranscript.challenge_scalar (labelStr l)).run (τ t) = .ok (φ c, τ t')

/-- The model of a generated Pedersen commitment. -/
def toPC (ψ : P → E) (c : pedersen.PedersenCommitment) : Bppp.PedersenCommitment E := ⟨ψ c⟩

/-- `PedersenCommitment::new` commits under the bases `G` and `H` (`pedersen::G`, `pedersen::H`
under `ψ`). -/
structure PedersenModel (φ : S → F) (ψ : P → E) (G H : E) : Prop where
  new : ∀ v b, ∃ c, pedersen.PedersenCommitment.new v b = ok c ∧ ψ c = φ v • H + φ b • G

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

/-- `Generators::new` does not panic and succeeds for powers of two at least `16`, and the
generators it returns have the right shape, precomputed MSM tables over themselves (`GensOK`)
and the Pedersen bases `G`, `H`. -/
structure GensNewModel (φ : S → F) (ψ : P → E) (G H : E) : Prop where
  total : ∀ n, ∃ r, bulletproofspp.crs.cached_generators n = ok r
  ok_pow : ∀ n : Usize, (∃ k, 4 ≤ k ∧ n.val = 2 ^ k) → ∃ a,
    bulletproofspp.crs.cached_generators n = ok (.Ok a)
  gens : ∀ n a, bulletproofspp.crs.cached_generators n = ok (.Ok a) → ∃ g,
    alloc.sync.Arc.Insts.CoreOpsDerefDeref.deref alloc.alloc.Global a = ok g ∧ GensOK φ ψ g ∧
    bulletproofspp.crs.compatible_with_pedersen_commitments g = ok true ∧
    g.h_vec.length = 8 ∧ g.g_vec.length = n.val ∧ ψ g.g = H ∧ (g.h_vec.val.map ψ).getD 0 0 = G

/-- The generators `Generators::new` returns for `n`, if it returns some. -/
def GenAt (n : ℕ) (g : bulletproofspp.crs.Generators) : Prop :=
  ∃ a, n ≤ Usize.max ∧
    bulletproofspp.crs.cached_generators ⟨BitVec.ofNat _ n⟩ = ok (.Ok a) ∧
    alloc.sync.Arc.Insts.CoreOpsDerefDeref.deref alloc.alloc.Global a = ok g

/-! ## The random number generator -/

/-- `RistrettoScalar::rand` never fails. -/
def RandOK : Prop := ∀ {R : Type} (inst : traits.AllowedRng R) (rng : R), ∃ s rng',
  groups.ristretto255.RistrettoScalar.Insts.FastcryptoGroupsScalar.rand inst rng = ok (s, rng')

section Stream

variable {R : Type} (hr : RandOK) (inst : traits.AllowedRng R)

/-- The draw of `RistrettoScalar::rand` from the state `rng`, and the next state. -/
noncomputable def rnext (rng : R) : S × R :=
  ((hr inst rng).choose, (hr inst rng).choose_spec.choose)

/-- The state after `k` draws from `rng`. -/
noncomputable def rstate : ℕ → R → R
  | 0, rng => rng
  | k + 1, rng => (rnext hr inst (rstate k rng)).2

/-- Draw `k` (from `0`) from `rng`. -/
noncomputable def rdraw (k : ℕ) (rng : R) : S := (rnext hr inst (rstate hr inst k rng)).1

end Stream

/-! ## All the models together -/

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

section Ideal

variable [Fintype F] [SampleableType F]

/-- **An ideal random number generator.** `D` is a distribution of states of the random number
generator under which, for every `n`, the first `n` draws of `RistrettoScalar::rand`, mapped to
`F` by `φ`, are uniform and independent. -/
def IdealRng (φ : S → F) (hr : RandOK) {R : Type} (inst : traits.AllowedRng R) (D : ProbComp R) :
    Prop :=
  ∀ n, (fun rng => fun i : Fin n => φ (rdraw hr inst i rng)) <$> D =ᵈ
    ($ᵗ (Fin n → F) : ProbComp (Fin n → F))

end Ideal

end BpppProofs
