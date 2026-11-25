-- THIS FILE IS AI-ONLY
import bulletproofspp.Scalar
import bulletproofspp.Model.Crs
import bulletproofspp.Model.Transcript

/-!
What the proofs assume about `RistrettoPoint`, the precomputed MSM tables of `Generators`, and
the Merlin transcript, whose functions are opaque in the translation.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

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

end BpppProofs
