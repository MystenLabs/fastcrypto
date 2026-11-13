import BpppModel.Circuit

/-!
# `range_proof.rs`

`Generators::new` is the input `generators`, a function of `nm`, and `pedersen::G`, `pedersen::H`
are the inputs `G`, `H`. A byte string `dst` is a list of bytes. Serialization is not modelled.
-/

namespace Bppp

variable {F E : Type} [Add F] [Mul F] [Sub F] [Neg F] [Zero F] [One F] [Inv F] [NatCast F] [OfNat F 2] [DecidableEq F] [Add E] [Zero E] [SMul F E] [DecidableEq E]

variable (F E) in
/-- `RangeProof`. -/
structure RangeProof where
  proof : Circuit.CircuitProof F E

namespace RangeProof

open BpppTranscript

/-- `transcript`, with the hash `oracle` of the Merlin transcript. -/
def transcript (oracle : List (Entry F E) → F) (dst : List Nat) (n_bits m : Nat) :
    BpppTranscript F E :=
  let t := BpppTranscript.new oracle "fastcrypto-bppp-range-proof-01"
  { t with log := t.log ++ [.message "dst" dst, .message "n_bits" (u64_le_bytes n_bits),
    .message "m" (u64_le_bytes m)] }

/-- `setup`. -/
def setup (oracle : List (Entry F E) → F) (generators : Nat → Result (Generators E)) (range : Range)
    (m : Nat) (dst : List Nat) : Result (CircuitParams × Generators E × BpppTranscript F E) := do
  let params ← CircuitParams.new range m
  let gens ← generators params.nm
  pure (params, gens, transcript oracle dst range.bits m)

/-- `RangeProof::prove_batch`, with the draws `rng`. -/
def prove_batch (oracle : List (Entry F E) → F) (generators : Nat → Result (Generators E))
    (G H : E) (values : List Nat) (blindings : List F) (range : Range) (dst : List Nat)
    (rng : Circuit.Randomness F) : Result (RangeProof F E) := do
  if values = [] ∨ values.length ≠ blindings.length ∨ values.any (fun v => !range.is_in_range v)
  then throw .InvalidInput
  let (params, gens, transcript) ← setup oracle generators range values.length dst
  match (Circuit.prove G H gens params rng values blindings).run' transcript with
  | .ok (proof, _) => pure ⟨proof⟩
  | .error _ => throw .GeneralOpaqueError

/-- `RangeProof::verify_batch`. -/
def verify_batch (self : RangeProof F E) (oracle : List (Entry F E) → F)
    (generators : Nat → Result (Generators E)) (commitments : List (PedersenCommitment E))
    (range : Range) (dst : List Nat) : Result Unit := do
  if commitments = [] then throw .InvalidInput
  let (params, gens, transcript) ← setup oracle generators range commitments.length dst
  match (Circuit.verify gens params self.proof commitments).run' transcript with
  | .ok () => pure ()
  | .error _ => throw .InvalidProof

/-- `RangeProof::prove`. -/
def prove (oracle : List (Entry F E) → F) (generators : Nat → Result (Generators E))
    (G H : E) (value : Nat) (blinding : F) (range : Range) (dst : List Nat)
    (rng : Circuit.Randomness F) : Result (RangeProof F E) :=
  prove_batch oracle generators G H [value] [blinding] range dst rng

/-- `RangeProof::verify`. -/
def verify (self : RangeProof F E) (oracle : List (Entry F E) → F)
    (generators : Nat → Result (Generators E)) (commitment : PedersenCommitment E)
    (range : Range) (dst : List Nat) : Result Unit :=
  self.verify_batch oracle generators [commitment] range dst

end RangeProof

end Bppp
