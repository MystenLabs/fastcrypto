import BpppModel.Fastcrypto

/-!
# `transcript.rs`

The Merlin transcript is modelled by its log of absorbed entries and the function `oracle` that
derives a challenge from the log, standing in for STROBE. Statements hold for every `oracle`.
-/

namespace Bppp

variable (F E : Type)

/-- An entry absorbed by the transcript. -/
inductive Entry
  | message (label : String) (data : List Nat)
  | point (label : String) (p : E)
  | scalar (label : String) (s : F)
  | challenge (label : String)

/-- `BpppTranscript`. -/
structure BpppTranscript where
  oracle : List (Entry F E) → F
  log : List (Entry F E)

/-- A computation that reads and writes the transcript (`&mut BpppTranscript`) and may fail. -/
abbrev TranscriptM (α : Type) := StateT (BpppTranscript F E) (Except Error) α

variable {F E}

namespace BpppTranscript

/-- `BpppTranscript::new`: Merlin's `Transcript::new` absorbs `label` under `dom-sep`. -/
def new (oracle : List (Entry F E) → F) (label : String) : BpppTranscript F E :=
  ⟨oracle, [.message "dom-sep" (label.toList.map Char.toNat)]⟩

/-- Absorb `e`. -/
def absorb (e : Entry F E) : TranscriptM F E Unit :=
  modify fun t => { t with log := t.log ++ [e] }

/-- `BpppTranscript::domain_sep`. -/
def domain_sep (label : String) : TranscriptM F E Unit :=
  absorb (.message "dom-sep" (label.toList.map Char.toNat))

/-- `BpppTranscript::append_message`. -/
def append_message (label : String) (data : List Nat) : TranscriptM F E Unit :=
  absorb (.message label data)

/-- `BpppTranscript::append_point`. -/
def append_point (label : String) (p : E) : TranscriptM F E Unit := absorb (.point label p)

/-- `BpppTranscript::append_commits`. -/
def append_commits (label : String) (commits : List (PedersenCommitment E)) :
    TranscriptM F E Unit :=
  commits.forM fun c => append_point label c.point

/-- `BpppTranscript::append_scalar`. -/
def append_scalar (label : String) (s : F) : TranscriptM F E Unit := absorb (.scalar label s)

/-- `BpppTranscript::append_scalars`. -/
def append_scalars (label : String) (scalars : List F) : TranscriptM F E Unit :=
  scalars.forM fun s => append_scalar label s

/-- `u64::to_le_bytes`. -/
def u64_le_bytes (value : Nat) : List Nat := (List.range 8).map fun i => value / 256 ^ i % 256

/-- `BpppTranscript::append_u64`. -/
def append_u64 (label : String) (value : Nat) : TranscriptM F E Unit :=
  absorb (.message label (u64_le_bytes value))

/-- `BpppTranscript::challenge_scalar`. -/
def challenge_scalar (label : String) : TranscriptM F E F := do
  absorb (.challenge label)
  let t ← get
  pure (t.oracle t.log)

end BpppTranscript

end Bppp
