import BpppModel
import RistrettoModel

/-!
The model of `fastcrypto::bulletproofspp` instantiated at `RistrettoModel`, and the export the Rust
tests call.

A point is its canonical encoding, so structural equality is equality in the group. The Merlin
transcript is not modelled: the oracle replays the entries and challenges computed in Rust, and
answers `1` as soon as the model's transcript differs from them, which makes verification fail.
-/

namespace BpppHarness

open Bppp
open RistrettoModel (Fe L decode encode)

abbrev F := RistrettoModel.Scalar

instance : Zero F := ⟨Fin.ofNat L 0⟩
instance : One F := ⟨Fin.ofNat L 1⟩
instance : Inv F := ⟨fun x => RistrettoModel.pow x (L - 2)⟩
instance : NatCast F := ⟨Fin.ofNat L⟩

/-- A group element, as the field element `s` of its encoding. -/
structure Enc where
  s : Fe
  deriving DecidableEq

def Enc.point (a : Enc) : RistrettoModel.Point :=
  match decode a.s.val with
  | .ok P => P
  | .error _ => RistrettoModel.zero

def ofPoint (P : RistrettoModel.Point) : Enc := ⟨encode P⟩

instance : Zero Enc := ⟨ofPoint RistrettoModel.zero⟩
instance : Add Enc := ⟨fun a b => ofPoint (RistrettoModel.add a.point b.point)⟩
instance : SMul F Enc := ⟨fun k a => ofPoint (RistrettoModel.smul a.point k)⟩

def bytesHex (bytes : List Nat) : String :=
  String.ofList (bytes.flatMap fun b => [Nat.digitChar (b / 16), Nat.digitChar (b % 16)])

/-- The form in which the Rust tests record a transcript entry. -/
def entryString : Entry F Enc → String
  | .message label data => s!"m|{label}|{bytesHex data}"
  | .point label p => s!"p|{label}|{RistrettoModel.hexOfNat p.s.val}"
  | .scalar label s => s!"s|{label}|{RistrettoModel.scalarToHex s}"
  | .challenge label => s!"c|{label}"

/-- The challenge for `log`, given the entries and challenges of the Merlin transcript. -/
def oracle (expected : List String) (challenges : Array F) (log : List (Entry F Enc)) : F :=
  if (log.map entryString).isPrefixOf expected then
    let k := (log.filter fun | .challenge _ => true | _ => false).length
    challenges.getD (k - 1) 1
  else 1

def rangeOfBits : UInt64 → Except String Range
  | 8 => .ok .Bits8
  | 16 => .ok .Bits16
  | 32 => .ok .Bits32
  | 64 => .ok .Bits64
  | _ => .error "bad range"

def parsePoint (s : String) : Except String Enc :=
  return ofPoint (← RistrettoModel.pointOfHex s)

def parseScalar (s : String) : Except String F := RistrettoModel.scalarOfHex s

/-- `[(a, b), (c, d), ...]` from `[a, b, c, d, ...]`. -/
def pairs {α : Type} : List α → List (α × α)
  | a :: b :: rest => (a, b) :: pairs rest
  | _ => []

/-- `RangeProof::verify_batch`. `input` is `[dst, commitments, [g], h_vec, g_vec, [C_L, C_O, C_R,
C_S], rounds, [l_final], n_final, entries, challenges]`, each a list of hex strings except
`entries`. The result is whether the proof is accepted. -/
@[export bppp_harness_verify_batch]
def exportVerifyBatch (bits : UInt64) (input : Array (Array String)) : Except String Bool := do
  let #[dst, commitments, g, h_vec, g_vec, c, rounds, l_final, n_final, entries, challenges] :=
    input | throw "bad input"
  let range ← rangeOfBits bits
  let dst ← RistrettoModel.bytesOfChars (String.join dst.toList).toList
  let commitments ← commitments.toList.mapM parsePoint
  let g ← parsePoint (g.getD 0 "")
  let h_vec ← h_vec.toList.mapM parsePoint
  let g_vec ← g_vec.toList.mapM parsePoint
  let c ← c.toList.mapM parsePoint
  let rounds ← rounds.toList.mapM parsePoint
  let l_final ← parseScalar (l_final.getD 0 "")
  let n_final ← n_final.toList.mapM parseScalar
  let challenges ← challenges.mapM parseScalar
  let proof : RangeProof F Enc :=
    ⟨⟨c.getD 0 0, c.getD 1 0, c.getD 2 0, c.getD 3 0, ⟨pairs rounds, l_final, n_final⟩⟩⟩
  let generators : Nat → Result (Generators Enc) := fun _ => .ok ⟨g, h_vec, g_vec⟩
  let result := proof.verify_batch (F := F) (oracle entries.toList challenges) generators
    (commitments.map (⟨·⟩)) range dst
  return match result with
    | .ok () => true
    | .error _ => false

/-- `RangeProof::prove_batch`. `input` is `[dst, values, blindings, [g], h_vec, g_vec, [G, H], r_o,
r_l, r_r, n_s, [l_s], entries, challenges]`, the values in decimal and the rest as for
`exportVerifyBatch`. The result is the serialized proof, as the list of its 32-byte elements. -/
@[export bppp_harness_prove_batch]
def exportProveBatch (bits : UInt64) (input : Array (Array String)) :
    Except String (Array String) := do
  let #[dst, values, blindings, g, h_vec, g_vec, pedersen, r_o, r_l, r_r, n_s, l_s, entries,
    challenges] := input | throw "bad input"
  let range ← rangeOfBits bits
  let dst ← RistrettoModel.bytesOfChars (String.join dst.toList).toList
  let values ← values.toList.mapM fun v => (v.toNat?).elim (throw "bad value") pure
  let blindings ← blindings.toList.mapM parseScalar
  let g ← parsePoint (g.getD 0 "")
  let h_vec ← h_vec.toList.mapM parsePoint
  let g_vec ← g_vec.toList.mapM parsePoint
  let G ← parsePoint (pedersen.getD 0 "")
  let H ← parsePoint (pedersen.getD 1 "")
  let draws := fun (a : Array String) => do
    let a ← a.mapM parseScalar
    return fun i => a.getD i (0 : F)
  let rng : Circuit.Randomness F :=
    ⟨← draws r_o, ← draws r_l, ← draws r_r, ← draws n_s, ← parseScalar (l_s.getD 0 "")⟩
  let challenges ← challenges.mapM parseScalar
  let generators : Nat → Result (Generators Enc) := fun _ => .ok ⟨g, h_vec, g_vec⟩
  match RangeProof.prove_batch (oracle entries.toList challenges) generators G H values blindings
      range dst rng with
  | .error _ => throw "prove_batch failed"
  | .ok ⟨proof⟩ =>
    let point (p : Enc) := RistrettoModel.hexOfNat p.s.val
    let nl := proof.nl_proof
    return ([proof.c_l, proof.c_o, proof.c_r, proof.c_s].map point ++
      nl.rounds.flatMap (fun (x, r) => [point x, point r]) ++
      (nl.l_final :: nl.n_final).map RistrettoModel.scalarToHex).toArray

end BpppHarness
