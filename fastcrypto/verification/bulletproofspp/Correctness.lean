-- THIS FILE IS AI-ONLY
import bulletproofspp.Model.RangeProof
import bulletproofspp.Proofs.Circuit

/-!
# Completeness of `range_proof.rs`

`RangeProof::verify_batch` accepts the proof `RangeProof::prove_batch` outputs for the Pedersen
commitments to the values.
-/

open Finset

namespace Bppp

variable {F E : Type} [Field F] [DecidableEq F] [AddCommGroup E] [Module F E] [DecidableEq E]

lemma le_next_power_of_two (n : ℕ) : n ≤ next_power_of_two n :=
  Nat.le_pow_clog (by norm_num) n

namespace RangeProof

/-- `CircuitParams::new` for a nonempty batch. -/
lemma params_new (range : Range) (m : ℕ) (hm : m ≠ 0) :
    ∃ params, CircuitParams.new range m = .ok params ∧ params.Valid ∧ params.range = range ∧
      params.m = m ∧ 16 ^ params.d = 2 ^ range.bits := by
  refine ⟨_, by simp [CircuitParams.new, hm]; rfl, ⟨rfl, ?_, ?_⟩, rfl, rfl, ?_⟩
  · exact (le_max_left _ _).trans (le_next_power_of_two _)
  · exact (le_max_right _ BASE).trans (le_next_power_of_two _)
  · cases range <;> rfl

/-- The Pedersen commitments to `values` under `blindings`. -/
def commitments (G H : E) (values : List ℕ) (blindings : List F) : List (PedersenCommitment E) :=
  (List.zip (to_scalars values : List F) blindings).map fun (v, s) => PedersenCommitment.new G H v s

/-- **Completeness.** For values in `range`, generators for the batch's `nm` of the right shape
whose `G` and `H_0` are the Pedersen bases, and a transcript hash that never outputs `-j` for
`j < 16`, `verify_batch` accepts the proof of `prove_batch` for the Pedersen commitments to the
values. -/
theorem completeness (oracle : List (Entry F E) → F) (generators : ℕ → Result (Generators E))
    (G H : E) (values : List ℕ) (blindings : List F) (range : Range) (dst : List ℕ)
    (rng : Circuit.Randomness F) (gens : Generators E) (params : CircuitParams)
    (hvals : values ≠ []) (hb : blindings.length = values.length)
    (hrange : ∀ v ∈ values, range.is_in_range v)
    (hparams : CircuitParams.new range values.length = .ok params)
    (hgens : generators params.nm = .ok gens) (hh : gens.h_vec.length = H_LEN)
    (hg : gens.g_vec.length = params.nm) (hgH : gens.g = H)
    (hhG : gens.h_vec.getD 0 0 = G) (horacle : ∀ log, ∀ j : ℕ, j < 16 → oracle log + j ≠ 0) :
    ∃ proof, prove_batch oracle generators G H values blindings range dst rng = .ok proof ∧
      proof.verify_batch oracle generators (commitments G H values blindings) range dst = .ok () := by
  have hm : values.length ≠ 0 := by simpa using hvals
  obtain ⟨params', hpn, hv, hpr, hpm, h16⟩ := params_new range values.length hm
  obtain rfl : params = params' := by rw [hparams] at hpn; exact Except.ok.inj hpn
  have hd : ∀ v ∈ values, v < 16 ^ params.d := fun v hv' => by
    have := hrange v hv'
    simp only [Range.is_in_range, decide_eq_true_eq] at this
    rw [h16]; have := Nat.one_le_two_pow (n := range.bits); omega
  obtain ⟨proof, t', hprove, hverify⟩ := Circuit.completeness params hv rng values blindings G H
    gens (transcript oracle dst range.bits values.length) hh hg hgH hhG hpm.symm
    (by rw [hb, hpm]) (by rw [hpr]; exact hrange) hd (fun log j hj => horacle log j hj)
  refine ⟨⟨proof⟩, ?_, ?_⟩
  · have hc : ¬(values = [] ∨ values.length ≠ blindings.length ∨
        values.any (fun v => !range.is_in_range v)) := by
      simp [hvals, hb]; intro v hv'; simpa using hrange v hv'
    have hp : Circuit.prove G H gens params rng values blindings
        (transcript oracle dst range.bits values.length) =
          .ok ((proof, commitments G H values blindings), t') := hprove
    simp only [prove_batch, hc, if_false, setup, hparams, hgens, bind, Except.bind, pure,
      Except.pure, StateT.run', hp]
    rfl
  · have hlen : (commitments G H values blindings : List (PedersenCommitment E)).length =
        values.length := by simp [commitments, length_to_scalars, hb]
    have hc : ¬(commitments G H values blindings : List (PedersenCommitment E)) = [] := by
      intro h0; rw [h0] at hlen; exact hm hlen.symm
    have hv' : Circuit.verify gens params proof (commitments G H values blindings)
        (transcript oracle dst range.bits values.length) = .ok ((), t') := hverify
    simp only [verify_batch, hc, if_false, setup, hlen, hparams, hgens, bind, Except.bind, pure,
      Except.pure, StateT.run', hv']
    rfl

end RangeProof

end Bppp
