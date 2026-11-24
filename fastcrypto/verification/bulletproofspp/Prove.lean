-- THIS FILE IS AI-ONLY
import bulletproofspp.LazyBases

/-!
The generated `norm_linear::prove` computes the model's.
-/

open Aeneas Aeneas.Std Result
open fastcrypto

namespace BpppProofs

set_option linter.unusedSectionVars false

variable {F : Type} [Field F] [DecidableEq F] {φ : groups.ristretto255.RistrettoScalar → F}

local notation "S" => groups.ristretto255.RistrettoScalar
local notation "P" => groups.ristretto255.RistrettoPoint

variable {E : Type} [AddCommGroup E] [Module F E] [DecidableEq E] {ψ : P → E}

/-- The model of generated rounds. -/
def roundsψ (ψ : P → E) (r : List (P × P)) : List (E × E) := r.map fun (a, b) => (ψ a, ψ b)

/-- The model of a generated norm-linear proof. -/
def toProof (φ : S → F) (ψ : P → E) (pr : bulletproofspp.norm_linear.NormLinearProof) :
    Bppp.NormLinearProof F E :=
  ⟨roundsψ ψ pr.rounds.val, φ pr.l_final, pr.n_final.val.map φ⟩

/-- The result of a generated `prove`, with the rounds `pre` already sent, matches the model's
run: the same proof under the models, after `pre`, and the same transcript; or the same error. -/
def ProveMatches (φ : S → F) (ψ : P → E)
    (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E) (pre : List (E × E))
    (r : core.result.Result bulletproofspp.norm_linear.NormLinearProof error.FastCryptoError ×
      bulletproofspp.transcript.BpppTranscript)
    (m : Except Bppp.Error (Bppp.NormLinearProof F E × Bppp.BpppTranscript F E)) : Prop :=
  match m with
  | .ok (pm, T) => ∃ pr, r.1 = .Ok pr ∧ τ r.2 = T ∧
    toProof φ ψ pr = { pm with rounds := pre ++ pm.rounds }
  | .error _ => r.1 = .Err .InvalidInput

lemma round_challenge_spec {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (t : bulletproofspp.transcript.BpppTranscript) (x r : P) :
    bulletproofspp.norm_linear.round_challenge t x r ⦃ q =>
      (do
        Bppp.BpppTranscript.append_point "X" (ψ x)
        Bppp.BpppTranscript.append_point "R" (ψ r)
        Bppp.BpppTranscript.challenge_scalar "gamma").run (τ t) = .ok (φ q.1, τ q.2) ⦄ := by
  unfold bulletproofspp.norm_linear.round_challenge
  obtain ⟨t1, h1, m1⟩ := ht.append_point t .X x
  obtain ⟨t2, h2, m2⟩ := ht.append_point t1 .R r
  obtain ⟨c, t3, h3, m3⟩ := ht.challenge_scalar t2 .Gamma
  rw [h1, bind_ok, h2, bind_ok, h3, WP.spec_ok]
  simp only [labelStr] at m1 m2 m3
  simp [StateT.run_bind, m1, m2, m3]

lemma is_base_case_spec (a b : Usize) (h : a.val + b.val ≤ Usize.max) :
    bulletproofspp.norm_linear.is_base_case a b =
      ok (Bppp.NormLinear.is_base_case a.val b.val) := by
  unfold bulletproofspp.norm_linear.is_base_case Bppp.NormLinear.is_base_case
  by_cases ha : a.val ≤ 1
  · have : a ≤ 1#usize := by scalar_tac
    simp only [this, ite_true]
    have hs := Usize.add_spec (x := a) (y := b) h
    obtain ⟨z, hz, hzv⟩ := spec_eq_ok' hs
    rw [hz, bind_ok]
    simp [ha, bulletproofspp.norm_linear.FOLD_THRESHOLD, Bppp.FOLD_THRESHOLD, hzv]
    exact decide_eq_decide.mpr Iff.rfl
  · have : ¬ a ≤ 1#usize := by scalar_tac
    simp [this, ha]

/-- The model's run of the prove loop from a generated state. -/
noncomputable def proveM (φ : S → F) (ψ : P → E)
    (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (gens : bulletproofspp.crs.Generators) (t : bulletproofspp.transcript.BpppTranscript)
    (bases : bulletproofspp.norm_linear.LazyBases) (c : alloc.vec.Vec S) (rho : S)
    (l n : alloc.vec.Vec S) :
    Except Bppp.Error (Bppp.NormLinearProof F E × Bppp.BpppTranscript F E) :=
  (Bppp.NormLinear.prove_loop (toLB φ ψ gens bases) (c.val.map φ) (φ rho) (l.val.map φ)
    (n.val.map φ)).run (τ t)

/-- The model's run with the rounds `pre` put first. -/
def withPre (pre : List (E × E)) (m : Except Bppp.Error (Bppp.NormLinearProof F E ×
    Bppp.BpppTranscript F E)) : Except Bppp.Error (Bppp.NormLinearProof F E ×
    Bppp.BpppTranscript F E) :=
  m.map fun (pm, T) => ({ pm with rounds := pre ++ pm.rounds }, T)

lemma proveMatches_withPre (τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E)
    (pre : List (E × E)) (r) (m : Except Bppp.Error (Bppp.NormLinearProof F E ×
      Bppp.BpppTranscript F E)) :
    ProveMatches φ ψ τ pre r m ↔ ProveMatches φ ψ τ [] r (withPre pre m) := by
  cases m with
  | error e => simp [ProveMatches, withPre, Except.map]
  | ok v => obtain ⟨pm, T⟩ := v; simp [ProveMatches, withPre, Except.map]

lemma prove_base_spec {τ : bulletproofspp.transcript.BpppTranscript → Bppp.BpppTranscript F E}
    (ht : TranscriptModel φ ψ τ) (gens : bulletproofspp.crs.Generators)
    (t : bulletproofspp.transcript.BpppTranscript) (bases : bulletproofspp.norm_linear.LazyBases)
    (c : alloc.vec.Vec S) (rho : S) (l n : alloc.vec.Vec S)
    (rounds : alloc.vec.Vec (P × P)) (hl : l.val.length = 1)
    (hb : Bppp.NormLinear.is_base_case (l.val.length) (n.val.length) = true)
    (hlen : l.val.length + n.val.length ≤ Usize.max) :
    bulletproofspp.norm_linear.prove_loop.body gens.g gens.h_vec gens.g_vec gens.precomp t bases c
      rho l n rounds ⦃ cf => match cf with
        | .done r => ProveMatches φ ψ τ (roundsψ ψ rounds.val) r
            (proveM φ ψ τ gens t bases c rho l n)
        | .cont _ => False ⦄ := by
  unfold bulletproofspp.norm_linear.prove_loop.body
  have el : l.len.val = l.val.length := rfl
  have en : n.len.val = n.val.length := rfl
  simp only []
  rw [is_base_case_spec l.len n.len (by rw [el, en]; exact hlen), el, en, hb, bind_ok]
  simp only [ite_true]
  obtain ⟨t1, h1, m1⟩ := ht.append_scalars t .LFinal (alloc.vec.Vec.deref l)
  obtain ⟨t2, h2, m2⟩ := ht.append_scalars t1 .NFinal (alloc.vec.Vec.deref n)
  rw [h1, bind_ok, h2, bind_ok]
  step*
  simp only [ProveMatches, proveM]
  rw [Bppp.NormLinear.prove_loop, dif_pos (by simpa using hb)]
  simp only [labelStr, deref_val] at m1 m2
  simp only [StateT.run_bind, m1, except_ok_bind, m2, StateT.run_pure]
  refine ⟨_, rfl, rfl, ?_⟩
  obtain ⟨a, ha⟩ : ∃ a, l.val = [a] := List.length_eq_one_iff.mp hl
  simp [toProof, rs_post, ha]

end BpppProofs
