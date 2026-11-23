-- THIS FILE IS AI-ONLY
import merkle.Generated.Funs

/-!
From a Hoare triple about a generated function to what it returns.
-/

open Aeneas Aeneas.Std Result

namespace MerkleProofs

lemma spec_eq_ok {α : Type _} {m : Result α} {p : α → Prop} (h : m ⦃ x => p x ⦄) :
    ∃ x, m = ok x ∧ p x := by
  cases m with
  | ret a => exact ⟨a, rfl, (WP.spec_ok a).mp h⟩
  | vis e k => exact absurd h (by simp)
  | div => exact absurd h (by simp)

lemma spec_of_eq_ok {α : Type _} {m : Result α} {p : α → Prop} {x : α}
    (h : m ⦃ x => p x ⦄) (hm : m = ok x) : p x := by
  rw [hm] at h; exact (WP.spec_ok x).mp h

end MerkleProofs
