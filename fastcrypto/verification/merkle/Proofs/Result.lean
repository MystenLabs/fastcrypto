-- THIS FILE IS AI-ONLY
import merkle.Generated.Funs

/-!
From a Hoare triple about a generated function to what it returns, and the `ok_inv` tactic (as in
the AVSS proofs): `ok_inv at h` breaks `h : f .. = ok y` into one hypothesis per step of `f`.
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

/-- If `x >>= f` returns `ok y`, then `x` returned some `ok a` and `f a` returned `ok y`. -/
lemma bind_eq_ok {α β : Type _} {x : Result α} {f : α → Result β} {y : β}
    (h : (x >>= f) = ok y) : ∃ a, x = ok a ∧ f a = ok y := by
  change Std.bind x f = ok y at h
  cases x with
  | ret a => exact ⟨a, rfl, by simpa using h⟩
  | vis i k => simp at h
  | div => simp at h

/-- The error carried by the residual of a `?`. -/
def residualErr {E : Type _} : core.result.Result Never E → E
  | .Ok x => nomatch x
  | .Err e => e

/-- A `?` that propagated an error returns that error. -/
lemma from_residual_eq {T E : Type _} (r : core.result.Result Never E) :
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual T
      (core.convert.FromSame E) r = ok (core.result.Result.Err (residualErr r)) := by
  cases r with
  | Ok x => exact nomatch x
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      residualErr]

/-- A `?` on `w`: binding `branch w` and matching on it is matching on `w`. -/
lemma bind_branch {T E β : Type _} (w : core.result.Result T E)
    (k : core.ops.control_flow.ControlFlow (core.result.Result Never E) T → Result β) :
    Std.bind (core.result.Result.Insts.CoreOpsTry.branch w) k =
      match w with
      | .Ok v => k (.Continue v)
      | .Err e => k (.Break (.Err e)) := by
  cases w <;> simp [core.result.Result.Insts.CoreOpsTry.branch]

/-- `ok_inv at h` repeatedly splits `h : (do ..) = ok y` at binds, `match`es and `if`s, and
closes the branches that return a different constructor. -/
macro "ok_inv" " at " h:ident : tactic =>
  `(tactic| repeat' (first
    | (simp only [Std.uncurry_apply_pair, from_residual_eq, bind_ok, bind_branch] at $h:ident)
    | (guard_hyp $h:ident :~ (_ >>= _) = ok _; replace $h:ident := bind_eq_ok $h; obtain ⟨_, _, $h:ident⟩ := $h)
    | (cases_type Prod)
    | (split at $h:ident)
    | (dsimp only at $h:ident)
    | (simp only [Result.ok_injective.eq_iff, core.result.Result.Ok.injEq, Prod.mk.injEq,
        Option.some.injEq, reduceCtorEq, false_and, and_false] at $h:ident)
    ))

end MerkleProofs
