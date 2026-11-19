import Aeneas
import Mathlib.Tactic.CasesM

/-!
Reasoning about a generated function that returned `ok`: every `let x ← e` before the return
also returned `ok`. `ok_inv at h` breaks `h : f .. = ok y` into one hypothesis per step.
-/

open Aeneas Aeneas.Std Result

namespace AvssProofs

theorem vis_ne_ok {α : Type _} {i k} {y : α} : Result.vis i k ≠ ok y := by
  intro h
  have := congrArg Result.match h
  simp at this

theorem div_ne_ok {α : Type _} {y : α} : (Result.div : Result α) ≠ ok y := by
  intro h
  have := congrArg Result.match h
  simp at this

theorem fail_ne_ok {α : Type _} {e} {y : α} : (Result.fail e : Result α) ≠ ok y := by
  intro h
  have := congrArg Result.match h
  simp [Result.fail] at this

/-- If `x >>= f` returns `ok y`, then `x` returned some `ok a` and `f a` returned `ok y`. -/
theorem bind_eq_ok {α β : Type _} {x : Result α} {f : α → Result β} {y : β}
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
theorem from_residual_eq {T E : Type _} (r : core.result.Result Never E) :
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual T
      (core.convert.FromSame E) r = ok (core.result.Result.Err (residualErr r)) := by
  cases r with
  | Ok x => exact nomatch x
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
      core.convert.FromSame, residualErr]

/-- A `?` on `w`: binding `branch w` and matching on it is matching on `w`. -/
theorem bind_branch {T E β : Type _} (w : core.result.Result T E)
    (k : core.ops.control_flow.ControlFlow (core.result.Result Never E) T → Result β) :
    Std.bind (core.result.Result.Insts.CoreOpsTry.branch w) k =
      match w with
      | .Ok v => k (.Continue v)
      | .Err e => k (.Break (.Err e)) := by
  cases w <;> simp [core.result.Result.Insts.CoreOpsTry.branch]

/-- `unwrap` returns `v` only for `Ok v`. -/
theorem unwrap_eq_ok {T E : Type _} {inst : core.fmt.Debug E} {e : core.result.Result T E} {v : T}
    (h : core.result.Result.unwrap inst e = ok v) : e = core.result.Result.Ok v := by
  cases e with
  | Ok x => simp [core.result.Result.unwrap] at h; rw [h]
  | Err _ => simp [core.result.Result.unwrap] at h

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

end AvssProofs
