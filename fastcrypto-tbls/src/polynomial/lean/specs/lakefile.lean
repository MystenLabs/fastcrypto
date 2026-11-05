import Lake
open Lake DSL

/-! The Shamir specs: the functions of `polynomial.rs` as black boxes, what we expect of them, and
what follows. Built with Mathlib; never compiled to native code. -/

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.35.0"

package «shamir_specs» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

@[default_target] lean_lib «Shamir» {}
