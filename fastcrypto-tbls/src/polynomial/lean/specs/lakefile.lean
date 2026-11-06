import Lake
open Lake DSL

/-! Theorems about the model in `../model`: recovery, privacy and additivity of Shamir sharing.
Built with Mathlib; never compiled to native code. -/

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.35.0"

require shamir_model from "../model"

package «shamir_specs» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

@[default_target] lean_lib «Shamir» {}
