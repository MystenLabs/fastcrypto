-- THIS FILE IS AI-ONLY
import Lake
open Lake DSL

-- The Aeneas Lean library, at the commit of the nightly release whose Charon and Aeneas
-- generated the `Generated` folders (see each folder's `extract.sh`).
require aeneas from git "https://github.com/AeneasVerif/aeneas" @
  "2e3d4488280bb8a95411db81019a7854a784861f" / "backends" / "lean"

-- For the zero-knowledge theorem of `bulletproofspp`. Uses the same Mathlib as Aeneas.
require VCVio from git
  "https://github.com/Verified-zkEVM/VCV-io.git" @ "8781becff83faa559bfd1f1abf376d6e3ecd8f2d"

package «fastcrypto-verification» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

/-- `fastcrypto::merkle`: its translation (`merkle.Generated`), lemmas about it, and the theorems
(`merkle.Theorems`). -/
@[default_target]
lean_lib merkle { globs := #[.submodules `merkle] }

/-- `fastcrypto::bulletproofspp`: its translation (`bulletproofspp.Generated`), a model of it
(`bulletproofspp.Model`), lemmas, and the theorems (`bulletproofspp.Theorems`). -/
@[default_target]
lean_lib bulletproofspp { globs := #[.submodules `bulletproofspp] }
