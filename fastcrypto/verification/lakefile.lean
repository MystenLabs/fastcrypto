-- THIS FILE IS AI-ONLY
import Lake
open Lake DSL

-- The Aeneas Lean library, at the commit of the nightly release whose Charon and Aeneas
-- generated the `Generated` folders (see each folder's `extract.sh`).
require aeneas from git "https://github.com/AeneasVerif/aeneas" @
  "2e3d4488280bb8a95411db81019a7854a784861f" / "backends" / "lean"

package «fastcrypto-verification» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

/-- `fastcrypto::merkle`: its translation (`merkle.Generated`), lemmas about it, and the theorems
(`merkle.Spec`). -/
@[default_target]
lean_lib merkle { globs := #[.submodules `merkle] }
