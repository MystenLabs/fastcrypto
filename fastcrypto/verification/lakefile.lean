-- THIS FILE IS AI-ONLY
import Lake
open Lake DSL

-- The Aeneas Lean library, at the commit of the nightly release whose Charon and Aeneas
-- generated the `Generated` folders (see each folder's `extract.sh`).
require aeneas from git "https://github.com/AeneasVerif/aeneas" @
  "1dc8ad31b1b062a77c50e29144a6c7bba955fa09" / "backends" / "lean"

package «fastcrypto-verification» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

/-- `fastcrypto::merkle`: its translation (`merkle.Generated`), lemmas about it, and the theorems
(`merkle.Theorems`). -/
@[default_target]
lean_lib merkle { globs := #[.submodules `merkle] }
