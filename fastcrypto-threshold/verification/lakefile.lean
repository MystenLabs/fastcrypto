-- THIS FILE IS AI-ONLY
import Lake
open Lake DSL

-- The Aeneas Lean library, at the commit of the nightly release whose Charon and Aeneas
-- generated the `Generated` folders (see each folder's `extract.sh`).
require aeneas from git "https://github.com/AeneasVerif/aeneas" @
  "1dc8ad31b1b062a77c50e29144a6c7bba955fa09" / "backends" / "lean"

package «fastcrypto-threshold-verification» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

/-- `fastcrypto_threshold::threshold_schnorr::avss`: its translation (`avss.Generated`), lemmas
about it, the protocol-level theorems (`avss.Protocol`), and the theorems for the code
(`avss.Theorems`). -/
@[default_target]
lean_lib avss { globs := #[.submodules `avss] }

/-- `fastcrypto_threshold::polynomial`: the protocol-level theorems about Shamir secret sharing
(`polynomial.Protocol`). -/
@[default_target]
lean_lib polynomial { globs := #[.submodules `polynomial] }
