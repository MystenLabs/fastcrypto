import Lake
open Lake DSL

-- The Aeneas Lean library, at the commit of the nightly release whose Charon and Aeneas
-- generated `Avss/Generated` (see `Avss/extract.sh`).
require aeneas from git "https://github.com/AeneasVerif/aeneas" @
  "1dc8ad31b1b062a77c50e29144a6c7bba955fa09" / "backends" / "lean"

package «fastcrypto-verification» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

/-- `fastcrypto_threshold::threshold_schnorr::avss`: its translation (`Avss.Generated`), lemmas
about it, and the protocol-level theorems (`Avss.Protocol`). -/
@[default_target]
lean_lib «Avss» { globs := #[.submodules `Avss] }

/-- Shamir secret sharing (`fastcrypto_threshold::polynomial`): the protocol-level theorems
(`Shamir.Protocol`). -/
@[default_target]
lean_lib «Shamir» { globs := #[.submodules `Shamir] }
