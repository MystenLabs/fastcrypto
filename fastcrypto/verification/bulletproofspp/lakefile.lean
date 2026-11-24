-- THIS FILE IS AI-ONLY
import Lake
open Lake DSL

-- The Aeneas Lean library, at the commit of the nightly release whose Charon and Aeneas generated
-- `Generated` (see `extract.sh`).
require aeneas from git "https://github.com/AeneasVerif/aeneas" @
  "2e3d4488280bb8a95411db81019a7854a784861f" / "backends" / "lean"

-- For the zero-knowledge theorem. Uses the same Mathlib as Aeneas.
require VCVio from git
  "https://github.com/Verified-zkEVM/VCV-io.git" @ "8781becff83faa559bfd1f1abf376d6e3ecd8f2d"

package «fastcrypto-bulletproofspp» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

/-- `fastcrypto::bulletproofspp`: its translation (`bulletproofspp.Generated`), lemmas about it,
and the theorems (`bulletproofspp.Theorems`). -/
@[default_target]
lean_lib bulletproofspp where
  srcDir := ".."
  roots := #[`bulletproofspp.Theorems]
  -- Not `.andSubmodules `bulletproofspp`: with `srcDir := ".."` that would include `.lake`.
  globs := #[.one `bulletproofspp.Theorems, .submodules `bulletproofspp.Generated,
    .submodules `bulletproofspp.Model, .submodules `bulletproofspp.Spec,
    .submodules `bulletproofspp.Proofs] ++
    #[`Correctness, `Soundness, `ZeroKnowledge, `Scalar, `Util, `Laurent, `Constraints, `Points, `NormLinear, `LazyBases, `Prove, `Verify, `Circuit, `CircuitWitness, `CircuitOpening, `CircuitProve].map
      fun n => .one (`bulletproofspp ++ n)
