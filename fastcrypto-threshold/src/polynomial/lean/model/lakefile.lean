import Lake
open Lake DSL

/-! The executable model of `polynomial.rs`. It depends on core Lean only, since `lean-rs` loads it
as a native shared library and everything it imports is compiled with it. -/

package «shamir_model» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

@[default_target]
lean_lib «ShamirModel» where
  defaultFacets := #[LeanLib.sharedFacet]
