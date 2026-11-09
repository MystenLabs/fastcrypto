import Lake
open Lake DSL

/-! The executable model of `ristretto255.rs`. It depends on core Lean only, since `lean-rs` loads
it as a native shared library and everything it imports is compiled with it. -/

package «ristretto_model» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

@[default_target]
lean_lib «RistrettoModel» where
  defaultFacets := #[LeanLib.sharedFacet]
