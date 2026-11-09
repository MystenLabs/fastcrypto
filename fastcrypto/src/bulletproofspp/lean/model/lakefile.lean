import Lake
open Lake DSL

/-! The executable model of `fastcrypto::bulletproofspp`. It depends on core Lean only, so that it
can be compiled and called from Rust. -/

package «bppp_model» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

@[default_target]
lean_lib «BpppModel» where
  defaultFacets := #[LeanLib.sharedFacet]
