import Lake
open Lake DSL

/-! The BP++ model at ristretto255, with the exports the Rust tests call. Core Lean only, since
`lean-rs` loads it as a native shared library. -/

require ristretto_model from "../../../groups/lean/model"
require bppp_model from "../model"

package «bppp_harness» where
  leanOptions := #[⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

@[default_target]
lean_lib «BpppHarness» where
  defaultFacets := #[LeanLib.sharedFacet]
