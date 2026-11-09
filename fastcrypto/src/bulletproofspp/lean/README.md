# Lean model of `bulletproofspp`

| Folder | Contents |
| --- | --- |
| `model/` | `BpppModel`: the BP++ modules in Lean, one file per Rust file, generic over the scalar and point operations. Core Lean only. |
| `bindings/` | `BpppHarness.lean`: the model at the [ristretto255 model](../../groups/lean/model), and the exports the tests call. |
| `harness/` | A Rust crate whose tests compare `RangeProof` with the model through [`lean-rs`](https://github.com/jcreinhold/lean-rs). |

The tests check that the provers give byte-identical proofs from the same randomness, and that the
verifiers accept and reject the same proofs. Merlin is not modelled: the tests replay it and pass the
model the entries and challenges, and the model checks its own transcript against those entries.

Needs [`elan`](https://github.com/leanprover/elan). Run with:

```bash
cd harness && cargo test --release
```
