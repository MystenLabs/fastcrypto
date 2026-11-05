# Lean model and specs of `polynomial.rs`

| Folder | Contents |
| --- | --- |
| `model/` | `ShamirModel.lean`: `Poly::{degree_bound, c0, eval, add, recover_c0}` over BLS12-381 scalars, in core Lean only, with `@[export]` wrappers. |
| `harness/` | A Rust crate whose property tests call the model through [`lean-rs`](https://github.com/jcreinhold/lean-rs) and compare it with `fastcrypto_tbls::polynomial::Poly`. |
| `specs/` | The Shamir specs from `fastcrypto-specs`: the functions as black boxes, the contracts we expect of them, and recovery, privacy and DKG summation from those contracts. Needs Mathlib. |

## Running the tests

Needs [`elan`](https://github.com/leanprover/elan). `build.rs` builds the model with Lake as a shared
library, so a change to `ShamirModel.lean` is picked up by the next `cargo test`.

```bash
cd harness && cargo test
```

The harness is not a member of the fastcrypto workspace, so the rest of the repository builds without
Lean.

## Why the model avoids Mathlib

`lean-rs` loads the model as native code, and a native Lean library includes every module it
imports. Scalars are therefore `Fin r` with core Lean's arithmetic. In Mathlib `ZMod r` is
definitionally `Fin r`, so the specs can state facts about the model without a translation.

## Not yet done

The specs and the model are not connected: nothing proves that the model satisfies `Contracts`.
