# Lean model and specs of `polynomial.rs`

| Folder | Contents |
| --- | --- |
| `model/` | `ShamirModel.lean`: `Poly::{degree_bound, c0, eval, add, recover_c0}` over BLS12-381 scalars, in core Lean only, with `@[export]` wrappers. |
| `harness/` | A Rust crate whose property tests call the model through [`lean-rs`](https://github.com/jcreinhold/lean-rs) and compare it with `fastcrypto_threshold::polynomial::Poly`. |
| `specs/` | Theorems about the model, with Mathlib: `recover_c0` is Lagrange interpolation at zero (`Interpolation.lean`), and recovery, privacy and additivity of Shamir sharing. |

## Running the tests

Needs [`elan`](https://github.com/leanprover/elan). `build.rs` builds the model with Lake as a shared
library, so a change to `ShamirModel.lean` is picked up by the next `cargo test`.

```bash
cd harness && cargo test
```

The harness is not a member of the fastcrypto workspace, so the rest of the repository builds without
Lean. Its generic parts (opening a model, `same`, hex encoding, export signatures for `build.rs`)
live in [`fastcrypto-lean-testing`](../../../../fastcrypto-lean-testing), for models of other parts
of fastcrypto.

## How the pieces fit

The property tests check that the Rust code and the model agree on random inputs; the specs prove
theorems about the model. Together they say that the theorems hold for the Rust code on the tested
inputs.

`lean-rs` loads the model as native code, and a native Lean library includes every module it
imports, so the model uses core Lean only. Scalars are `Fin r`, which Mathlib's `ZMod r` is by
definition, so the specs reason about the model directly. They assume that `r` is prime
(`[Fact r.Prime]`).

`rand_fixed_c0` is the one function not in the model: the specs describe its output as
`deal d s c`, for coefficients `c` that it draws uniformly.

Build the specs with `cd specs && lake build`.
