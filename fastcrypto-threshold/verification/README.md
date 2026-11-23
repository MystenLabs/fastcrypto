<!-- THIS FILE IS AI-ONLY -->
# Verification

Lean proofs about the `fastcrypto-threshold` crate, one folder per module, against a Lean
translation of the Rust code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas).
Each folder's `README.md` lists its theorems and what they assume.

| Folder | Module |
|---|---|
| `avss/` | `fastcrypto_threshold::threshold_schnorr::avss` |
| `polynomial/` | `fastcrypto_threshold::polynomial` (Shamir secret sharing) |

A building block whose guarantees only show at the level of a protocol run also has a `Protocol/`
folder. There, the module's functions are black boxes with the properties the protocol needs from
them (`Contracts`), and the theorems are proved from those properties and explicit assumptions
about the network and the callers, so they hold for any implementation that has the properties.
The module's `README.md` lists the protocol theorems first, then the theorems about the code, and
says which of the properties are proved for the code. `STYLE.md` says how the `Protocol/` files
are written.

To check the proofs, install Lean with `elan` and run, here:

```bash
lake exe cache get
lake build
```
