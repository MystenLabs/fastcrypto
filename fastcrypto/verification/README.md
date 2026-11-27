<!-- THIS FILE IS AI-ONLY -->
# Verification

Lean proofs about the `fastcrypto` crate, one folder per module, against a Lean translation of the
Rust code made by [Charon and Aeneas](https://github.com/AeneasVerif/aeneas). Each folder's
`README.md` lists its theorems and what they assume.

| Folder | Module |
|---|---|
| `merkle/` | `fastcrypto::merkle` |
| `bulletproofspp/` | `fastcrypto::bulletproofspp` |

To check the proofs, install Lean with `elan` and run, here:

```bash
lake exe cache get
lake build
```

The first build also compiles the Aeneas library and VCVio, which `bulletproofspp` uses for
zero-knowledge.
