# Verification

Lean proofs about fastcrypto, one folder per module, each in up to two layers:

* **Lemmas about the code**, directly in the module's folder: what its Rust functions return,
  proved against a Lean translation of the Rust code made by
  [Charon and Aeneas](https://github.com/AeneasVerif/aeneas).
* **Protocol-level theorems**, in the module's `Protocol/` folder, for building blocks whose
  guarantees only show at the level of a protocol run. The module's functions appear there as black
  boxes, with the lemmas the protocol needs from them (`Contracts`), and the theorems are proved from
  those lemmas and explicit assumptions about the network and the callers. A `Link*.lean` file
  instantiates the black boxes with the translated code and proves the lemmas for it, so the
  theorems hold for the code.

For most modules the first layer is enough.

| Path | Module | Contents |
|---|---|---|
| `Avss/` | `fastcrypto_threshold::threshold_schnorr::avss` | The translation of `avss.rs` (`Avss/Generated`), lemmas about it, and in `Avss/Protocol` AVSS, DKG and key rotation. See `Avss/README.md`. |
| `Shamir/` | `fastcrypto_threshold::polynomial` | In `Shamir/Protocol`, Shamir secret sharing: recovery, privacy and summing dealings. See `Shamir/README.md`. |
| `STYLE.md` | | How the protocol-level files are written. |

To check the proofs, install Lean with `elan` and run, here:

```bash
lake exe cache get
lake build
```

## Protocol-level files

For each building block:

1. **Black boxes.** The Rust functions appear with their names and inputs/outputs but without
   implementations (`Api`). They are total, pure and deterministic; each `Api` says how errors,
   panics and randomness are idealized.
2. **Lemmas about the code.** What the protocol needs from the functions, stated only by relating
   them to each other (`Contracts`, `DkgContracts`, `RotationContracts`, `Shamir.Contracts`). Each
   folder's `README.md` says, for each of them, whether it is proved for the code.
3. **Model.** Explicit assumptions about the network and the callers, as named structures
   (`Run`, `Certificate`, `Tob`, ...). An assumption that a caller such as Hashi must meet is
   documented as a *caller obligation*: `grep -rni "caller obligation" .` lists them.
4. **Theorems.** Proved from the lemmas and the model only, so they hold for any implementation
   that satisfies the lemmas.
