# fastcrypto fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for inputs that an adversary controls.
This crate is not part of the main workspace because cargo-fuzz needs a nightly toolchain.

| Target | What it fuzzes |
|---|---|
| `bls12381_deserialize` | Decoding of BLS12-381 keys and signatures in both modes, through `from_bytes`, BCS, bincode and JSON |
| `bls12381_verify` | Signature verification the way Sui's `bls12381_*_verify` Move natives do it |
| `bls12381_batch_verify` | Aggregation and `batch_verify` of certificates mixing honest and arbitrary signatures |

Run a target with:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run bls12381_verify -- -max_total_time=60
```

CI runs each target for a short time on every pull request and push to `main`. Longer runs are
done separately.
