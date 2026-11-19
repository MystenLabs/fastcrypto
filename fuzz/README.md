# fastcrypto fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for inputs that an adversary controls.
This crate is not part of the main workspace because cargo-fuzz needs a nightly toolchain.

| Target | What it fuzzes |
|---|---|
| `bls12381_deserialize` | Decoding of BLS12-381 keys and signatures in both modes, through `from_bytes`, BCS, bincode and JSON |
| `bls12381_verify` | Signature verification the way Sui's `bls12381_*_verify` Move natives do it |
| `bls12381_batch_verify` | Aggregation and `batch_verify` of certificates mixing honest and arbitrary signatures |
| `ed25519_deserialize` | Decoding of Ed25519 keys, signatures and aggregate signatures through `from_bytes`, BCS, bincode and JSON |
| `ed25519_verify` | Signature verification the way Sui's `ed25519_verify` Move native does it, against an independent ZIP215 implementation |
| `ed25519_batch_verify` | Every Ed25519 batch verification API against individual verification, on ZIP215 edge cases |
| `bls12381_group_deserialize` | Decoding of BLS12-381 scalars, G1, G2, GT and uncompressed G1 elements from raw and mutated bytes, compared with serde and arkworks |
| `bls12381_group_ops` | Sequences of the BLS12-381 operations of Sui's `group_ops` Move natives and multi-pairing, on elements kept as bytes like `sui::group_ops::Element`, compared with naive computation |
| `secp256k1_deserialize` | Decoding of secp256k1 keys, signatures and recoverable signatures, through `from_bytes`, BCS, bincode, JSON and the `*AsBytes` types, compared with k256 |
| `secp256k1_verify` | Signature verification the way Sui's `secp256k1_verify` Move native does it, compared with k256 |
| `secp256k1_ecrecover` | Public key recovery and decompression the way Sui's `secp256k1_ecrecover` and `decompress_pubkey` Move natives do it, compared with k256 |

Run a target with:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run --no-cfg-fuzzing bls12381_verify -- -max_total_time=60
```

`--no-cfg-fuzzing` is needed for the secp256k1 targets: by default cargo-fuzz sets `cfg(fuzzing)`,
under which rust-secp256k1 replaces its cryptography with insecure mocks. The secp256k1 targets
check this and fail at once if they were built without the flag.

CI runs each target for a short time on every pull request and push to `main`. Longer runs are
done separately.
