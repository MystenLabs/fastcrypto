# Fuzz targets

Coverage-guided fuzz targets for the primitives that parse untrusted bytes on Sui validators.
They check that no input panics, since a panic in a validator is a remote crash (Sui builds with
`panic = "abort"`).

| Target | What it exercises |
|---|---|
| `bls12381_group_ops` | Decoding and arithmetic of BLS12-381 scalars, G1, G2 and GT, multi-scalar multiplication, pairing, hash-to-curve and the uncompressed G1 sum, as used by `sui::bls12381` and `sui::group_ops` |
| `groth16_bls12381` | `prepare_pvk_bytes` and `verify_groth16_in_bytes` over BLS12-381 |
| `groth16_bn254` | `prepare_pvk_bytes` and `verify_groth16_in_bytes` over BN254 |

The property tests next to the code check the results as well: they compare these primitives
with arkworks (`fastcrypto/src/tests/bls12381_group_property_tests.rs`,
`fastcrypto-zkp/src/bls12381/api/property_tests.rs`) and run with the normal test suite.

## Running

This crate is not part of the main workspace, since cargo-fuzz needs a nightly toolchain.

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run -O bls12381_group_ops -- -max_total_time=300
```

CI runs every target for a minute on PRs that touch the fuzzed code, and for 15 minutes nightly
(`.github/workflows/fuzz.yml`).
