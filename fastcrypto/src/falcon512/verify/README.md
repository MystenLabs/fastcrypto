# Falcon-512

Pure-Rust verifier (this folder), ported from PQClean. Signing/keygen live in
`../sign` behind the `falcon-sign` feature (PQClean C).

## Test

```sh
# verifier only (default, no C)
cargo test -p fastcrypto --lib falcon512

# with signing/keygen
cargo test -p fastcrypto --features falcon-sign --lib falcon512
```

## CLI

`sigs-cli` covers keygen, sign, verify. The seed must be 32 bytes but is ignored for falcon512 (keys are randomized), and signatures are salted, so each run differs. `sign` also prints the public key it derives from the sk.

```sh
SEED=0101010101010101010101010101010101010101010101010101010101010101
cargo run --bin sigs-cli -- keygen --scheme falcon512 --seed $SEED
cargo run --bin sigs-cli -- sign   --scheme falcon512 --msg 00010203 --secret-key <sk-hex>
cargo run --bin sigs-cli -- verify --scheme falcon512 --msg 00010203 --signature <sig-hex> --public-key <pk-hex>
```

Sizes (hex is 2x): pk 897, sk 1281 (pk derived, not stored), sig 666.
