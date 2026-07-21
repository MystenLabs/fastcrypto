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

`sigs-cli` covers keygen, sign, verify. falcon512 consumes a raw 48-byte seed that deterministically fixes the key pair (same seed, same keys — see `falcon512::sign::keygen_from_seed`; `@noble/post-quantum`'s `falcon512padded.keygen` reproduces the pair for most seeds, including the shipped vectors, but noble keygen equivalence is not universal — see the sign module docs); signatures are salted, so only `sign` output differs per run. `sign` also prints the public key it derives from the sk.

```sh
SEED=010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101
cargo run --bin sigs-cli -- keygen --scheme falcon512 --seed $SEED
cargo run --bin sigs-cli -- sign   --scheme falcon512 --msg 00010203 --secret-key <sk-hex>
cargo run --bin sigs-cli -- verify --scheme falcon512 --msg 00010203 --signature <sig-hex> --public-key <pk-hex>
```

Sizes (hex is 2x): pk 897, sk 1281 (pk derived, not stored), sig 666.
