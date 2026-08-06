# fastcrypto-pq

Post-quantum signature schemes behind fastcrypto's traits. Today that is ML-DSA-65
(FIPS 204), the scheme Sui is integrating for quantum-safe accounts.

> [!WARNING]
> This crate has not been audited and is not ready for production use.

## How it fits together

```mermaid
flowchart LR
    A["mldsa-native<br/>(verified C)"] --> B["mysten-mldsa-native-rs<br/>(Rust wrapper)"] --> C["fastcrypto-pq<br/>(this crate)"] --> D["Sui"]
```

The wrapper is a separate crate because it needs a C toolchain and does not build for
wasm32; consumers who only want fastcrypto's classical schemes pay neither cost. This
crate adds no cryptography of its own. What it adds is the trait implementations,
serialization, and the key-management contract the rest of Sui relies on.

## The trait layer's contract

- `MLDSA65KeyPair`, `MLDSA65PrivateKey`, `MLDSA65PublicKey`, and `MLDSA65Signature`
  implement the same fastcrypto traits as the classical schemes (`KeyPair`, `Signer`,
  `VerifyingKey`, `ToFromBytes`), so call sites treat ML-DSA-65 like Ed25519 with
  larger byte arrays.
- The private key's serialized form is the 32-byte FIPS 204 seed, so wallets store and
  back up exactly what they do today. Deserializing a key pair re-derives the public
  key from the seed; a mismatched pair cannot be constructed.
- Signing is hedged, the FIPS 204 default: fresh OS randomness for every signature.
  The FIPS 204 context string is frozen to the empty string.
- Serialization is the raw encoding: bincode, BCS, and `as_ref()` produce identical
  bytes, and the human-readable serde form is base64.
- Sizes: public key 1,952 B, signature 3,309 B, private key 32 B.

## Testing

Beyond trait mechanics, CI pins the wire format itself: interop vectors produced by
`@noble/post-quantum`, an independent TypeScript implementation of FIPS 204, must
reproduce byte for byte through this crate and the wrapper, and its signatures must
verify here. The scheme's own known-answer tests live in the wrapper repository.

## Benchmarks

```bash
cargo bench -p fastcrypto-pq --features native
```

Measured through this crate on an Apple M2 Max, medians:

|                | Ed25519 | ML-DSA-65 (`native`) | ML-DSA-65 (portable C) |
| -------------- | ------- | -------------------- | ---------------------- |
| Sign           | 13 µs   | 66 µs                | 189 µs                 |
| Verify         | 28 µs   | 24 µs                | 57 µs                  |
| Key generation | 11 µs   | 53 µs                | 136 µs                 |

Verification, the cost validators pay per transaction, is at parity with Ed25519. The
`native` feature forwards to the wrapper's formally verified NEON (aarch64) and AVX2
(x86_64) backends behind a runtime CPU probe; outputs are byte-identical across
backends, which the tests check.
