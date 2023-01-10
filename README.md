# fastcrypto

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build status](https://github.com/MystenLabs/fastcrypto/actions/workflows/rust.yml/badge.svg)](https://github.com/MystenLabs/fastcrypto/actions)
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

<p align="center">
  <img width="300" src="images/fastcrypto_logo_800.png">
</p>

`fastcrypto` is a common cryptography library used in software at Mysten Labs. It is published as an independent crate to encourage reusability across different applications and domains. It is a wrapper library around several carefully selected crates with the following considerations:

- Security: Whether the libraries are vulnerable to known attack vectors or possible misuses.
- Performance: Whether the crate performs cryptographic operations with speed after extensive benchmarking. This is critical for the Sui Network to be performant when signing and verifying large amounts of transactions and certificates.
- Determinism: Whether the signature is non-malleable.
- Popularity: Whether the library is used by other consensus critical systems.

Furthermore, we extend the selected libraries with additional features:
- Robust testing framework: [Wycheproof tests](https://github.com/google/wycheproof) and [prop tests](https://altsysrq.github.io/proptest-book/intro.html) are added when possible to protect against arbitrary inputs and crafted edge cases.
- Zeroization: Sensitive private key materials are cleared from memory securely and proactively when it goes out of scope using [zeroize](https://docs.rs/zeroize/latest/zeroize/) trait.
- Serialization: Effective and standardized serialization are required.

This library will be continuously updated with more schemes and faster implementations based on benchmarking results, RFC updates, new research and auditor inputs.

This crate contains:

- Traits that should be implemented by concrete types representing digital cryptographic materials.
    - [`SigningKey`]: Trait implemented by the private key with associated types of its public key and signature.
    - [`VerifyingKey`]: Trait implemented by the public key with associated types of its private key and signature. It also includes a default implementation of batch verification that fails on empty batch verification.
    - [`Authenticator`]: Trait implemented by the signature with associated types of its public key and private key.
    - [`AggregateAuthenticator`]: Trait implemented by the aggregated signature, which allows adding signatures to the aggregated signature and verifying against the public keys with the corresponding messages.
    - [`KeyPair`]: Trait that represents a public/private keypair, which includes the common get priv/pub key functions and a keypair generation function with seeded randomness.
    - [`ToFromBytes`]: Trait that aims to minimize the number of steps involved in obtaining a serializable key.
    - [`EncodeDecodeBase64`]: Trait that extends `ToFromBytes` for immediate conversion to/from Base64 strings. This is the format in which cryptographic materials are stored.

- Concrete signature schemes of type that implement the recommended traits required for cryptographic agility.
    - Ed25519: Backed by [`ed25519-consensus`](https://github.com/penumbra-zone/ed25519-consensus) crate. Compliant to [ZIP-215](https://zips.z.cash/zip-0215) that defines the signature validity that is lacking from RFC8032 but critical for consensus algorithms. [`ed25519-dalek`](https://github.com/dalek-cryptography/ed25519-dalek) is fully deprecated due to the recently discovered [Chalkias double pub-key api vulnerability](https://github.com/MystenLabs/ed25519-unsafe-libs).
    - Secp256k1: ECDSA signatures over the secp256k1 curve. Backed by [Secp256k1 FFI](https://crates.io/crates/secp256k1/0.23.1) wrapper that binds to C library and provides performance faster than the native Rust implementation [k256](https://crates.io/crates/k256) library by ~30% on verification. Produces a 65-byte recoverable signature of shape [r, s, v] where v can be 0 or 1 representing the recovery Id. Produces deterministic signatures using the pseudo-random deterministic nonce generation according to [RFC6979](https://www.rfc-editor.org/rfc/rfc6979), without the strong requirement to generate randomness for nonce protection. Uses sha256 as the default hash function for sign and verify. An interface for verify_hashed is provided to accept a pre-hashed message and its signature for verification. Supports public key recovery by providing the Secp256k1 signature with the corresponding pre-hashed message.
    - BLS12-381: Backed by [`blst`](https://github.com/supranational/blst) crate written in Assembly and C that optimizes for performance and security. G1 and G2 points are serialized following [ZCash specification](https://github.com/supranational/blst#serialization-format) in compressed format. Provides methods for verifying signatures in the G1 group against public keys in the G2 group. Provides methods for aggregating signatures and fast verifying aggregated signatures, where public keys are assumed to be verified for proof of possession.
    - Secp256r1: ECDSA signatures over the secp256r1 curve. Backed by the [p256](https://crates.io/crates/p256) crate which is a pure rust implementation of the Secp256r1 (aka [NIST P-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) and prime256v1) curve. The functionality from p256 is extended such that our implementation produces a 65 byte recoverable signatures of the form [r, s, v] where v is the recoveryID. Produces deterministic signatures using the pseudo-random deterministic nonce generation according to [RFC6979](https://www.rfc-editor.org/rfc/rfc6979), without the strong requirement to generate randomness for nonce protection. Uses sha256 as the default hash function for sign and verify. Supports public key recovery by providing the Secp256r1 ECDSA signature with the corresponding pre-hashed message.

- Utility functions that serve as the underlying RUST implementation for the Move smart contract api. 
    - HKDF: An HMAC-based key derivation function based on [RFC-5869](https://tools.ietf.org/html/rfc5869), to derive keypairs with a salt and an optional domain for the given keypair. This requires choosing an HMAC function that expands precisely to the byte length of a private key for the chosen KeyPair parameter.
    - Pedersen Commitment: Function to create a Pedersen commitment with a value and a blinding factor. Add or subtract Ristretto points that represent Pedersen commitments.
    - Bulletproofs Range Proof: Function to prove that a committed value is an unsigned integer that is within the range [0, 2^bits). Function to verify that the commitment is a Pedersen commitment of some value with an unsigned bit length, a value is an integer within the range [0, 2^bits)

- A asynchronous signature service is provided for testing and benchmarking.
## Tests
There exist tests for all the three schemes, which can be run by:  
```
$ cargo test
```

## Benchmarks
One can compare all currently implemented schemes for *sign, verify, verify_batch* and
*key-generation* by running:
```
$ cargo bench
```
A [report of the benchmarks](https://mystenlabs.github.io/fastcrypto/benchmarks/criterion/reports/) is generated for each release, allowing easy comparison of the performance of the different cryptographic primitives and schemes available in fastcrypto. As an example, we get these timings for signing messages and verifying the signature for the different schemes in fastcrypto as of revision [7dc17a](https://github.com/MystenLabs/fastcrypto/commit/7dc17afca3f9bfcd2a0a712e8cc6da3ad745eb90):

| Scheme           | Sign      | Verify    |
|------------------|-----------|-----------|
| Ed25519          | 19.545 μs | 54.263 μs |
| BLS12381 min_sig | 162.06 μs | 1145.1 μs |
| BLS12381 min_pk  | 399.43 μs | 1276.9 μs |
| Secp256k1        | 97.126 μs | 44.152 μs |
| Secp256r1        | 171.49 μs | 311.82 μs |


Below is a plot from the report, showing benchmarks for batched signature verification where all signatures are on the same message:
![Batched signature verification with all signatures on same message.](https://mystenlabs.github.io/fastcrypto/benchmarks/criterion/reports/Verify%20batch/lines.svg)

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/fastcrypto
[crate-link]: https://crates.io/crates/fastcrypto
[docs-image]: https://docs.rs/fastcrypto/badge.svg
[docs-link]: https://docs.rs/fastcrypto/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.63+-blue.svg
