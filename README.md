# [fastcrypto]

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build status](https://github.com/MystenLabs/fastcrypto/actions/workflows/rust.yml/badge.svg)](https://github.com/MystenLabs/fastcrypto/actions)
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

fastcrypto` is a common cryptography library used in software at Mysten Labs. It is published independently encouraging reusability across different applications and domains. It is a wrapper library around several carefully selected crates with following considerations: 
- Security: Whether the libraries are vulnerable to known attack vectors or possible misuses. 
- Performance: Whether the crate performs cryptographic operations with speed after extensive benchmarking. This is critical for the Sui Network to be performant when signing and verifying large amounts of transactions and certificates. 
- Determinism: Whether the signature is non-malleable.
- Popularity: Whether the library is used by other consensus critical systems. 

Furthermore, we extend the selected libraries with additional features:
- Robust testing framework: [Wycheproof tests](https://github.com/google/wycheproof) and [prop tests](https://altsysrq.github.io/proptest-book/intro.html) are added when possible to protect against arbitrary inputs and crafted edge cases.
- Zeroization: Sensitive private key materials are cleared from memory securely and proactively when it goes out of scope using [zeroize](https://docs.rs/zeroize/latest/zeroize/) trait.
- Serialization: Effective and standardized serialization are required.

This library will be continuously updated with more schemes and its faster and more secure implementations based on benchmarking results, RFC updates and audit inputs.

This crate contains:

- Traits that should be implemented by concrete types representing digital cryptographic materials. 

    - [`SigningKey`]: Trait implemented by the private key with associated types of its public key and signature. 
    - [`VerifyingKey`]: Trait implemented by the public key with associated types of its private key and signature. It also includes a default implementation of batch verification that fails on empty batch verification.
    - [`Authenticator`]: Trait implemented by the signature with associated types of its public key and private key.
    - [`AggregateAuthenticator`]: Trait implemented by the aggregated signature, which allows adding signatures to the aggregated signature and verifying against the public keys with the corresponding messages.
    - [`KeyPair`]: Trait represents a public/private keypair, which includes the common get priv/pub key functions and a keypair generation function with a seeded randomness.
    - [`ToFromBytes`]: Trait that aims to minimize the number of steps involved in obtaining a serializable key.
[`EncodeDecodeBase64`]: Trait that extends `ToFromBytes` for immediate conversion to/from Base64 strings. This is the format in which cryptographic materials are stored.

- Concrete signature schemes of type that implement the recommended traits required for cryptographic agility. 
    - Ed25519: Backed by [`ed25519-consensus`](https://github.com/penumbra-zone/ed25519-consensus) crate. Compliant to [ZIP-215](https://zips.z.cash/zip-0215) that defines the signature validity that is lacking from RFC8032 but critical for consensus algorithms. [`ed25519-dalek`](https://github.com/dalek-cryptography/ed25519-dalek) is fully deprecated due to the recently discovered [Chalkias double pub-key api vulnerability](https://github.com/MystenLabs/ed25519-unsafe-libs).
    - Secp256k1: Backed by [Secp256k1 FFI](https://crates.io/crates/secp256k1/0.23.1) wrapper that binds to C library and provides performance faster than the native Rust implementation [k256](https://crates.io/crates/k256) library by ~30% on verification. Produces a 65-byte recoverable signature of shape [r, s, v] where v can be 0 or 1 representing the recovery Id. Produces deterministic signatures using the pseudo-random deterministic nonce generation according to [RFC6979](https://www.rfc-editor.org/rfc/rfc6979), without the strong requirement to generate randomness for nonce protection. Uses sha256 as the default hash function for sign and verify. An interface for verify_hashed is provided to accept a pre-hashed message and its signature for verification. Supports public key recovery by providing the Secp256k1 signature with the corresponding pre-hashed message.
    - BLS12-381: Backed by [`blst`](https://github.com/supranational/blst) crate written in Assembly and C that optimizes for performance and security. G1 and G2 points are serialized following [ZCash specification](https://github.com/supranational/blst#serialization-format) in compressed format. Provides methods for verifying signatures in the G1 group against public keys in the G2 group. Provides methods for aggregating signatures and fast verifying aggregated signatures, where public keys are assumed to be verified for proof of possession.

- Utility functions that serves as the underlying RUST implementation for the Move smart contract api. 
    - HKDF: An HMAC-based key derivation function based on [RFC-5869](https://tools.ietf.org/html/rfc5869), to derive keypairs with a salt and an optional domain for the given keypair. This requires choosing an HMAC function that expands precisely to the byte length of a private key for the chosen KeyPair parameter.
    - Pedersen Commitment: Function to create a Pedersen commitment with a value and a blinding factor. Add or subtract Ristretto points that represent Pedersen commitments.
    - Bulletproofs Range Proof: Function to prove that the value is an unsigned integer that is within the range [0, 2^bits). Function to verify that the commitment is a Pedersen commitment of some value with an unsigned bit length, a value is an integer within the range [0, 2^bits)

4. A asynchronous signature service is provided for testing and benchmarking.
## Tests and Benchmarks
There exist tests for all the three schemes, which can be run by:  
```
$ cargo test
```

One can compare all currently implemented schemes for *sign, verify, verify_batch* and 
*key-generation* by running:
```
$ cargo bench
```

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