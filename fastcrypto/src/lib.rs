// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

#[cfg(test)]
#[path = "tests/ed25519_tests.rs"]
pub mod ed25519_tests;

#[cfg(test)]
#[path = "tests/secp256k1_tests.rs"]
pub mod secp256k1_tests;

#[cfg(test)]
#[path = "tests/secp256k1_recoverable_tests.rs"]
pub mod secp256k1_recoverable_tests;

#[cfg(test)]
#[path = "tests/secp256r1_tests.rs"]
pub mod secp256r1_tests;

#[cfg(test)]
#[path = "tests/secp256r1_recoverable_tests.rs"]
pub mod secp256r1_recoverable_tests;

#[cfg(test)]
#[path = "tests/bls12381_tests.rs"]
pub mod bls12381_tests;

#[cfg(test)]
#[path = "tests/bulletproofs_tests.rs"]
pub mod bulletproofs_tests;

#[cfg(test)]
#[path = "tests/aes_tests.rs"]
pub mod aes_tests;

#[cfg(test)]
#[path = "tests/hash_tests.rs"]
pub mod hash_tests;

#[cfg(test)]
#[path = "tests/hmac_tests.rs"]
pub mod hmac_tests;

#[cfg(test)]
#[path = "tests/encoding_tests.rs"]
pub mod encoding_tests;

#[cfg(feature = "experimental")]
#[cfg(test)]
#[path = "tests/mskr_tests.rs"]
pub mod mskr_tests;

#[cfg(test)]
#[path = "tests/ristretto255_tests.rs"]
pub mod ristretto255_tests;

#[cfg(test)]
#[path = "tests/bls12381_group_tests.rs"]
pub mod bls12381_group_tests;

#[cfg(test)]
#[path = "tests/vrf_tests.rs"]
pub mod vrf_tests;

#[cfg(test)]
#[path = "tests/signature_service_tests.rs"]
pub mod signature_service_tests;

#[cfg(test)]
#[path = "tests/test_helpers.rs"]
pub mod test_helpers;

#[cfg(test)]
#[path = "tests/utils_tests.rs"]
pub mod utils_tests;

#[cfg(test)]
#[path = "tests/secp256r1_group_tests.rs"]
pub mod secp256r1_group_tests;

pub mod traits;

#[cfg(any(test, feature = "experimental"))]
pub mod aes;
pub mod bls12381;
#[cfg(any(test, feature = "experimental"))]
pub mod bulletproofs;
pub mod ed25519;
pub mod encoding;
pub mod error;
pub mod groups;
pub mod hash;
pub mod hmac;
pub mod private_seed;
pub mod rsa;
pub mod secp256k1;
pub mod secp256r1;
pub mod serde_helpers;
pub mod signature_service;
pub mod utils;
pub mod vrf;

/// This module contains unsecure cryptographic primitives. The purpose of this library is to allow seamless
/// benchmarking of systems without taking into account the cost of cryptographic primitives - and hence
/// providing a theoretical maximal throughput that a system could achieve if the cost of crypto is optimized
/// away.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
#[cfg(feature = "unsecure_schemes")]
pub mod unsecure;
