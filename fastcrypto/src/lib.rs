// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#![warn(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    rust_2021_compatibility
)]

use hash::Digest;
use rand::thread_rng;

pub use signature::Signature as _;

#[cfg(test)]
#[path = "tests/signature_tests.rs"]
pub mod signature_tests;

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

// Signing traits
pub mod traits;
// Key scheme implementations
pub mod aes;
pub mod bls12381;
pub mod bulletproofs;
pub mod ed25519;
pub mod groups;
pub mod hash;
pub mod hmac;
pub mod secp256k1;
pub mod secp256r1;

// Other tooling
pub mod encoding;
pub mod error;
pub mod private_seed;
pub mod serde_helpers;
pub mod signature_service;
pub mod vrf;

/// This module contains unsecure cryptographic primitives. The purpose of this library is to allow seamless
/// benchmarking of systems without taking into account the cost of cryptographic primitives - and hence
/// providing a theoretical maximal throughput that a system could achieve if the cost of crypto is optimized
/// away.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
#[cfg(all(
    feature = "unsecure_schemes",
    not(feature = "secure"),
    debug_assertions
))]
pub mod unsecure;

////////////////////////////////////////////////////////////////
// Generic Keypair
////////////////////////////////////////////////////////////////

pub fn generate_production_keypair<K: traits::KeyPair>() -> K {
    generate_keypair::<K, _>(&mut thread_rng())
}

pub fn generate_keypair<K: traits::KeyPair, R>(csprng: &mut R) -> K
where
    R: traits::AllowedRng,
{
    K::generate(csprng)
}
