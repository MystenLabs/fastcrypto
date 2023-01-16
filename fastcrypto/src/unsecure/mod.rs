// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// This module contains an unsecure non-cryptographic hash function. The purpose of this library is to allow
/// seamless benchmarking of systems without taking into account the cost of cryptographic primitives - and hence
/// providing a theoretical maximal throughput that a system could achieve if the cost of crypto is optimized
/// away.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
pub mod hash;

/// This module contains an implementation of a negligible-cost (apart from some occasional pk copying) trivial
/// cryptographic signature scheme. The purpose of this library is to allow seamless benchmarking of systems
/// without taking into account the cost of cryptographic primitives - and hence providing a theoretical maximal
/// throughput that a system could achieve if the cost of crypto is optimized away.
///
/// The scheme is implemented as follows: The private key is PRIVATE_KEY_LENGTH random bytes and the public
/// key is defined from the private key as follows:
///
/// if PRIVATE_KEY_LENGTH >= PUBLIC_KEY_LENGTH {
///     pk = sk[0..PUBLIC_KEY_LENGTH]
/// } else {
///     pk = sk || 0...0
/// }
///
/// Signatures are implemented as H(pk || msg) where H is the non-cryptographic hash function XXHash, and
/// an aggregated signature is computed as the XOR of the individual signatures.
///
/// Warning: All schemes in this file are completely unsafe to use in production.
pub mod signature;

#[cfg(test)]
#[path = "tests/hash_tests.rs"]
pub mod unsecure_hash_tests;

#[cfg(test)]
#[path = "tests/unsecure_signature_tests.rs"]
pub mod unsecure_signature_tests;
