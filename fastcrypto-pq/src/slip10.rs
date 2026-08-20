// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! SLIP-0010 master keys for the post-quantum schemes.
//!
//! One string per parameter set, byte for byte as proposed in
//! [satoshilabs/slips#1968](https://github.com/satoshilabs/slips/pull/1968)

/// ML-DSA-44 (FIPS 204, NIST security level 2).
pub const MLDSA44_MASTER_KEY: &[u8] = b"ML-DSA-44 seed";
/// ML-DSA-65 (FIPS 204, NIST security level 3).
pub const MLDSA65_MASTER_KEY: &[u8] = b"ML-DSA-65 seed";
/// ML-DSA-87 (FIPS 204, NIST security level 5).
pub const MLDSA87_MASTER_KEY: &[u8] = b"ML-DSA-87 seed";
