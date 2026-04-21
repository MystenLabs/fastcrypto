// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// FIPS 205 Section 11.2.1 — SHA2-based tweakable hash functions for security category 1 (n=16).
///
/// F, H, T_l, and PRF all share the same core:
///   Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64-n) ‖ ADRSc ‖ M))
///
/// TODO: this only covers the n=16 SHA2 instantiation. Extend to cover:
///   - n ≥ 24 (SHA2-192/256): H and T_l switch to SHA-512 with 128-byte block
///     pad (toByte(0, 128-n)); F and PRF stay on SHA-256. See FIPS 205 §11.2.1.
///   - SLH-DSA-SHAKE-*: the SHAKE256-based construction from §11.2.2, which
///     replaces the whole family with a single XOF — no SHA-256/SHA-512 split,
///     no 64-n padding.
use digest::Digest;
use sha2::Sha256;

use super::Adrs;

const SHA256_BLOCK: usize = 64;
const ZERO_PAD: [u8; SHA256_BLOCK] = [0u8; SHA256_BLOCK];

/// Core shared by F, H, T_l, and PRF:
///   Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64-n) ‖ ADRSc ‖ M))
pub fn tweakable_hash(pk_seed: &[u8], adrs: Adrs, m: &[u8]) -> Vec<u8> {
    let n = pk_seed.len();
    let adrs_c = adrs.compress();
    let mut hasher = Sha256::new();
    // TODO: the first block is fixed - so we can share its output across instantiations to optimize hash costs
    hasher.update(pk_seed);
    hasher.update(&ZERO_PAD[..SHA256_BLOCK - n]);
    hasher.update(adrs_c);
    hasher.update(m);
    hasher.finalize()[..n].to_vec()
}
