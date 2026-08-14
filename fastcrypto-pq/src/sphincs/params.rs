// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! SLH-DSA parameter sets (FIPS 205).
//!
//! One canonical table shared by production (`SlhDsaParams::sha2_*` constructors)
//! and tests (per-module `run_e2e` helpers).
//!
//! The `dead_code` allow covers consts/fields that are only read from tests or
//! from PR 2's `slh_dsa.rs` — they look unused in a non-test build of this PR.

#![allow(dead_code)]

/// `name`, `m`, `sig_size` are redundant with the other fields — kept as
/// cross-checks against the spec (FIPS 205 Table 1).
#[derive(Debug, Clone, Copy)]
pub(super) struct FipsParams {
    pub name: &'static str,
    pub n: u16,
    pub h: u8,
    pub d: u8,
    pub h_prime: u8,
    pub a: u16,
    pub k: u16,
    pub lg_w: u16,
    /// Message digest length `m = ⌈k·a/8⌉ + ⌈(h−h')/8⌉ + ⌈h'/8⌉`.
    pub m: u16,
    /// Total signature length in bytes (per FIPS 205 Table 1).
    pub sig_size: usize,
}

// FIPS 205 approved sets (all use lg_w = 4).
pub(super) const FIPS_128S: FipsParams = FipsParams {
    name: "128s",
    n: 16,
    h: 63,
    d: 7,
    h_prime: 9,
    a: 12,
    k: 14,
    lg_w: 4,
    m: 30,
    sig_size: 7856,
};
pub(super) const FIPS_128F: FipsParams = FipsParams {
    name: "128f",
    n: 16,
    h: 66,
    d: 22,
    h_prime: 3,
    a: 6,
    k: 33,
    lg_w: 4,
    m: 34,
    sig_size: 17088,
};
pub(super) const FIPS_192S: FipsParams = FipsParams {
    name: "192s",
    n: 24,
    h: 63,
    d: 7,
    h_prime: 9,
    a: 14,
    k: 17,
    lg_w: 4,
    m: 39,
    sig_size: 16224,
};
pub(super) const FIPS_192F: FipsParams = FipsParams {
    name: "192f",
    n: 24,
    h: 66,
    d: 22,
    h_prime: 3,
    a: 8,
    k: 33,
    lg_w: 4,
    m: 42,
    sig_size: 35664,
};
pub(super) const FIPS_256S: FipsParams = FipsParams {
    name: "256s",
    n: 32,
    h: 64,
    d: 8,
    h_prime: 8,
    a: 14,
    k: 22,
    lg_w: 4,
    m: 47,
    sig_size: 29792,
};
pub(super) const FIPS_256F: FipsParams = FipsParams {
    name: "256f",
    n: 32,
    h: 68,
    d: 17,
    h_prime: 4,
    a: 9,
    k: 35,
    lg_w: 4,
    m: 49,
    sig_size: 49856,
};
