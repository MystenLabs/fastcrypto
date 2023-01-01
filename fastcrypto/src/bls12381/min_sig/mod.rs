// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Module minimizing the size of signatures. See also [min_pk].

use super::*;
use blst::min_sig as blst;
/// Hash-to-curve domain separation tag.
pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
define_bls12381!(BLS_G2_LENGTH, BLS_G1_LENGTH, DST_G1);

#[cfg(feature = "experimental")]
pub mod mskr;
