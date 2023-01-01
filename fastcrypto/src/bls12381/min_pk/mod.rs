// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Module minimizing the size of public keys. See also [min_sig].

use super::*;
use blst::min_pk as blst;
/// Hash-to-curve domain separation tag.
pub const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
define_bls12381!(BLS_G1_LENGTH, BLS_G2_LENGTH, DST_G2);

#[cfg(feature = "experimental")]
pub mod mskr;
