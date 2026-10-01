// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! SLIP-0010 key derivation for the post-quantum schemes.

use fastcrypto::error::FastCryptoResult;
use fastcrypto::slip10::{derive_hardened, Slip10MasterKey};
use fastcrypto::traits::ToFromBytes;

use crate::mldsa65::MLDSA65KeyPair;

/// Derive an ML-DSA-65 keypair from a BIP-39 seed along a hardened SLIP-0010
/// path, per [satoshilabs/slips#1968](https://github.com/satoshilabs/slips/pull/1968):
/// the node secret is the FIPS 204 keygen seed.
pub fn derive_mldsa65_keypair(seed: &[u8], indexes: &[u32]) -> FastCryptoResult<MLDSA65KeyPair> {
    let node = derive_hardened(Slip10MasterKey::MlDsa65, seed, indexes)?;
    MLDSA65KeyPair::from_bytes(&node.secret)
}
