// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Generic [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
//! hardened-only hierarchical key derivation.
//!
//! SLIP-0010 parametrizes its HMAC-SHA512 tree by one per-scheme master key
//! (the "Curve" string: `"ed25519 seed"`, `"Bitcoin seed"`, ...). This
//! module is designed generically and exposes the walk itself; each scheme
//! supplies its master key and interprets the resulting node secret

use hkdf::hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A derived SLIP-0010 node: the 32-byte node secret `I_L` and chain code
/// `I_R`. The secret is key material and is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Slip10Node {
    pub secret: [u8; 32],
    pub chain_code: [u8; 32],
}

/// Derive the SLIP-0010 node for `indexes` under `master_key`.
///
/// `master_key` is the per-scheme HMAC key from the SLIP-0010 curve table (or
/// a proposed extension of it, e.g. satoshilabs/slips#1968 for ML-DSA).
pub fn derive_hardened(master_key: &[u8], seed: &[u8], indexes: &[u32]) -> Slip10Node {
    let mut node = hmac_sha512(master_key, seed);
    for index in indexes {
        let mut data = [0u8; 37];
        data[1..33].copy_from_slice(&node[..32]);
        data[33..].copy_from_slice(&(index | 0x8000_0000).to_be_bytes());
        let next = hmac_sha512(&node[32..], &data);
        data.zeroize();
        node.zeroize();
        node = next;
    }
    let mut result = Slip10Node {
        secret: [0u8; 32],
        chain_code: [0u8; 32],
    };
    result.secret.copy_from_slice(&node[..32]);
    result.chain_code.copy_from_slice(&node[32..]);
    node.zeroize();
    result
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key)
      .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
