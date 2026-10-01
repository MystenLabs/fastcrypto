// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
//! hardened-only key derivation.
//!
//! One HMAC-SHA512 walk, keyed per scheme by [`Slip10MasterKey`]. Each scheme
//! decides what the 32-byte node secret means; for ed25519 and ML-DSA it is
//! the keygen seed.

use crate::error::{FastCryptoError, FastCryptoResult};
use hkdf::hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SLIP-0010 seeds are 128 to 512 bits, see
/// [slip-0010.md#master-key-generation](https://github.com/satoshilabs/slips/blob/master/slip-0010.md#master-key-generation).
pub const MIN_SEED_LENGTH: usize = 16;
/// Upper bound of the SLIP-0010 seed range, see [`MIN_SEED_LENGTH`].
pub const MAX_SEED_LENGTH: usize = 64;

const HARDENED_OFFSET: u32 = 0x8000_0000;

/// The schemes this module derives keys for, each with its SLIP-0010 master key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slip10MasterKey {
    /// `"ed25519 seed"`, from the SLIP-0010 curve table.
    Ed25519,
    /// `"ML-DSA-65 seed"`, as proposed in
    /// [satoshilabs/slips#1968](https://github.com/satoshilabs/slips/pull/1968).
    MlDsa65,
}

impl Slip10MasterKey {
    pub fn slip10_string(&self) -> &'static [u8] {
        match self {
            Slip10MasterKey::Ed25519 => b"ed25519 seed",
            Slip10MasterKey::MlDsa65 => b"ML-DSA-65 seed",
        }
    }
}

/// A derived SLIP-0010 node: the node secret `I_L` and chain code `I_R`.
/// Zeroized on drop and deliberately without `Debug`, since the secret is key
/// material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Slip10Node {
    pub secret: [u8; 32],
    pub chain_code: [u8; 32],
}

/// Derive the node for `indexes` under `master_key`. Every level is hardened,
/// whether or not the caller already set the hardened bit.
///
/// Returns `InputTooShort` / `InputTooLong` if `seed` is outside the SLIP-0010
/// range.
pub fn derive_hardened(
    master_key: Slip10MasterKey,
    seed: &[u8],
    indexes: &[u32],
) -> FastCryptoResult<Slip10Node> {
    if seed.len() < MIN_SEED_LENGTH {
        return Err(FastCryptoError::InputTooShort(MIN_SEED_LENGTH));
    }
    if seed.len() > MAX_SEED_LENGTH {
        return Err(FastCryptoError::InputTooLong(MAX_SEED_LENGTH));
    }

    let mut node = hmac_sha512(master_key.slip10_string(), seed);
    for index in indexes {
        // Hardened child: HMAC(chain code, 0x00 || secret || index).
        let mut data = [0u8; 37];
        data[1..33].copy_from_slice(&node[..32]);
        data[33..].copy_from_slice(&(index | HARDENED_OFFSET).to_be_bytes());
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
    Ok(result)
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}
