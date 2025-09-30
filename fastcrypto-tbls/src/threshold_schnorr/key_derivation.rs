// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::threshold_schnorr::{G, S};
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{HashFunction, Sha256};

/// Compute a tweak from a verifying key and a derivation index.
pub(crate) fn compute_tweak(vk: &G, index: u64) -> S {
    let mut hash = Sha256::new();
    hash.update(vk.x_as_be_bytes().unwrap());
    hash.update(index.to_be_bytes());
    S::from_bytes_mod_order(&hash.finalize().digest) // TODO: This is not uniform
}

/// Derive a new verifying key from an existing one and a derivation index.
///
/// This is computed as vk + [compute_tweak](vk, index) * G.
pub(crate) fn derive_verifying_key(vk: &G, index: u64) -> G {
    vk + G::generator() * compute_tweak(vk, index)
}
