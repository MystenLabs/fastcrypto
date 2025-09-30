// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::threshold_schnorr::{G, S};
use fastcrypto::groups::GroupElement;
use fastcrypto::hmac::{hkdf_sha3_256, HkdfIkm};
use fastcrypto::traits::ToFromBytes;

const HKDF_DST: &[u8] = b"FASTCRYPTO-TBLS-KEY-DERIVATION-v1";

/// Compute a tweak from a verifying key and a derivation index.
pub(crate) fn compute_tweak(vk: &G, index: u64) -> S {
    let mut ikm: Vec<u8> = vk.x_as_be_bytes().unwrap().to_vec(); // 32 bytes
    ikm.extend_from_slice(&index.to_be_bytes()); // 8 bytes

    // Derive 64 uniform bytes to avoid bias from modular reduction
    let bytes = hkdf_sha3_256(&HkdfIkm::from_bytes(&ikm).unwrap(), &[], HKDF_DST, 64).unwrap();
    S::from_bytes_mod_order(&bytes)
}

/// Derive a new verifying key from an existing one and a derivation index.
/// This is computed as vk + [compute_tweak](vk, index) * G.
pub(crate) fn derive_verifying_key(vk: &G, index: u64) -> G {
    vk + G::generator() * compute_tweak(vk, index)
}
