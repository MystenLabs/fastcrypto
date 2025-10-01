// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::threshold_schnorr::{G, S};
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::groups::GroupElement;
use fastcrypto::hmac::{hkdf_sha3_256, HkdfIkm};
use fastcrypto::traits::ToFromBytes;

/// Compute a tweak from a verifying key and a derivation index.
pub(crate) fn compute_tweak(vk: &G, index: u64, info: &[u8]) -> S {
    let mut ikm: Vec<u8> = vk.x_as_be_bytes().unwrap().to_vec(); // 32 bytes
    ikm.extend_from_slice(&index.to_be_bytes()); // 8 bytes

    // Derive 64 uniform bytes to reduce bias from modular reduction to the 32 byte scalar field.
    // This is conservative since the secp256k1 scalar field size is very close to 2^256.
    let bytes = hkdf_sha3_256(&HkdfIkm::from_bytes(&ikm).unwrap(), &[], info, 64).unwrap();
    S::from_bytes_mod_order(&bytes)
}

/// Derive a new verifying key from an existing one and a derivation index.
/// This is computed as vk + [compute_tweak](vk, index) * G.
///
/// The derived key can have odd Y coordinate and hence not be a valid BIP-0340 Schnorr public key.
/// However, the signing protocol ensures that the signature will be valid for the derived key
/// computed with [derive_verifying_key] which returns a valid BIP-0340 public key
pub(crate) fn derive_verifying_key_internal(vk: &G, index: u64, info: &[u8]) -> G {
    vk + G::generator() * compute_tweak(vk, index, info)
}

/// Derive a new verifying key from an existing one and a derivation index.
/// This will be a valid BIP-0340 Schnorr public key.
pub fn derive_verifying_key(vk: &G, index: u64, info: &[u8]) -> SchnorrPublicKey {
    SchnorrPublicKey::try_from(&derive_verifying_key_internal(vk, index, info))
        .expect("is never zero")
}
