// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::threshold_schnorr::{Address, G, S};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::groups::GroupElement;
use fastcrypto::hmac::{hkdf_sha3_256, HkdfIkm};
use fastcrypto::traits::ToFromBytes;

/// Domain separation for the tweak computed by [compute_tweak].
const DERIVATION_CONTEXT: &[u8] = b"threshold_schnorr_key_derivation";

/// Compute a tweak from a verifying key and a derivation path.
/// Returns an error if `vk` is the identity point, which has no x-coordinate.
pub(crate) fn compute_tweak(vk: &G, address: &Address) -> FastCryptoResult<S> {
    let mut ikm: Vec<u8> = vk.x_as_be_bytes()?.to_vec(); // 32 bytes
    ikm.extend_from_slice(address);

    // Derive 64 uniform bytes to reduce bias from modular reduction to the 32 byte scalar field.
    // This is conservative since the secp256k1 scalar field size is very close to 2^256.
    let bytes = hkdf_sha3_256(
        &HkdfIkm::from_bytes(&ikm).unwrap(),
        &[],
        DERIVATION_CONTEXT,
        64,
    )
    .unwrap();
    Ok(S::from_bytes_mod_order(&bytes))
}

/// Derive a new verifying key from an existing one and a Sui address.
/// This is computed as P + [compute_tweak](vk, address) * G, where P is `vk` or `-vk`, whichever
/// has an even Y coordinate. The derived key is thus a function of the BIP-0340 (x-only) form of
/// `vk` alone, as in BIP-0341.
///
/// The derived key can have odd Y coordinate and hence not be a valid BIP-0340 Schnorr public key.
/// However, the signing protocol ensures that the signature will be valid for the derived key
/// computed with [derive_verifying_key] which returns a valid BIP-0340 public key.
///
/// Returns an error if `vk` is the identity point.
pub(crate) fn derive_verifying_key_internal(vk: &G, address: &Address) -> FastCryptoResult<G> {
    let even_y_vk = if vk.has_even_y()? { *vk } else { -*vk };
    Ok(even_y_vk + G::generator() * compute_tweak(vk, address)?)
}

/// Derive a new verifying key from an existing one and a Sui address.
/// This will be a valid BIP-0340 Schnorr public key.
///
/// The derivation depends on the y-parity of `vk`, so it must be given the full verifying key.
/// Lifting the x-only BIP-0340 form of `vk` to even y gives a different result for about half of
/// all keys.
///
/// The derivation is non-hardened: the derived signing key is the original one plus a public
/// tweak, so revealing a derived signing key reveals the original one.
///
/// Returns an error if `vk` is the identity point.
pub fn derive_verifying_key(vk: &G, address: &Address) -> FastCryptoResult<SchnorrPublicKey> {
    Ok(
        SchnorrPublicKey::try_from(&derive_verifying_key_internal(vk, address)?)
            .expect("is never zero"),
    )
}

#[cfg(test)]
mod tests {
    use super::derive_verifying_key;
    use crate::threshold_schnorr::{G, S};
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::serde_helpers::ToFromByteArray;

    #[test]
    fn test_derivation_only_depends_on_x_coordinate() {
        let vk = G::generator() * S::rand(&mut rand::thread_rng());
        let address = [7u8; 32];
        assert_eq!(
            derive_verifying_key(&vk, &address).unwrap().to_byte_array(),
            derive_verifying_key(&-vk, &address)
                .unwrap()
                .to_byte_array()
        );
    }
}
