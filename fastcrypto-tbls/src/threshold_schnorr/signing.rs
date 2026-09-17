// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::key_derivation::{compute_tweak, derive_verifying_key_internal};
use crate::threshold_schnorr::{avss, Address, G, S};
use fastcrypto::error::FastCryptoError::InputTooShort;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::secp256k1::schnorr::{
    bip0340_hash_to_scalar, SchnorrPublicKey, SchnorrSignature, Tag,
};
use fastcrypto::groups::GroupElement;
use itertools::Itertools;
use tap::TapFallible;
use tracing::warn;

/// Domain separation prefix for the random oracle used to compute presignature binding factors.
const BINDING_FACTOR_DOMAIN: &str = "fastcrypto_threshold_schnorr_presignature_binding";

/// Generate partial threshold Schnorr signatures for a given message using two presigning tuples.
/// The presigning tuples are combined into one nonce which is bound to the message and verifying
/// key, so it does not matter whether the presignatures are generated before or after the message
/// is known.
/// The presigning tuples must be taken from a [Presignatures] iterator, the other parties should use the same tuples in the same order and one tuple may only be used once.
/// Returns also the public nonce R.
///
/// The signatures produced follow the BIP-0340 standard (<https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>).
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly.
/// The signature will be valid for the derived verifying key.
///
/// `GeneralOpaqueError` is returned if the generated nonce R is the identity element (should happen only with negligible probability).
/// `InvalidInput` is returned if the verifying key is the identity element, if the two presigning
/// tuples are equal or if they have a different number of shares.
pub fn generate_partial_signatures(
    message: &[u8],
    presig_0: (Vec<S>, G),
    presig_1: (Vec<S>, G),
    my_signing_key_shares: &avss::SharesForNode,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<(G, Vec<Eval<S>>)> {
    let (mut secret_presigs, r_g) = bind_presignatures(
        message,
        presig_0,
        presig_1,
        verifying_key,
        derivation_address,
    )?;
    check_nonce(&r_g)?;

    // In BIP-340, the nonce R must have an even Y coordinate.
    // If it doesn't, we negate the secret nonce to get a new nonce R' = -R with an even Y.
    // Since only the X coordinate of R is included in the signature, we don't need to change R, but we must negate the presigs.
    if !r_g.has_even_y()? {
        for presig in &mut secret_presigs {
            *presig = -*presig;
        }
    }

    // If a derivation index is provided, derive a new verifying key (and implicitly also signing key) for this index.
    let verifying_key = if let Some(address) = derivation_address {
        derive_verifying_key_internal(verifying_key, address)?
    } else {
        *verifying_key
    };

    // The verifying key must also have an even Y coordinate.
    // If this is not the case, we must negate the verifying key (and hence also the signing key).
    // Since the signing key shares are multiplied with the challenge, we just change the sign of the challenge instead.
    let mut h = bip0340_hash(&r_g, &verifying_key, message)?;
    if !verifying_key.has_even_y()? {
        h = -h;
    }

    // sanity check.
    if my_signing_key_shares.shares.len() != secret_presigs.len() {
        return Err(FastCryptoError::InvalidInput);
    }

    Ok((
        r_g,
        my_signing_key_shares
            .shares
            .iter()
            .zip(secret_presigs)
            .map(
                |(
                    Eval {
                        index,
                        value: sk_share,
                    },
                    presig,
                )| Eval {
                    index: *index,
                    value: presig + h * sk_share,
                },
            )
            .collect(),
    ))
}

/// Given enough partial signatures, aggregate them into a full signature and verify it.
/// The signature produced follows the BIP-0340 standard.
///
/// The public presignatures must be the public parts of the presigning tuples used in
/// [generate_partial_signatures], in the same order.
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly.
/// The signature will be valid for the derived verifying key.
///
/// Returns an `InputTooShort` error if not enough partial signatures are provided.
/// `GeneralOpaqueError` is returned if the computed nonce R is the identity element.
/// `InvalidSignature` is returned if the aggregated signature does not verify.
/// `InvalidInput` is returned if the provided verifying key is the identity element or if the two
/// public presignatures are equal.
pub fn aggregate_signatures(
    message: &[u8],
    public_presig_0: &G,
    public_presig_1: &G,
    partial_signatures: &[Eval<S>],
    threshold: u16,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<SchnorrSignature> {
    if partial_signatures.len() < threshold as usize {
        return Err(InputTooShort(threshold as usize));
    }

    if !partial_signatures.iter().map(|s| s.index).all_unique() {
        return Err(FastCryptoError::InvalidInput);
    }

    let s = Poly::recover_c0(
        threshold,
        partial_signatures.iter().take(threshold as usize),
    )?;

    finalize_schnorr_signature(
        message,
        public_presig_0,
        public_presig_1,
        s,
        verifying_key,
        derivation_address,
    )
}

/// Wrap an already-recovered signing scalar `s = f(0)` into a BIP-0340 Schnorr signature.
///
/// This is the second half of [aggregate_signatures], split out so callers that recover `s`
/// through a different path (e.g. Reed–Solomon decoding, which yields `s` as the constant
/// coefficient of the message polynomial) can reuse the BIP-0340 finalization without
/// re-running Lagrange interpolation.
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly. The signature will
/// be valid for the derived verifying key.
///
/// `GeneralOpaqueError` is returned if the computed nonce R is the identity element.
/// `InvalidSignature` is returned if the aggregated signature does not verify.
/// `InvalidInput` is returned if the provided verifying key is the identity element or if the two
/// public presignatures are equal.
pub fn finalize_schnorr_signature(
    message: &[u8],
    public_presig_0: &G,
    public_presig_1: &G,
    mut s: S,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<SchnorrSignature> {
    // Compute the nonce R for the signature.
    let r_g = bind_public_presignatures(
        message,
        public_presig_0,
        public_presig_1,
        verifying_key,
        derivation_address,
    )?;
    check_nonce(&r_g)?;

    // If a derivation index is provided, compute the derived verifying key and adjust the signature accordingly.
    let verifying_key = if let Some(address) = derivation_address {
        let tweak = compute_tweak(verifying_key, address)?;
        let derived_vk = derive_verifying_key_internal(verifying_key, address)?;
        let h = tweak * bip0340_hash(&r_g, &derived_vk, message)?;
        if derived_vk.has_even_y()? {
            s += h;
        } else {
            s -= h;
        }
        derived_vk
    } else {
        *verifying_key
    };

    let signature = SchnorrSignature::try_from((r_g, s))?;

    SchnorrPublicKey::try_from(&verifying_key)?
        .verify(message, &signature)
        .tap_err(|e| warn!("signing: aggregated signature failed verification: {e:?}"))?;

    Ok(signature)
}

/// Combine two presigning tuples into one bound to the message and verifying key:
/// `(t_0 + b * t_1, p_0 + b * p_1)` with `b = H(p_0, p_1, vk, message)`.
fn bind_presignatures(
    message: &[u8],
    (secret_presigs_0, public_presig_0): (Vec<S>, G),
    (secret_presigs_1, public_presig_1): (Vec<S>, G),
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<(Vec<S>, G)> {
    if secret_presigs_0.len() != secret_presigs_1.len() {
        return Err(FastCryptoError::InvalidInput);
    }
    let b = binding_factor(
        message,
        &public_presig_0,
        &public_presig_1,
        verifying_key,
        derivation_address,
    )?;
    Ok((
        secret_presigs_0
            .into_iter()
            .zip(secret_presigs_1)
            .map(|(t_0, t_1)| t_0 + b * t_1)
            .collect(),
        public_presig_0 + public_presig_1 * b,
    ))
}

/// Compute the public part of [bind_presignatures].
fn bind_public_presignatures(
    message: &[u8],
    public_presig_0: &G,
    public_presig_1: &G,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<G> {
    let b = binding_factor(
        message,
        public_presig_0,
        public_presig_1,
        verifying_key,
        derivation_address,
    )?;
    Ok(*public_presig_0 + *public_presig_1 * b)
}

/// Compute the binding factor `b = H(p_0, p_1, vk, message)`, where `vk` is the derived verifying
/// key if a derivation address is given.
fn binding_factor(
    message: &[u8],
    public_presig_0: &G,
    public_presig_1: &G,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<S> {
    if public_presig_0 == public_presig_1 || *verifying_key == G::zero() {
        return Err(FastCryptoError::InvalidInput);
    }
    let verifying_key = if let Some(address) = derivation_address {
        derive_verifying_key_internal(verifying_key, address)?
    } else {
        *verifying_key
    };
    Ok(
        RandomOracle::new(BINDING_FACTOR_DOMAIN).evaluate_to_group_element(&(
            public_presig_0,
            public_presig_1,
            verifying_key,
            message,
        )),
    )
}

/// Reject the identity element as a nonce. Since the presignatures are random, this occurs only
/// with negligible probability and is rejected with [`FastCryptoError::GeneralOpaqueError`].
fn check_nonce(r_g: &G) -> FastCryptoResult<()> {
    if *r_g == G::zero() {
        return Err(FastCryptoError::GeneralOpaqueError);
    }
    Ok(())
}

fn bip0340_hash(r_g: &G, vk: &G, message: &[u8]) -> FastCryptoResult<S> {
    Ok(bip0340_hash_to_scalar(
        Tag::Challenge,
        [&r_g.x_as_be_bytes()?, &vk.x_as_be_bytes()?, message],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::serde_helpers::ToFromByteArray;

    #[test]
    fn test_bind_public_presignatures_vector() {
        let p_0 = G::generator() * S::from(1u128);
        let p_1 = G::generator() * S::from(2u128);
        let vk = G::generator() * S::from(3u128);
        let address = [4u8; 32];

        let r = bind_public_presignatures(b"Hello, world!", &p_0, &p_1, &vk, None).unwrap();
        assert_eq!(
            Hex::encode(r.to_byte_array()),
            "a73d0abbc7f892d55e1fe3c86a86d4eec63a47ca6410469fab1939f5f08e08ee00"
        );

        let r =
            bind_public_presignatures(b"Hello, world!", &p_0, &p_1, &vk, Some(&address)).unwrap();
        assert_eq!(
            Hex::encode(r.to_byte_array()),
            "4ffcc2538b053e64ae56e93f2ae5ca8790251fbab0fdb9d5f29fe4dfd564e31900"
        );
    }
}
