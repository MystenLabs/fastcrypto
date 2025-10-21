// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use crate::threshold_schnorr::key_derivation::{compute_tweak, derive_verifying_key_internal};
use crate::threshold_schnorr::presigning::Presignatures;
use crate::threshold_schnorr::{avss, G, S};
use fastcrypto::error::FastCryptoError::{InputTooShort, OutOfPresigs};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::secp256k1::schnorr::{
    bip0340_hash_to_scalar, SchnorrPublicKey, SchnorrSignature, Tag,
};
use fastcrypto::groups::GroupElement;
use itertools::Itertools;

/// Generate partial threshold Schnorr signatures for a given message using a presigning triple.
/// Returns also the public nonce R.
///
/// The signatures produced follow the BIP-0340 standard (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly.
/// The signature will be valid for the derived verifying key.
///
/// Returns an `OutOfPresigs` error if the presignatures iterator is exhausted.
/// `GeneralOpaqueError` is returned if the generated nonce R is the identity element (should happen only with negligible probability).
/// `InvalidInput` is returned if the verifying key is the identity element.
pub fn generate_partial_signatures<const BATCH_SIZE: usize>(
    message: &[u8],
    presignatures: &mut Presignatures<BATCH_SIZE>,
    beacon_value: &S,
    my_signing_key_shares: &avss::SharesForNode,
    verifying_key: &G,
    derivation_index: Option<u64>,
) -> FastCryptoResult<(G, Vec<Eval<S>>)> {
    // TODO: Each output from an instance of Presigning has a unique index. Perhaps this is needed for coordination?
    let (_, mut secret_presigs, public_presig) = presignatures.next().ok_or(OutOfPresigs)?;

    let r_g = public_presig + G::generator() * beacon_value;

    // Since both the public_presig and the beacon_value are random, this should happen only with negligible probability.
    if r_g == G::zero() {
        return Err(FastCryptoError::GeneralOpaqueError);
    }

    // In BIP-340, the nonce R must have an even Y coordinate.
    // If it doesn't, we negate the secret nonce to get a new nonce R' = -R with an even Y.
    // Since only the X coordinate of R is included in the signature, we don't need to change R, but we must negate the presigs.
    if !r_g.has_even_y()? {
        for presig in &mut secret_presigs {
            *presig = -*presig;
        }
    }

    // If a derivation index is provided, derive a new verifying key (and implicitly also signing key) for this index.
    let verifying_key = if let Some(index) = derivation_index {
        derive_verifying_key_internal(verifying_key, index)
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

    Ok((
        public_presig,
        my_signing_key_shares
            .shares
            .iter()
            .zip_eq(secret_presigs)
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
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly.
/// The signature will be valid for the derived verifying key.
///
/// Returns an `InputTooShort` error if not enough partial signatures are provided.
/// `GeneralOpaqueError` is returned if the computed nonce R is the identity element.
/// `InvalidSignature` is returned if the aggregated signature does not verify.
/// `InvalidInput` is returned if the provided verifying key is the identity element.
pub fn aggregate_signatures(
    message: &[u8],
    public_presig: &G,
    beacon_value: &S,
    partial_signatures: &[Eval<S>],
    threshold: u16,
    verifying_key: &G,
    derivation_index: Option<u64>,
) -> FastCryptoResult<SchnorrSignature> {
    if partial_signatures.len() < threshold as usize {
        return Err(InputTooShort(threshold as usize));
    }

    if !partial_signatures.iter().map(|s| s.index).all_unique() {
        return Err(FastCryptoError::InvalidInput);
    }

    // Interpolate the partial signatures to get the full signature.
    let mut s = Poly::recover_c0(
        threshold,
        partial_signatures.iter().take(threshold as usize),
    )?;

    // Compute the nonce R for the signature.
    let r_g = public_presig + G::generator() * beacon_value;
    if r_g == G::zero() {
        return Err(FastCryptoError::GeneralOpaqueError);
    }

    // In acc. with BIP-0340, we need to ensure the nonce R has an even Y coordinate.
    // If it doesn't, we subtract the beacon value instead of adding it like it is done for the secret shares.
    // We don't need to change R itself since only the X coordinate of this is used in the hash and signature below.
    if r_g.has_even_y()? {
        s += beacon_value
    } else {
        s -= beacon_value
    };

    // If a derivation index is provided, compute the derived verifying key and adjust the signature accordingly.
    let verifying_key = if let Some(index) = derivation_index {
        let tweak = compute_tweak(verifying_key, index);
        let derived_vk = derive_verifying_key_internal(verifying_key, index);
        if derived_vk.has_even_y()? {
            s += tweak * bip0340_hash(&r_g, &derived_vk, message)?;
        } else {
            s -= tweak * bip0340_hash(&r_g, &derived_vk, message)?;
        }
        derived_vk
    } else {
        *verifying_key
    };

    let signature = SchnorrSignature::try_from((r_g, s))?;

    // TODO: Handle invalid signatures
    SchnorrPublicKey::try_from(&verifying_key)?.verify(message, &signature)?;

    Ok(signature)
}

fn bip0340_hash(r_g: &G, vk: &G, message: &[u8]) -> FastCryptoResult<S> {
    Ok(bip0340_hash_to_scalar(
        Tag::Challenge,
        [&r_g.x_as_be_bytes()?, &vk.x_as_be_bytes()?, message],
    ))
}
