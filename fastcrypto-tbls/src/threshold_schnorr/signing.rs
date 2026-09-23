// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use crate::threshold_schnorr::key_derivation::{compute_tweak, derive_verifying_key_internal};
use crate::threshold_schnorr::reed_solomon::RSDecoder;
use crate::threshold_schnorr::{avss, Address, Parameters, G, S};
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InconsistentInputs, InputTooShort, InvalidSignature};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::secp256k1::schnorr::{
    bip0340_hash_to_scalar, SchnorrPublicKey, SchnorrSignature, Tag,
};
use fastcrypto::groups::GroupElement;
use itertools::Itertools;
use tap::TapFallible;
use tracing::warn;

/// Generate partial threshold Schnorr signatures for a given message using a presigning tuple.
/// The presigning tuple must be taken from a [Presignatures] iterator, the other parties should use the same tuple and one tuple may only be used once.
/// Signing twice with the same tuple discloses the signing key, whatever the beacon value.
/// Returns also the public presignature, which all parties must agree on.
///
/// The signatures produced follow the BIP-0340 standard (<https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>).
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly.
/// The signature will be valid for the derived verifying key.
///
/// `GeneralOpaqueError` is returned if the generated nonce R is the identity element (should happen only with negligible probability).
/// `InvalidInput` is returned if the verifying key is the identity element.
pub fn generate_partial_signatures(
    message: &[u8],
    (mut secret_presigs, public_presig): (Vec<S>, G),
    beacon_value: &S,
    my_signing_key_shares: &avss::SharesForNode,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<(G, Vec<Eval<S>>)> {
    let r_g = compute_nonce(&public_presig, beacon_value)?;

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
        public_presig,
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

/// Who, if anyone, the aggregation can blame for a partial signature inconsistent with the
/// signature it recovered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blame {
    /// Every partial signature given was consistent with the recovered signature.
    Nobody,
    /// The contributors at these share indices did not follow the protocol.
    Certain(Vec<ShareIndex>),
    /// These share indices were excluded without the margin to blame them, so some of their
    /// contributors may have followed the protocol.
    Inconclusive(Vec<ShareIndex>),
}

/// Given enough partial signatures, aggregate them into a full signature and verify it.
/// The signature produced follows the BIP-0340 standard.
///
/// The partial signatures must be received over an authenticated channel, and the caller must
/// reject any whose share index the sender does not hold. `params` must be the parameters
/// validated for this committee, see [Parameters::validate].
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly.
/// The signature will be valid for the derived verifying key.
///
/// Only the first `params.t` partial signatures are interpolated, so if any of those is wrong, all
/// of them are decoded as a Reed-Solomon code word instead and the share indices the decoding
/// excluded are returned along with the signature. Correcting `e` faults requires `params.t + 2e`
/// partial signatures.
///
/// A failed aggregation, reported as an `InvalidSignature` error, may be retried with a new set of
/// partial signatures as long as the presigning tuple, message and beacon value stay the same.
/// Reusing the presigning tuple for a different message or beacon value discloses the signing key.
///
/// The excluded indices come back as [Blame::Certain] when their contributors did not follow the
/// protocol, and as [Blame::Inconclusive] when the decoding had too little margin to show that.
/// Nothing excluded is [Blame::Nobody].
///
/// Returns an `InputTooShort` error if fewer than `params.t` partial signatures are provided.
/// `GeneralOpaqueError` is returned if the computed nonce R is the identity element.
/// `InvalidSignature` is returned if there are too many corrupted partial signatures to correct,
/// which the caller should retry as above, with more of them.
/// `InconsistentInputs` is returned if enough partial signatures were good to rule them out as the
/// cause, which leaves the presigning tuple, beacon value, message or verifying key given here
/// disagreeing with the ones the signers used. Retrying does not help.
/// `InvalidInput` is returned if the provided verifying key is the identity element.
pub fn aggregate_signatures(
    message: &[u8],
    public_presig: &G,
    beacon_value: &S,
    partial_signatures: &[Eval<S>],
    params: Parameters,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<(SchnorrSignature, Blame)> {
    if partial_signatures.len() < params.t as usize {
        return Err(InputTooShort(params.t as usize));
    }

    if !partial_signatures.iter().map(|s| s.index).all_unique() {
        return Err(FastCryptoError::InvalidInput);
    }

    let s = Poly::recover_c0(params.t, partial_signatures.iter().take(params.t as usize))?;

    match finalize_schnorr_signature(
        message,
        public_presig,
        beacon_value,
        s,
        verifying_key,
        derivation_address,
    ) {
        Ok(signature) => Ok((signature, Blame::Nobody)),
        Err(InvalidSignature) => correct_and_aggregate_signatures(
            message,
            public_presig,
            beacon_value,
            partial_signatures,
            params,
            verifying_key,
            derivation_address,
        ),
        Err(e) => Err(e),
    }
}

/// Decode the partial signatures as a Reed-Solomon code word, recovering the signature and the
/// share indices the decoding excluded, see [can_blame_excluded_indices].
fn correct_and_aggregate_signatures(
    message: &[u8],
    public_presig: &G,
    beacon_value: &S,
    partial_signatures: &[Eval<S>],
    params: Parameters,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<(SchnorrSignature, Blame)> {
    let decoder = RSDecoder::new(
        partial_signatures.iter().map(|s| s.index).collect(),
        params.t as usize,
    )
    .map_err(|_| InvalidSignature)?;
    let decoding = decoder
        .decode(&partial_signatures.iter().map(|s| s.value).collect_vec())
        .map_err(|_| InvalidSignature)?;

    let excluded: Vec<ShareIndex> = partial_signatures
        .iter()
        .map(|s| s.index)
        .filter(|&index| decoding.is_error(index))
        .collect();
    let can_blame = can_blame_excluded_indices(partial_signatures.len(), excluded.len(), params);

    let signature = match finalize_schnorr_signature(
        message,
        public_presig,
        beacon_value,
        decoding.constant_term(),
        verifying_key,
        derivation_address,
    ) {
        Ok(signature) => signature,
        // Enough of the points the decoding kept are honest to pin the polynomial, so the scalar
        // it recovered is the one the signers produced and the mismatch is in the inputs here.
        Err(InvalidSignature) if can_blame => return Err(InconsistentInputs),
        Err(e) => return Err(e),
    };

    let excluded = match (excluded.is_empty(), can_blame) {
        (true, _) => Blame::Nobody,
        (false, true) => Blame::Certain(excluded),
        (false, false) => Blame::Inconclusive(excluded),
    };
    Ok((signature, excluded))
}

/// Whether excluding `excluded` of the `given` partial signatures proves that those indices'
/// owners submitted a wrong one.
fn can_blame_excluded_indices(given: usize, excluded: usize, params: Parameters) -> bool {
    // Of the points the decoding kept, at most `f` are faulty, so `given - excluded - f` of them
    // are honest. Once that reaches `t` they determine the degree-`(t - 1)` polynomial, so the
    // decoding found the true one and everything it excluded really does lie off it.
    given.saturating_sub(excluded) >= params.t as usize + params.f as usize
}

/// Wrap an already-recovered signing scalar `s = f(0)` into a BIP-0340 Schnorr signature.
///
/// This is the second half of [aggregate_signatures], shared with the Reed-Solomon path, which
/// recovers `s` as the constant coefficient of the message polynomial instead of by interpolation.
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly. The signature will
/// be valid for the derived verifying key.
///
/// `GeneralOpaqueError` is returned if the computed nonce R is the identity element.
/// `InvalidSignature` is returned if the aggregated signature does not verify.
/// `InvalidInput` is returned if the provided verifying key is the identity element.
fn finalize_schnorr_signature(
    message: &[u8],
    public_presig: &G,
    beacon_value: &S,
    mut s: S,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<SchnorrSignature> {
    // Compute the nonce R for the signature.
    let r_g = compute_nonce(public_presig, beacon_value)?;

    // In acc. with BIP-0340, we need to ensure the nonce R has an even Y coordinate.
    // If it doesn't, we subtract the beacon value instead of adding it like it is done for the secret shares.
    // We don't need to change R itself since only the X coordinate of this is used in the hash and signature below.
    if r_g.has_even_y()? {
        s += beacon_value
    } else {
        s -= beacon_value
    };

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

/// Compute the signature nonce `R = public_presig + G * beacon_value`. Since both inputs are
/// random, the identity element occurs only with negligible probability and is rejected with
/// [`FastCryptoError::GeneralOpaqueError`].
fn compute_nonce(public_presig: &G, beacon_value: &S) -> FastCryptoResult<G> {
    let r_g = *public_presig + G::generator() * beacon_value;
    if r_g == G::zero() {
        return Err(FastCryptoError::GeneralOpaqueError);
    }
    Ok(r_g)
}

fn bip0340_hash(r_g: &G, vk: &G, message: &[u8]) -> FastCryptoResult<S> {
    Ok(bip0340_hash_to_scalar(
        Tag::Challenge,
        [&r_g.x_as_be_bytes()?, &vk.x_as_be_bytes()?, message],
    ))
}
