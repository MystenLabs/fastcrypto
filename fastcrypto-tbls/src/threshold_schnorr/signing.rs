// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::key_derivation::{compute_tweak, derive_verifying_key_internal};
use crate::threshold_schnorr::presigning::{PresignaturePair, PublicPresignaturePair};
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

/// Domain separation prefix for the random oracle used to compute presignature binding factors.
const BINDING_FACTOR_DOMAIN: &str = "fastcrypto_threshold_schnorr_presignature_binding";

/// Generate partial threshold Schnorr signatures for a given message using a pair of presigning
/// tuples. Returns also the public nonce, which all parties must agree on.
///
/// The tuples are combined into a single nonce which is bound to the message and the verifying
/// key, so the signature is secure whether the presignatures are generated before or after the
/// message is known.
///
/// The pair must come from the iterator returned by [PresignaturePair::from_dealings], and the
/// other parties must use the same pair. Each tuple must go into exactly one signature: two
/// signatures from one pair do not disclose the signing key on their own, but three on different
/// messages do, and many pairs each used twice is a ROS forgery.
///
/// The signatures produced follow the BIP-0340 standard (<https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>).
///
/// If a derivation index is provided, a new verifying key is derived for this index (see
/// [derive_verifying_key]), and the signature is adjusted accordingly.
/// The signature will be valid for the derived verifying key.
///
/// `GeneralOpaqueError` is returned if the generated nonce R is the identity element (should happen only with negligible probability).
/// `InvalidInput` is returned if the verifying key or one of the public presignatures is the
/// identity element, if the two public presignatures are equal or if the tuples hold a different
/// number of shares.
pub fn generate_partial_signatures(
    message: &[u8],
    presig_pair: PresignaturePair,
    my_signing_key_shares: &avss::SharesForNode,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<(G, Vec<Eval<S>>)> {
    let (mut secret_presigs, r_g) =
        compute_nonce_shares(message, presig_pair, verifying_key, derivation_address)?;

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

/// Who, if anyone, the aggregation can blame for a partial signature inconsistent with the
/// signature it recovered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Blame {
    /// Nothing was corrected: the first `params.t` partial signatures interpolated to a valid
    /// signature, so the rest were never examined.
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
/// partial signatures as long as the presigning tuples, message and derivation address stay the
/// same. Any second use of the presigning tuples with a different message or derivation address
/// discloses the signing key.
///
/// The excluded indices come back as [Blame::Certain] when their contributors did not follow the
/// protocol, and as [Blame::Inconclusive] when the decoding had too little margin to show that.
/// [Blame::Nobody] means the decoding never ran.
///
/// Returns an `InputTooShort` error if fewer than `params.t` partial signatures are provided.
/// `GeneralOpaqueError` is returned if the computed nonce R is the identity element.
/// `InvalidSignature` is returned if there are too many corrupted partial signatures to correct,
/// which the caller should retry as above, with more of them.
/// `InconsistentInputs` is returned if enough partial signatures were good to rule them out as the
/// cause, which leaves the presigning tuples, message, verifying key or derivation address given
/// here disagreeing with the ones the signers used. Retrying does not help.
/// `InvalidInput` is returned if two partial signatures share a share index, if the verifying key
/// or one of the public presignatures is the identity element, or if the two public presignatures
/// are equal.
pub fn aggregate_signatures(
    message: &[u8],
    presig_pair: &PublicPresignaturePair,
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

    match finalize_schnorr_signature(message, presig_pair, s, verifying_key, derivation_address) {
        Ok(signature) => Ok((signature, Blame::Nobody)),
        // Decode the partial signatures as a Reed-Solomon code word instead.
        Err(InvalidSignature) => {
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
            let can_blame =
                can_blame_excluded_indices(partial_signatures.len(), excluded.len(), params);

            let signature = match finalize_schnorr_signature(
                message,
                presig_pair,
                decoding.constant_term(),
                verifying_key,
                derivation_address,
            ) {
                Ok(signature) => signature,
                // Enough of the points the decoding kept are honest to pin the polynomial,
                // so the scalar it recovered is the one the signers produced and the
                // mismatch is in the inputs here.
                Err(InvalidSignature) if can_blame => return Err(InconsistentInputs),
                Err(e) => return Err(e),
            };

            let blame = if can_blame {
                Blame::Certain(excluded)
            } else {
                Blame::Inconclusive(excluded)
            };
            Ok((signature, blame))
        }
        Err(e) => Err(e),
    }
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
/// `InvalidInput` is returned if the verifying key or one of the public presignatures is the
/// identity element, or if the two public presignatures are equal.
fn finalize_schnorr_signature(
    message: &[u8],
    presig_pair: &PublicPresignaturePair,
    s: S,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<SchnorrSignature> {
    // Compute the nonce R for the signature. The signers negate their secret nonces when R has an
    // odd Y coordinate, which covers the whole nonce here, so `s` needs no adjustment.
    let r_g = compute_nonce(message, presig_pair, verifying_key, derivation_address)?;
    let mut s = s;

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
/// `(T + delta * T', D + delta * D')`, see [compute_delta].
fn compute_nonce_shares(
    message: &[u8],
    presig_pair: PresignaturePair,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<(Vec<S>, G)> {
    let (public, (first_shares, second_shares)) = presig_pair.into_parts();
    if first_shares.len() != second_shares.len() {
        return Err(FastCryptoError::InvalidInput);
    }
    let delta = compute_delta(message, &public, verifying_key, derivation_address)?;
    Ok((
        first_shares
            .into_iter()
            .zip(second_shares)
            .map(|(t, t_prime)| t + delta * t_prime)
            .collect(),
        combine_public_presignatures(&public, &delta)?,
    ))
}

/// Compute the nonce `R = D + delta * D'` a signature is made with.
fn compute_nonce(
    message: &[u8],
    presig_pair: &PublicPresignaturePair,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<G> {
    let delta = compute_delta(message, presig_pair, verifying_key, derivation_address)?;
    combine_public_presignatures(presig_pair, &delta)
}

/// Compute the nonce `D + delta * D'` for a signature. Since the presignatures are random, the
/// identity element occurs only with negligible probability and is rejected with
/// [`FastCryptoError::GeneralOpaqueError`].
fn combine_public_presignatures(
    presig_pair: &PublicPresignaturePair,
    delta: &S,
) -> FastCryptoResult<G> {
    let (first, second) = presig_pair.presignatures();
    let r_g = *first + *second * delta;
    if r_g == G::zero() {
        return Err(FastCryptoError::GeneralOpaqueError);
    }
    Ok(r_g)
}

/// Compute the binding factor `delta = H(vk, presigning_id, index, D, D', message)`.
fn compute_delta(
    message: &[u8],
    presig_pair: &PublicPresignaturePair,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<S> {
    // As in FROST, the public presignatures must be non-identity group elements, and they must be
    // distinct so that the binding factor actually binds the second nonce to the message.
    let (first, second) = presig_pair.presignatures();
    if *first == G::zero() || *second == G::zero() || first == second || *verifying_key == G::zero()
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let verifying_key = if let Some(address) = derivation_address {
        derive_verifying_key_internal(verifying_key, address)?
    } else {
        *verifying_key
    };
    Ok(
        RandomOracle::new(BINDING_FACTOR_DOMAIN).evaluate_to_group_element(&(
            verifying_key,
            presig_pair.presigning_id().as_bytes(),
            presig_pair.index(),
            first,
            second,
            message,
        )),
    )
}

fn bip0340_hash(r_g: &G, vk: &G, message: &[u8]) -> FastCryptoResult<S> {
    Ok(bip0340_hash_to_scalar(
        Tag::Challenge,
        [&r_g.x_as_be_bytes()?, &vk.x_as_be_bytes()?, message],
    ))
}

/// Expose the nonce computation to the tests in the parent module.
#[cfg(test)]
pub(crate) fn compute_nonce_for_testing(
    message: &[u8],
    presig_pair: &PublicPresignaturePair,
    verifying_key: &G,
    derivation_address: Option<&Address>,
) -> FastCryptoResult<G> {
    compute_nonce(message, presig_pair, verifying_key, derivation_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_schnorr::PresigningId;
    use fastcrypto::encoding::{Encoding, Hex};
    use fastcrypto::serde_helpers::ToFromByteArray;

    fn presig_pair() -> PublicPresignaturePair {
        PublicPresignaturePair::new_for_testing(
            PresigningId::from_bytes_for_testing([7u8; 64]),
            1,
            (
                G::generator() * S::from(3u128),
                G::generator() * S::from(4u128),
            ),
        )
    }

    #[test]
    fn test_compute_nonce_vector() {
        let presig_pair = presig_pair();
        let vk = G::generator() * S::from(5u128);
        let address = [6u8; 32];

        let r = compute_nonce(b"Hello, world!", &presig_pair, &vk, None).unwrap();
        assert_eq!(
            Hex::encode(r.to_byte_array()),
            "045bfc64e26e284db3dcc72e2be4e99cfdea05879a2e250c56e66175d2bd701e00"
        );

        let r = compute_nonce(b"Hello, world!", &presig_pair, &vk, Some(&address)).unwrap();
        assert_eq!(
            Hex::encode(r.to_byte_array()),
            "0d72c476a432ce93f844e665d9cb6a973f00e26046075a6ca7817c98a0e2036680"
        );
    }

    /// Everything the binding factor is meant to cover must move the nonce it produces, since the
    /// signing tests only check that the parties agree on a delta, not on which one.
    #[test]
    fn test_bound_nonce_covers_every_input() {
        let pair = presig_pair();
        let vk = G::generator() * S::from(5u128);
        let address = [6u8; 32];
        let nonce = |message, pair: &PublicPresignaturePair, vk: &G, address| {
            compute_nonce(message, pair, vk, address).unwrap()
        };

        let r = nonce(b"Hello, world!", &pair, &vk, None);

        // The message
        assert_ne!(r, nonce(b"Goodbye, world!", &pair, &vk, None));

        // The derivation address, and hence the derived verifying key
        assert_ne!(r, nonce(b"Hello, world!", &pair, &vk, Some(&address)));
        assert_ne!(
            nonce(b"Hello, world!", &pair, &vk, Some(&address)),
            nonce(b"Hello, world!", &pair, &vk, Some(&[8u8; 32]))
        );

        // The verifying key
        let other_vk = G::generator() * S::from(9u128);
        assert_ne!(r, nonce(b"Hello, world!", &pair, &other_vk, None));

        // The presigning instance and the index of the pair within it
        let other_session = PublicPresignaturePair::new_for_testing(
            PresigningId::from_bytes_for_testing([10u8; 64]),
            pair.index(),
            *pair.presignatures(),
        );
        assert_ne!(r, nonce(b"Hello, world!", &other_session, &vk, None));
        let other_index = PublicPresignaturePair::new_for_testing(
            *pair.presigning_id(),
            pair.index() + 1,
            *pair.presignatures(),
        );
        assert_ne!(r, nonce(b"Hello, world!", &other_index, &vk, None));

        // The two presignatures, including the order they are given in
        let swapped = PublicPresignaturePair::new_for_testing(
            *pair.presigning_id(),
            pair.index(),
            (pair.presignatures().1, pair.presignatures().0),
        );
        assert_ne!(r, nonce(b"Hello, world!", &swapped, &vk, None));
    }
}
