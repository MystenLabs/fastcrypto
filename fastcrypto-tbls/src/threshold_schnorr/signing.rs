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

/// Combine two presigning tuples into a single presigning tuple bound to the message and the
/// verifying key: `(t, p) = (t_0 + b * t_1, p_0 + b * p_1)` with `b = H(p_0, p_1, vk, message)`.
///
/// Since the resulting nonce depends on the message, the security of the signature does not depend
/// on the presignatures being generated before the message is fixed (or vice versa), and the
/// output can be used with a zero beacon value in [generate_partial_signatures] and
/// [aggregate_signatures].
///
/// Both tuples must be taken from a [Presignatures] iterator, the other parties should use the
/// same tuples in the same order, and each tuple may only be used once. The verifying key and
/// derivation address must be the same as those used when signing.
///
/// `InvalidInput` is returned if the two tuples are equal or have a different number of shares,
/// or if the verifying key is the identity element.
pub fn bind_presignatures(
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

/// Compute the public part of [bind_presignatures]. This is used by parties who do not hold
/// secret presignatures, e.g. to aggregate signatures.
pub fn bind_public_presignatures(
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

/// Generate partial threshold Schnorr signatures for a given message using a presigning tuple.
/// The presigning tuple must be taken from a [Presignatures] iterator, the other parties should use the same tuple and one tuple may only be used once.
/// Returns also the public nonce R.
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
        public_presig,
        beacon_value,
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
/// `InvalidInput` is returned if the provided verifying key is the identity element.
pub fn finalize_schnorr_signature(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_schnorr::key_derivation::derive_verifying_key;
    use crate::types::ShareIndex;
    use fastcrypto::groups::Scalar;
    use rand::thread_rng;

    const T: u16 = 3;
    const N: u16 = 5;

    /// Secret share a random nonce and return the shares of each party and the public presig.
    fn presig_tuples(rng: &mut impl fastcrypto::traits::AllowedRng) -> (Vec<Vec<S>>, G) {
        let poly = Poly::<S>::rand(T - 1, rng);
        let secret = (1..=N)
            .map(|i| vec![poly.eval(ShareIndex::new(i).unwrap()).value])
            .collect();
        (secret, G::generator() * poly.c0())
    }

    fn sign(
        message: &[u8],
        derivation_address: Option<&Address>,
    ) -> FastCryptoResult<SchnorrSignature> {
        let mut rng = thread_rng();
        let sk = Poly::<S>::rand(T - 1, &mut rng);
        let vk = G::generator() * sk.c0();
        let (secret_0, public_0) = presig_tuples(&mut rng);
        let (secret_1, public_1) = presig_tuples(&mut rng);

        let partial_signatures = (1..=N)
            .map(|i| {
                let presig = bind_presignatures(
                    message,
                    (secret_0[i as usize - 1].clone(), public_0),
                    (secret_1[i as usize - 1].clone(), public_1),
                    &vk,
                    derivation_address,
                )
                .unwrap();
                let shares = avss::SharesForNode {
                    shares: vec![sk.eval(ShareIndex::new(i).unwrap())],
                };
                generate_partial_signatures(
                    message,
                    presig,
                    &S::zero(),
                    &shares,
                    &vk,
                    derivation_address,
                )
                .unwrap()
            })
            .collect_vec();

        let public_presig =
            bind_public_presignatures(message, &public_0, &public_1, &vk, derivation_address)?;
        assert!(partial_signatures.iter().all(|(p, _)| *p == public_presig));

        let signature = aggregate_signatures(
            message,
            &public_presig,
            &S::zero(),
            &partial_signatures
                .into_iter()
                .flat_map(|(_, s)| s)
                .collect_vec(),
            T,
            &vk,
            derivation_address,
        )?;
        let pk = match derivation_address {
            Some(address) => derive_verifying_key(&vk, address)?,
            None => SchnorrPublicKey::try_from(&vk)?,
        };
        pk.verify(message, &signature)?;
        Ok(signature)
    }

    #[test]
    fn test_signing_with_bound_presignatures() {
        // Run a few times to hit both parities of the nonce and verifying key.
        for _ in 0..10 {
            sign(b"Hello, world!", None).unwrap();
            sign(b"Hello, world!", Some(&[7u8; 32])).unwrap();
        }
    }

    #[test]
    fn test_binding_factor_depends_on_inputs() {
        let mut rng = thread_rng();
        let vk = G::generator() * S::rand(&mut rng);
        let other_vk = G::generator() * S::rand(&mut rng);
        let p_0 = G::generator() * S::rand(&mut rng);
        let p_1 = G::generator() * S::rand(&mut rng);
        let address = [1u8; 32];

        let r = bind_public_presignatures(b"a", &p_0, &p_1, &vk, None).unwrap();
        assert_ne!(
            r,
            bind_public_presignatures(b"b", &p_0, &p_1, &vk, None).unwrap()
        );
        assert_ne!(
            r,
            bind_public_presignatures(b"a", &p_1, &p_0, &vk, None).unwrap()
        );
        assert_ne!(
            r,
            bind_public_presignatures(b"a", &p_0, &p_1, &other_vk, None).unwrap()
        );
        assert_ne!(
            r,
            bind_public_presignatures(b"a", &p_0, &p_1, &vk, Some(&address)).unwrap()
        );
    }

    #[test]
    fn test_bind_presignatures_rejects_invalid_input() {
        let mut rng = thread_rng();
        let vk = G::generator() * S::rand(&mut rng);
        let p = G::generator() * S::rand(&mut rng);
        let q = G::generator() * S::rand(&mut rng);
        let t = S::rand(&mut rng);

        // Same tuple twice
        assert!(bind_presignatures(b"m", (vec![t], p), (vec![t], p), &vk, None).is_err());
        // Different number of shares
        assert!(bind_presignatures(b"m", (vec![t], p), (vec![], q), &vk, None).is_err());
        // Identity verifying key
        assert!(bind_public_presignatures(b"m", &p, &q, &G::zero(), None).is_err());
    }
}
