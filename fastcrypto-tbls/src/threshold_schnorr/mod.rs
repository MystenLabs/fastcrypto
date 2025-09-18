// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use crate::threshold_schnorr::presigning::Presignatures;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{GeneralError, InputTooShort, InvalidSignature};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::secp256k1::schnorr::Tag::Challenge;
use fastcrypto::groups::secp256k1::schnorr::{hash_to_scalar, SchnorrPublicKey};
use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use itertools::Itertools;

pub mod avss;
pub mod batch_avss;
mod bcs;
pub mod certificate;
pub mod complaint;
mod presigning;
pub mod ro_extension;
pub mod si_matrix;

/// The group to use for the signing
pub type G = groups::secp256k1::ProjectivePoint;

/// Default scalar
pub type S = <G as GroupElement>::ScalarType;

/// The group used for multi-recipient encryption
type EG = G1Element;

/// Generate partial threshold Schnorr signatures for a given message using a presigning triple.
///
/// Returns also the public nonce R.
pub fn generate_partial_signatures<const BATCH_SIZE: usize>(
    my_indices: &[ShareIndex],
    message: &[u8],
    presignatures: &mut Presignatures<BATCH_SIZE>,
    my_signing_key_shares: &[S],
    verifying_key: &G,
    beacon_value: &S,
) -> FastCryptoResult<(G, Vec<Eval<S>>)> {
    // One share per weight for this party
    if my_signing_key_shares.len() != my_indices.len() {
        return Err(FastCryptoError::InvalidInput);
    }

    // TODO: Each output from an instance of Presigning has a unique index. Perhaps this is needed for coordination?
    let (_, secret_presigs, public_presig) = presignatures
        .next()
        .ok_or(GeneralError("No more pre-signatures".to_string()))?;

    let r = public_presig + G::generator() * beacon_value;
    let h = hash(&r, verifying_key, message);

    Ok((
        public_presig,
        my_indices
            .iter()
            .zip(my_signing_key_shares)
            .zip(secret_presigs)
            .map(|((index, si), ti)| Eval {
                index: *index,
                value: ti + h * si,
            })
            .collect_vec(),
    ))
}

/// Given enough partial signatures, aggregate them into a full signature and verify it.
pub fn aggregate_signatures(
    message: &[u8],
    public_presig: &G,
    partial_signatures: &[Eval<S>],
    beacon_value: &S,
    threshold: u16,
    vk: &G,
) -> FastCryptoResult<(G, S)> {
    if partial_signatures.len() < threshold as usize {
        return Err(InputTooShort(threshold as usize));
    }

    let r = public_presig + G::generator() * beacon_value;

    let sigma_prime = Poly::recover_c0(
        threshold,
        partial_signatures.iter().take(threshold as usize),
    )?;
    let s = sigma_prime + beacon_value;

    let signature = (r, s);
    verify(vk, &signature, message)?;
    Ok(signature)
}

fn hash(r: &G, vk: &G, message: &[u8]) -> S {
    let vk_bytes = SchnorrPublicKey(*vk).to_byte_array();
    hash_to_scalar(Challenge, [&r.x_as_be_bytes().unwrap(), &vk_bytes, message])
}

// TODO: Use verify from schnorr module
fn verify(vk: &G, signature: &(G, S), message: &[u8]) -> FastCryptoResult<()> {
    let r_prime = G::generator() * signature.1 - vk * hash(&signature.0, vk, message);
    if r_prime == signature.0 {
        Ok(())
    } else {
        Err(InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use crate::polynomial::{Eval, Poly};
    use crate::threshold_schnorr::batch_avss::{ReceiverOutput, ShareBatch, SharesForNode};
    use crate::threshold_schnorr::presigning::Presignatures;
    use crate::threshold_schnorr::{
        aggregate_signatures, generate_partial_signatures, hash, verify, G, S,
    };
    use crate::types::ShareIndex;
    use fastcrypto::groups::{GroupElement, Scalar};
    use fastcrypto::traits::AllowedRng;
    use itertools::Itertools;
    use std::array;

    fn sign(sk: &S, message: &[u8]) -> (G, S) {
        let mut rng = rand::thread_rng();
        let k = S::rand(&mut rng);
        let r = G::generator() * k;
        let h = hash(&r, &(G::generator() * sk), message);
        (r, k + h * sk)
    }

    #[test]
    fn test_mock_signing() {
        let msg = b"Hello, world!";
        let mut rng = rand::thread_rng();
        let sk = S::rand(&mut rng);
        let sig = sign(&sk, msg);
        let vk = G::generator() * sk;
        verify(&vk, &sig, msg).unwrap();
    }

    #[test]
    fn test_signing() {
        let f = 2;
        let t = f + 1;
        let n = 3 * f + 1;

        let mut rng = rand::thread_rng();

        // Mock DKG
        let sk = S::rand(&mut rng);
        let sk_shares = mock_shares(&mut rng, sk, t, n);

        // Mock nonce generation
        const BATCH_SIZE: usize = 10;
        let nonces_for_dealer = (0..n)
            .map(|_| {
                let nonces: [S; BATCH_SIZE] = array::from_fn(|_| S::rand(&mut rng));
                let public_keys = nonces.map(|s| G::generator() * s);
                let nonce_shares: [Vec<S>; BATCH_SIZE] = nonces.map(|nonce| {
                    mock_shares(&mut rng, nonce, t, n)
                        .iter()
                        .map(|s| s.value)
                        .collect_vec()
                });
                (nonces, public_keys, nonce_shares)
            })
            .collect_vec();

        let outputs = (0..n)
            .map(|i| {
                let index = ShareIndex::new(i + 1).unwrap();
                (0..n)
                    .map(|j| {
                        ReceiverOutput {
                            my_shares: SharesForNode {
                                batches: vec![ShareBatch {
                                    index,
                                    shares: array::from_fn(|l| {
                                        nonces_for_dealer[j as usize].2[l][i as usize]
                                    }),
                                    blinding_share: Default::default(), // Not used for this test
                                }],
                            },
                            public_keys: nonces_for_dealer[j as usize].1,
                        }
                    })
                    .collect_vec()
            })
            .collect_vec();

        let mut presigning = outputs
            .iter()
            .enumerate()
            .map(|(i, output)| {
                Presignatures::new(
                    &[ShareIndex::new((i + 1) as u16).unwrap()],
                    output,
                    f as usize,
                )
                .unwrap()
            })
            .collect_vec();

        let vk = G::generator() * sk;
        let message = b"Hello, world!";

        let beacon_value = S::rand(&mut rng);

        let partial_signatures = presigning
            .iter_mut()
            .enumerate()
            .map(|(i, presigning)| {
                generate_partial_signatures(
                    &[ShareIndex::new((i + 1) as u16).unwrap()],
                    message,
                    presigning,
                    &[sk_shares[i].value],
                    &vk,
                    &beacon_value,
                )
                .unwrap()
            })
            .collect_vec();

        assert!(partial_signatures
            .iter()
            .map(|partial_signature| partial_signature.0)
            .all_equal());
        let public = partial_signatures[0].0;

        let signature = aggregate_signatures(
            message,
            &public,
            &partial_signatures
                .iter()
                .flat_map(|(_, sigs)| sigs.clone())
                .collect_vec(),
            &beacon_value,
            t,
            &vk,
        )
        .unwrap();

        verify(&vk, &signature, message).unwrap();
    }

    fn mock_shares(rng: &mut impl AllowedRng, secret: S, t: u16, n: u16) -> Vec<Eval<S>> {
        let p = Poly::rand_fixed_c0(t - 1, secret, rng);
        (1..=n)
            .map(|i| p.eval(ShareIndex::new(i).unwrap()))
            .collect_vec()
    }
}
