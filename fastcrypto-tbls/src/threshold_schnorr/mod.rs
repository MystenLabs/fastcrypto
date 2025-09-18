// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::batch_avss::ReceiverOutput;
use crate::threshold_schnorr::si_matrix::LazyPascalMatrixMultiplier;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{
    InputTooShort, InvalidInput, InvalidSignature, NotEnoughInputs,
};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::secp256k1::schnorr::Tag::Challenge;
use fastcrypto::groups::secp256k1::schnorr::{
    hash_to_scalar, SchnorrPrivateKey, SchnorrPublicKey, SchnorrSignature,
};
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, Scalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::Serialize;
use std::array;
use std::collections::BTreeMap;
use std::iter::once;

pub mod avss;
pub mod batch_avss;
mod bcs;
pub mod certificate;
pub mod complaint;
pub mod ro_extension;
pub mod si_matrix;

/// The group to use for the signing
pub type G = groups::secp256k1::ProjectivePoint;

/// Default scalar
pub type S = <G as GroupElement>::ScalarType;

/// The group used for multi-recipient encryption
type EG = G1Element;

/// An iterator that yields presigning tuples (i, t_i, p_i).
pub struct Presigning<const BATCH_SIZE: usize> {
    secret: Vec<LazyPascalMatrixMultiplier<S>>,
    public: LazyPascalMatrixMultiplier<G>,
    index: usize,
}

impl<const BATCH_SIZE: usize> Iterator for Presigning<BATCH_SIZE> {
    type Item = (usize, Vec<S>, G);

    fn next(&mut self) -> Option<Self::Item> {
        let secret = self
            .secret
            .iter_mut()
            .map(Iterator::next)
            .collect::<Option<Vec<_>>>();
        let public = self.public.next();

        match (secret, public) {
            (Some(s), Some(p)) => {
                self.index += 1;
                Some((self.index, s, p))
            }
            _ => None,
        }
    }
}

impl<const BATCH_SIZE: usize> Presigning<BATCH_SIZE> {
    /// Based on the output if a batched AVSS from multiple dealers, complete the presigning.
    ///
    /// The resulting iterator can give
    pub fn new(
        my_indices: &[ShareIndex],
        avss_outputs: &[ReceiverOutput<BATCH_SIZE>],
        f: usize,
    ) -> FastCryptoResult<Self> {
        if avss_outputs.len() < 2 * f + 1 {
            return Err(InputTooShort(2 * f + 1));
        }
        let M = avss_outputs.len() - f;

        // There is one secret presigning output per weight for this party.
        let secret = my_indices
            .iter()
            .enumerate()
            .map(|(i, _index)| {
                let rho = avss_outputs
                    .iter()
                    .map(|output| output.my_shares.batches[i].shares.to_vec())
                    .collect();
                LazyPascalMatrixMultiplier::new(M, rho)
            })
            .collect_vec();

        let public = LazyPascalMatrixMultiplier::new(
            M,
            avss_outputs
                .iter()
                .map(|output| output.public_keys.to_vec())
                .collect(),
        );

        assert_eq!(secret[0].remaining(), public.remaining());

        Ok(Self {
            secret,
            public,
            index: 0,
        })
    }

    pub fn remaining(&self) -> usize {
        // The public and secret iterators has the same number of elements
        self.public.remaining()
    }
}

/// Generate partial threshold Schnorr signatures for a given message using a presigning triple.
///
/// Return
pub fn signature_generation<const BATCH_SIZE: usize>(
    my_indices: &[ShareIndex],
    message: &[u8],
    presigning: &mut Presigning<BATCH_SIZE>,
    signing_key_shares: &[S],
    vk: &G,
    beacon_value: &S,
) -> FastCryptoResult<(G, Vec<Eval<S>>)> {
    // One share per weight for this party
    let my_weight = my_indices.len();
    assert_eq!(signing_key_shares.len(), my_weight);

    // TODO: Each output from an instance of Presigning has a unique index. Perhaps this is needed for coordination?
    let (_, t, p) = presigning.next().ok_or(NotEnoughInputs)?;

    let r = p + G::generator() * beacon_value;
    let h = hash(&r, &vk, message);

    Ok((
        p,
        my_indices
            .into_iter()
            .zip(signing_key_shares)
            .zip(t)
            .map(|((index, si), ti)| Eval {
                index: *index,
                value: ti + h * si,
            })
            .collect_vec(),
    ))
}

pub fn signature_aggregation(
    message: &[u8],
    public: &G,
    partial_signatures: &[Eval<S>],
    beacon_value: &S,
    threshold: u16,
    vk: &G,
) -> FastCryptoResult<(G, S)> {
    let r = public + G::generator() * beacon_value;

    let sigma_prime = Poly::recover_c0(
        threshold,
        partial_signatures.iter().take(threshold as usize),
    )?;
    let s = sigma_prime + beacon_value;

    let signature = (r, s);
    verify(&vk, &signature, message)?;
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
        .map(|i| {
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
                        my_shares: batch_avss::SharesForNode {
                            batches: vec![batch_avss::ShareBatch {
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
            Presigning::new(
                &[ShareIndex::new((i + 1) as u16).unwrap()],
                &output,
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
            signature_generation(
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

    let signature = signature_aggregation(
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

#[cfg(test)]
fn mock_shares(rng: &mut impl AllowedRng, secret: S, t: u16, n: u16) -> Vec<Eval<S>> {
    let p = Poly::rand_fixed_c0(t - 1, secret, rng);
    (1..=n)
        .map(|i| p.eval(ShareIndex::new(i).unwrap()))
        .collect()
}
