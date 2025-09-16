// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::threshold_schnorr::batch_avss::ReceiverOutput;
use crate::threshold_schnorr::si_matrix::PascalMatrix;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InputTooShort, InvalidInput};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
use itertools::Itertools;
use serde::Serialize;
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

/// One output per index
pub struct PresigningOutput {
    pub index: ShareIndex,
    pub private: Vec<Vec<S>>,
    pub public: Vec<Vec<G>>,
}

/// One output per weight
pub fn presigning<const BATCH_SIZE: usize>(
    my_id: &PartyId,
    nodes: &Nodes<EG>,
    receiver_outputs: BTreeMap<PartyId, ReceiverOutput<BATCH_SIZE>>, // Dealer -> output
    f: u16,
) -> FastCryptoResult<Vec<PresigningOutput>> {
    let J = nodes.total_weight_of(receiver_outputs.keys())?;
    if J < 2 * f + 1 {
        return Err(InvalidInput);
    }

    let total_weight = nodes.total_weight();
    let matrix = PascalMatrix::new(total_weight as usize, J as usize);
    let my_indices = nodes.share_ids_of(*my_id)?;
    let my_weight = nodes.total_weight_of(once(my_id))?;

    // This has dimensions L x J x W where W is my weight
    let all_my_shares = (0..BATCH_SIZE)
        .map(|l| {
            receiver_outputs
                .values()
                .map(|output| {
                    output
                        .my_shares
                        .shares_for_secret(l)
                        .unwrap()
                        .map(|eval| eval.value)
                        .collect_vec()
                })
                .collect_vec()
        })
        .collect_vec();
    let all_public_keys = (0..BATCH_SIZE)
        .map(|l| {
            receiver_outputs
                .values()
                .map(|output| output.public_keys[l])
                .collect_vec()
        })
        .collect_vec();

    Ok((0..my_weight)
        .map(|w| {
            let private = (0..BATCH_SIZE)
                .map(|l| {
                    matrix.vector_mul(
                        &(0..J)
                            .map(|j| all_my_shares[l][j as usize][w as usize])
                            .collect_vec(),
                    )
                })
                .collect_vec();
            let public = (0..BATCH_SIZE)
                .map(|l| matrix.vector_mul(&all_public_keys[l]))
                .collect_vec();
            PresigningOutput {
                private,
                public,
                index: my_indices[w as usize],
            }
        })
        .collect_vec())
}

/// Injective map between indices [0..height*width) and coordinates [0..height)x[0..width).
fn matrix_coordinate(
    height: usize,
    width: usize,
    index: usize,
) -> FastCryptoResult<(usize, usize)> {
    if index > height * width {
        return Err(InvalidInput);
    }
    Ok((index / width, index % width))
}

pub fn signature_generation<G: GroupElement + Serialize>(
    index: ShareIndex,
    beacon_value: &G::ScalarType,
    public: &[Vec<G>],
    private: &[Vec<G::ScalarType>],
    message: (usize, &[u8]),
    vk: &[u8],
    random_oracle: &RandomOracle,
) -> FastCryptoResult<Eval<G::ScalarType>>
where
    G::ScalarType: FiatShamirChallenge,
{
    let (l, j) = matrix_coordinate(public.len(), public[0].len(), message.0)?;
    let R = public[l][j] + G::generator() * beacon_value;
    let sigma = private[l][j]
        + random_oracle.evaluate_to_group_element::<G::ScalarType, _>(&(message.1, &R, vk));
    Ok(Eval {
        index,
        value: sigma,
    })
}

pub fn signature_aggregation<G: GroupElement>(
    beacon_value: &G::ScalarType,
    public: &[Vec<G>],
    partial_signatures: &[Eval<G::ScalarType>],
    message: (usize, &[u8]),
    threshold: usize,
) -> FastCryptoResult<(G, G::ScalarType)> {
    if partial_signatures.len() < threshold {
        return Err(InputTooShort(threshold));
    }

    let (l, j) = matrix_coordinate(public.len(), public[0].len(), message.0)?;
    let R = public[l][j] + G::generator() * beacon_value;

    let sigma = Poly::recover_c0(threshold as u16, partial_signatures.iter())?;

    // TODO: Unhappy path

    Ok((R, sigma + beacon_value))
}
