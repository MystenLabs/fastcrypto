// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::hashi::avss::ReceiverOutput;
use crate::hashi::si_matrix::PascalMatrix;
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Eval, Poly};
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::{InputTooShort, InvalidInput};
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
use itertools::Itertools;
use serde::Serialize;
use std::collections::BTreeMap;
use std::iter::once;

pub mod avss;
mod bcs;
mod certificate;
pub(crate) mod complaint;
pub mod dkg;
mod ro_extension;
pub mod si_matrix;

/// One output per index
pub struct PresigningOutput<G: GroupElement> {
    pub index: ShareIndex,
    pub private: Vec<Vec<G::ScalarType>>,
    pub public: Vec<Vec<G>>,
}

/// One output per weight
pub fn presigning<G: GroupElement, EG: GroupElement + Serialize>(
    my_id: &PartyId,
    nodes: &Nodes<EG>,
    receiver_outputs: BTreeMap<PartyId, ReceiverOutput<G>>, // Dealer -> output
    batch_size: usize,
    f: u16,
) -> FastCryptoResult<Vec<PresigningOutput<G>>> {
    let J = nodes.total_weight_of(receiver_outputs.keys())?;
    if J < 2 * f + 1 {
        return Err(InvalidInput);
    }

    let total_weight = nodes.total_weight();
    let matrix = PascalMatrix::new(total_weight as usize, J as usize);
    let my_indices = nodes.share_ids_of(*my_id)?;
    let my_weight = nodes.total_weight_of(once(my_id))?;

    // This has dimensions L x J x W where W is my weight
    let all_my_shares = (0..batch_size)
        .map(|l| {
            receiver_outputs
                .values()
                .map(|output| {
                    output
                        .my_shares
                        .shares_for_secret(l)
                        .unwrap()
                        .iter()
                        .map(|eval| eval.value)
                        .collect_vec()
                })
                .collect_vec()
        })
        .collect_vec();
    let all_public_keys = (0..batch_size)
        .map(|l| {
            receiver_outputs
                .values()
                .map(|output| output.public_keys[l])
                .collect_vec()
        })
        .collect_vec();

    Ok((0..my_weight)
        .map(|w| {
            let private = (0..batch_size)
                .map(|l| {
                    matrix.vector_mul(
                        &(0..J)
                            .map(|j| all_my_shares[l][j as usize][w as usize])
                            .collect_vec(),
                    )
                })
                .collect_vec();
            let public = (0..batch_size)
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
    let sigma = private[l][j] + hash(random_oracle, message.1, &R, vk);
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

fn hash<G: GroupElement + Serialize>(
    random_oracle: &RandomOracle,
    message: &[u8],
    r: &G,
    vk: &[u8],
) -> G::ScalarType
where
    G::ScalarType: FiatShamirChallenge,
{
    let output = random_oracle.evaluate(&(message, r, vk));
    G::ScalarType::fiat_shamir_reduction_to_group_element(&output)
}
