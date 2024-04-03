// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use fastcrypto::groups::{GroupElement, Pairing};
use serde::Deserialize;

pub mod api;
mod prepared_vk;

#[derive(Debug, Deserialize)]
pub struct Proof<G1: Pairing>
where
    G1::Other: Debug,
{
    a: G1,
    b: G1::Other,
    c: G1,
}

#[derive(Debug, Deserialize)]
pub struct VerifyingKey<G1: Pairing>
where
    G1::Other: Debug,
{
    alpha: G1,
    beta: G1::Other,
    gamma: G1::Other,
    delta: G1::Other,
    gamma_abc: Vec<G1>,
}

/// This is a helper function to store a pre-processed version of the verifying key.
/// This is roughly homologous to [`ark_groth16::data_structures::PreparedVerifyingKey`].
/// Note that contrary to Arkworks, we don't store a "prepared" version of the `gamma_neg` and
/// `delta_neg` fields because they are very large and unpractical to use in the binary API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedVerifyingKey<G1>
where
    G1: Pairing,
    <G1 as Pairing>::Output: Clone + Debug + PartialEq + Eq,
{
    /// The element vk.gamma_abc,
    /// aka the `[gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * G]`, where i spans the public inputs
    vk_gamma_abc: Vec<G1>,

    /// The element `e(alpha * G, beta * H)` in `GT`.
    alpha_beta: <G1 as Pairing>::Output,

    /// The element `- gamma * H` in `G2`, for use in pairings.
    gamma_neg: <G1 as Pairing>::Other,

    /// The element `- delta * H` in `G2`, for use in pairings.
    delta_neg: <G1 as Pairing>::Other,
}

impl<G1> From<&VerifyingKey<G1>> for PreparedVerifyingKey<G1>
where
    G1: Pairing,
    <G1 as Pairing>::Output: GroupElement,
{
    fn from(vk: &VerifyingKey<G1>) -> Self {
        PreparedVerifyingKey {
            vk_gamma_abc: vk.gamma_abc.clone(),
            alpha_beta: vk.alpha.pairing(&vk.beta),
            gamma_neg: -vk.gamma,
            delta_neg: -vk.delta,
        }
    }
}
