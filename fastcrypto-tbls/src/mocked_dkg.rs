// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::dkg::Output;
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::PrivatePoly;
use fastcrypto::groups::GroupElement;
use serde::Serialize;

/// Emulates the output of an insecure DKG protocol (to be used in tests).
pub fn generate_mocked_output<G: GroupElement + Serialize, EG: GroupElement + Serialize>(
    nodes: Nodes<EG>,
    t: u32,
    full_private_key: u128,
    party: PartyId,
) -> Output<G, EG> {
    let mut coefficients: Vec<G::ScalarType> = (0..t)
        .map(|i| G::ScalarType::from((i + 1) as u128))
        .collect();
    *coefficients.get_mut(0).unwrap() = G::ScalarType::from(full_private_key);

    let poly = PrivatePoly::<G::ScalarType>::from(coefficients);
    let vss_pk = poly.commit();

    let shares = nodes
        .share_ids_of(party)
        .iter()
        .map(|sid| poly.eval(*sid))
        .collect();

    Output {
        nodes,
        vss_pk,
        shares: Some(shares),
    }
}
