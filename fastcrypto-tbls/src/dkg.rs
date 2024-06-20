// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Some of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::ecies;
use crate::ecies::RecoveryPackage;
use crate::nodes::{Nodes, PartyId};
use crate::polynomial::{Poly, PrivatePoly};
use crate::random_oracle::RandomOracle;
use crate::tbls::Share;
use fastcrypto::groups::GroupElement;
use serde::{Deserialize, Serialize};

/// Generics below use `G: GroupElement' for the group of the VSS public key, and `EG: GroupElement'
/// for the group of the ECIES public key.

/// Party in the DKG protocol.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party<G: GroupElement, EG: GroupElement> {
    pub id: PartyId,
    pub(crate) nodes: Nodes<EG>,
    pub t: u16,
    pub random_oracle: RandomOracle,
    pub(crate) enc_sk: ecies::PrivateKey<EG>,
    pub(crate) vss_sk: PrivatePoly<G>,
}

/// Assumptions:
/// - The high-level protocol is responsible for verifying that the 'sender' is correct in the
///   following messages (based on the chain's authentication).
/// - The high-level protocol is responsible that all parties see the same order of messages.

/// A complaint/fraud claim against a dealer that created invalid encrypted share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Complaint<EG: GroupElement> {
    pub(crate) accused_sender: PartyId,
    pub(crate) proof: RecoveryPackage<EG>,
}

// Upper bound on the size of binary serialized incoming messages assuming <=3333 shares, <=400
// parties, and using G2Element for encryption. This is a safe upper bound since:
// - Message is O(96*t + 32*n) bytes.
// - Confirmation is O((96*3 + 32) * k) bytes.
// Could be used as a sanity safety check before deserializing an incoming message.
pub const DKG_MESSAGES_MAX_SIZE: usize = 400_000; // 400 KB

/// [Output] is the final output of the DKG protocol in case it runs
/// successfully. It can be used later with [ThresholdBls], see examples in tests.
///
/// If shares is None, the object can only be used for verifying (partial and full) signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output<G: GroupElement, EG: GroupElement> {
    pub nodes: Nodes<EG>,
    pub vss_pk: Poly<G>,
    pub shares: Option<Vec<Share<G::ScalarType>>>, // None if some shares are missing or weight is zero.
}
