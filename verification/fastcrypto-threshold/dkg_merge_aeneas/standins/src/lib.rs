// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The verified functions of the DKG (`Party::merge`, `UsedProcessedMessages::from` and
//! `Nodes::node_id_to_node`), compiled against stand-ins for the DKG types so that Charon and
//! Aeneas can translate them to Lean. The code of the functions is the production code: `build.rs`
//! copies it from `fastcrypto-threshold/src` (see `verified_regions.rs` below).
//!
//! Aeneas can't translate fastcrypto's `GroupElement` trait, because it refers to the `Scalar`
//! trait and back. The verified functions don't use the group operations, so the stand-ins have
//! the same fields as the production types, except that they drop the `GroupElement` bounds and
//! replace the fields the verified functions don't read with fields of the generic types `G` and
//! `EG`. See the README.
#![allow(dead_code)]

use fastcrypto::error::{FastCryptoError, FastCryptoResult};

/// Aeneas can't translate what the `tracing` macros expand to, so logging is a no-op here and its
/// arguments are not evaluated.
macro_rules! no_logging {
    ($($arg:tt)*) => {
        ()
    };
}
use no_logging as debug;
use no_logging as error;
use no_logging as info;

pub type PartyId = u16;

/// Stand-in for `fastcrypto_threshold::nodes::Node`.
pub struct Node<G> {
    pub id: PartyId,
    /// Stands in for the ECIES public key.
    pub pk: G,
    pub weight: u16,
}

/// Stand-in for `fastcrypto_threshold::nodes::Nodes`, without the fields that are derived from
/// `nodes`.
pub struct Nodes<G> {
    nodes: Vec<Node<G>>,
}

/// Stand-in for `fastcrypto_threshold::dkg_v1::Message`.
#[derive(Clone)]
pub struct Message<G, EG> {
    pub sender: PartyId,
    /// Stands in for the commitment of the secret polynomial.
    pub vss_pk: G,
    /// Stands in for the encrypted shares.
    pub encrypted_shares: EG,
}

/// Stand-in for `fastcrypto_threshold::dkg_v1::Complaint`.
#[derive(Clone)]
pub struct Complaint<EG> {
    pub accused_sender: PartyId,
    /// Stands in for the recovery package.
    pub proof: EG,
}

/// Stand-in for `fastcrypto_threshold::dkg_v1::ProcessedMessage`.
#[derive(Clone)]
pub struct ProcessedMessage<G, EG> {
    pub message: Message<G, EG>,
    /// Stands in for the shares.
    pub shares: Vec<G>,
    pub complaint: Option<Complaint<EG>>,
}

/// Stand-in for `fastcrypto_threshold::dkg_v1::UsedProcessedMessages`.
pub struct UsedProcessedMessages<G, EG>(pub Vec<ProcessedMessage<G, EG>>);

/// Stand-in for `fastcrypto_threshold::dkg_v1::Confirmation`.
pub struct Confirmation<EG> {
    pub sender: PartyId,
    pub complaints: Vec<Complaint<EG>>,
}

/// Stand-in for `fastcrypto_threshold::dkg_v1::Party`, without the random oracle.
pub struct Party<G, EG> {
    pub id: PartyId,
    nodes: Nodes<EG>,
    pub t: u16,
    /// Stands in for the ECIES private key.
    enc_sk: EG,
    /// Stands in for the secret polynomial.
    vss_sk: G,
    pub old_t: Option<u16>,
}

// The production code of the verified functions, in impl blocks for the stand-ins.
include!(concat!(env!("OUT_DIR"), "/verified_regions.rs"));
