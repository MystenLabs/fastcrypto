// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{Blake2b256, Digest, HashFunction};
use serde::{Deserialize, Serialize};

pub type PartyId = u16;

/// Public parameters of a party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node<G: GroupElement> {
    pub id: PartyId,
    pub pk: ecies::PublicKey<G>,
    pub weight: u16,
}

/// Wrapper for a set of nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nodes<G: GroupElement> {
    nodes: Vec<Node<G>>,           // Party ids are 0..len(nodes)-1
    total_weight: u32,             // Share ids are 1..total_weight
    accumulated_weights: Vec<u32>, // Accumulated sum of all nodes' weights. Used to map share ids to party ids.
}

impl<G: GroupElement + Serialize> Nodes<G> {
    /// Create a new set of nodes. Nodes must have consecutive ids starting from 0.
    pub fn new(nodes: Vec<Node<G>>) -> FastCryptoResult<Self> {
        let mut nodes = nodes;
        nodes.sort_by_key(|n| n.id);
        // Check all ids are consecutive and start from 0
        if (0..nodes.len()).any(|i| (nodes[i].id as usize) != i) {
            return Err(FastCryptoError::InvalidInput);
        }
        // Make sure we never overflow, as we don't expect to have more than 1000 nodes
        if nodes.is_empty() || nodes.len() > 1000 {
            return Err(FastCryptoError::InvalidInput);
        }
        // Check that all weights are non-zero
        if nodes.iter().any(|n| n.weight == 0) {
            return Err(FastCryptoError::InvalidInput);
        }

        // We use accumulated weights to map share ids to party ids.
        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let total_weight = *accumulated_weights
            .last()
            .expect("Number of nodes is non-zero");

        Ok(Self {
            nodes,
            total_weight,
            accumulated_weights,
        })
    }

    fn get_accumulated_weights(nodes: &[Node<G>]) -> Vec<u32> {
        nodes
            .iter()
            .map(|n| n.weight as u32)
            .scan(0, |accumulated_weight, weight| {
                *accumulated_weight += weight;
                Some(*accumulated_weight)
            })
            .collect::<Vec<_>>()
    }

    /// Total weight of the nodes.
    pub fn total_weight(&self) -> u32 {
        self.total_weight
    }

    /// Number of nodes.
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Get an iterator on the share ids.
    pub fn share_ids_iter(&self) -> impl Iterator<Item = ShareIndex> {
        (1..=self.total_weight).map(|i| ShareIndex::new(i).expect("nonzero"))
    }

    /// Get the node corresponding to a share id.
    pub fn share_id_to_node(&self, share_id: &ShareIndex) -> FastCryptoResult<&Node<G>> {
        let node_id: PartyId = match self.accumulated_weights.binary_search(&share_id.get()) {
            Ok(i) => i,
            Err(i) => i,
        }
        .try_into()
        .map_err(|_| InvalidInput)?;
        self.node_id_to_node(node_id)
    }

    pub fn node_id_to_node(&self, party_id: PartyId) -> FastCryptoResult<&Node<G>> {
        if party_id as usize >= self.nodes.len() {
            Err(InvalidInput)
        } else {
            Ok(&self.nodes[party_id as usize])
        }
    }

    /// Get the share ids of a node.
    pub fn share_ids_of(&self, id: PartyId) -> Vec<ShareIndex> {
        // TODO: [perf opt] Cache this
        self.share_ids_iter()
            .filter(|node_id| self.share_id_to_node(node_id).expect("valid ids").id == id)
            .collect::<Vec<_>>()
    }

    /// Get an iterator on the nodes.
    pub fn iter(&self) -> impl Iterator<Item = &Node<G>> {
        self.nodes.iter()
    }

    pub fn hash(&self) -> Digest<32> {
        let mut hash = Blake2b256::default();
        hash.update(bcs::to_bytes(&self.nodes).expect("should serialize"));
        hash.finalize()
    }

    /// Reduce weights up to an allowed delta in the original total weight.
    /// Finds the largest d such that:
    /// - The new threshold is ceil(t / d)
    /// - The new weights are all divided by d (floor division)
    /// - The precision loss, counted as the sum of the remainders of the division by d, is at most
    ///   the allowed delta
    /// In practice, allowed delta will be the extra liveness we would assume above 2f+1.
    pub fn reduce(&self, t: u16, allowed_delta: u16) -> (Self, u16) {
        let mut max_d = 1;
        for d in 2..=40 {
            // TODO: [perf] Remove once the DKG & Nodes can work with zero weights.
            if self.nodes.iter().any(|n| n.weight < d) {
                break;
            }
            let sum = self.nodes.iter().map(|n| n.weight % d).sum::<u16>();
            if sum <= allowed_delta {
                max_d = d;
            }
        }
        let nodes = self
            .nodes
            .iter()
            .map(|n| Node {
                id: n.id,
                pk: n.pk.clone(),
                weight: n.weight / max_d,
            })
            .collect::<Vec<_>>();
        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let total_weight = nodes.iter().map(|n| n.weight as u32).sum::<u32>();
        let new_t = t / max_d + (t % max_d != 0) as u16;
        (
            Self {
                nodes,
                total_weight,
                accumulated_weights,
            },
            new_t,
        )
    }
}
