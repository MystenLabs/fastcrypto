// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1;
use crate::types::ShareIndex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{Blake2b256, Digest, HashFunction};
use serde::{Deserialize, Serialize};
use tracing::debug;

pub type PartyId = u16;

/// Public parameters of a party.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node<G: GroupElement> {
    pub id: PartyId,
    pub pk: ecies_v1::PublicKey<G>,
    pub weight: u16, // May be zero after reduce()
}

/// Wrapper for a set of nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nodes<G: GroupElement> {
    nodes: Vec<Node<G>>, // Party ids are 0..len(nodes)-1 (inclusive)
    total_weight: u16,   // Share ids are 1..total_weight (inclusive)
    // Next two fields are used to map share ids to party ids.
    accumulated_weights: Vec<u16>, // Accumulated sum of all nodes' weights. Used to map share ids to party ids.
    nodes_with_nonzero_weight: Vec<u16>, // Indexes of nodes with non-zero weight
}

impl<G: GroupElement + Serialize> Nodes<G> {
    // We don't expect to have more than 1000 nodes (simplifies some checks).
    const MAX_NODES: usize = 1000;

    /// Create a new set of nodes. Nodes must have consecutive ids starting from 0.
    pub fn new(nodes: Vec<Node<G>>) -> FastCryptoResult<Self> {
        let mut nodes = nodes;
        nodes.sort_by_key(|n| n.id);
        // Check all ids are consecutive and start from 0
        if (0..nodes.len()).any(|i| (nodes[i].id as usize) != i) {
            return Err(FastCryptoError::InvalidInput);
        }
        // Make sure we never overflow in the functions below.
        if nodes.is_empty() || nodes.len() > Self::MAX_NODES {
            return Err(FastCryptoError::InvalidInput);
        }
        // Make sure we never overflow in the functions below, as we don't expect to have more than u16::MAX total weight.
        let total_weight = nodes.iter().map(|n| n.weight as u32).sum::<u32>();
        if total_weight > u16::MAX as u32 || total_weight == 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        let total_weight = total_weight as u16;

        // We use the next two to map share ids to party ids.
        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let nodes_with_nonzero_weight = Self::filter_nonzero_weights(&nodes);

        Ok(Self {
            nodes,
            total_weight,
            accumulated_weights,
            nodes_with_nonzero_weight,
        })
    }

    fn filter_nonzero_weights(nodes: &[Node<G>]) -> Vec<u16> {
        nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| if n.weight > 0 { Some(i as u16) } else { None })
            .collect::<Vec<_>>()
    }

    fn get_accumulated_weights(nodes: &[Node<G>]) -> Vec<u16> {
        nodes
            .iter()
            .filter_map(|n| if n.weight > 0 { Some(n.weight) } else { None })
            .scan(0, |accumulated_weight, weight| {
                *accumulated_weight += weight;
                Some(*accumulated_weight)
            })
            .collect::<Vec<_>>()
    }

    /// Total weight of the nodes.
    pub fn total_weight(&self) -> u16 {
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
        let nonzero_node_id = self
            .accumulated_weights
            .binary_search(&share_id.get())
            .unwrap_or_else(|i| i);
        match self.nodes_with_nonzero_weight.get(nonzero_node_id) {
            Some(node_id) => self.node_id_to_node(*node_id),
            None => Err(FastCryptoError::InvalidInput),
        }
    }

    pub fn node_id_to_node(&self, party_id: PartyId) -> FastCryptoResult<&Node<G>> {
        self.nodes
            .get(party_id as usize)
            .ok_or(FastCryptoError::InvalidInput)
    }

    /// Get the share ids of a node (ordered). Returns error if the node does not exist.
    pub fn share_ids_of(&self, id: PartyId) -> FastCryptoResult<Vec<ShareIndex>> {
        // Check if the input is valid.
        self.node_id_to_node(id)?;

        // TODO: [perf opt] Cache this or impl differently.
        Ok(self
            .share_ids_iter()
            .filter(|share_id| self.share_id_to_node(share_id).expect("valid share id").id == id)
            .collect::<Vec<_>>())
    }

    /// Get an iterator on the nodes.
    pub fn iter(&self) -> impl Iterator<Item = &Node<G>> {
        self.nodes.iter()
    }

    // Used for logging.
    pub fn hash(&self) -> Digest<32> {
        let mut hash = Blake2b256::default();
        hash.update(bcs::to_bytes(&self.nodes).expect("should serialize"));
        hash.finalize()
    }

    /// Create a new set of nodes. Nodes must have consecutive ids starting from 0.
    /// Reduces weights up to an allowed delta in the original total weight.
    /// Finds the largest d such that:
    /// - The new threshold is ceil(t / d)
    /// - The new weights are all divided by d (floor division)
    /// - The precision loss, counted as the sum of the remainders of the division by d, is at most
    ///   the allowed delta
    ///
    /// In practice, allowed delta will be the extra liveness we would assume above 2f+1.
    ///
    /// total_weight_lower_bound allows limiting the level of reduction (e.g., in benchmarks). To
    /// get the best results, set it to 1.
    pub fn new_reduced(
        nodes_vec: Vec<Node<G>>,
        t: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<(Self, u16)> {
        let n = Self::new(nodes_vec)?; // checks the input, etc
        assert!(total_weight_lower_bound <= n.total_weight && total_weight_lower_bound > 0);
        let mut max_d = 1;
        for d in 2..=40 {
            // Break if we reached the lower bound.
            // U16 is safe here since total_weight is u16.
            let new_total_weight = n.nodes.iter().map(|n| n.weight / d).sum::<u16>();
            if new_total_weight < total_weight_lower_bound {
                break;
            }
            // Compute the precision loss.
            // U16 is safe here since total_weight is u16.
            let delta = n.nodes.iter().map(|n| n.weight % d).sum::<u16>();
            if delta <= allowed_delta {
                max_d = d;
            }
        }
        debug!(
            "Nodes::reduce reducing from {} with max_d {}, allowed_delta {}, total_weight_lower_bound {}",
            n.total_weight, max_d, allowed_delta, total_weight_lower_bound
        );

        let nodes = n
            .nodes
            .iter()
            .map(|n| Node {
                id: n.id,
                pk: n.pk.clone(),
                weight: n.weight / max_d,
            })
            .collect::<Vec<_>>();
        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let nodes_with_nonzero_weight = Self::filter_nonzero_weights(&nodes);
        // U16 is safe here since the original total_weight is u16.
        let total_weight = nodes.iter().map(|n| n.weight).sum::<u16>();
        let new_t = t / max_d + (t % max_d != 0) as u16;
        Ok((
            Self {
                nodes,
                total_weight,
                accumulated_weights,
                nodes_with_nonzero_weight,
            },
            new_t,
        ))
    }
}
