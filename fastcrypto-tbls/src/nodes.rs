// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies;
use crate::types::ShareIndex;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::GroupElement;
use std::collections::HashSet;
use std::iter::Map;
use std::ops::RangeInclusive;

pub type PartyId = u16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node<G: GroupElement> {
    pub id: PartyId,
    pub pk: ecies::PublicKey<G>,
    pub weight: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nodes<G: GroupElement> {
    nodes: Vec<Node<G>>,
    n: u32, // share ids are 1..n
}

impl<G: GroupElement> Nodes<G> {
    /// Create a new set of nodes.
    pub fn new(nodes: Vec<Node<G>>) -> FastCryptoResult<Self> {
        let mut nodes = nodes;
        nodes.sort_by_key(|n| n.id);
        // Check all ids are consecutive and start from 0
        if (0..nodes.len()).any(|i| (nodes[i].id as usize) != i) {
            return Err(FastCryptoError::InvalidInput);
        }
        // Get the total weight of the nodes
        let n = nodes.iter().map(|n| n.weight as u32).sum::<u32>();
        Ok(Self { nodes, n })
    }

    /// Total weight of the nodes.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// Get an iterator on the share ids.
    pub fn share_ids_iter(&self) -> Map<RangeInclusive<u32>, fn(u32) -> ShareIndex> {
        (1..=self.n).map(|i| ShareIndex::new(i).expect("nonzero"))
    }

    /// Get the node corresponding to a share id.
    pub fn share_id_to_node(&self, share_id: &ShareIndex) -> FastCryptoResult<&Node<G>> {
        // TODO: [perf opt] Cache this
        let mut curr_share_id = 1;
        for n in &self.nodes {
            if curr_share_id <= share_id.get() && share_id.get() < curr_share_id + (n.weight as u32)
            {
                return Ok(n);
            }
            curr_share_id += n.weight as u32;
        }
        Err(FastCryptoError::InvalidInput)
    }

    /// Get the share ids of a node.
    pub fn share_ids_of(&self, id: PartyId) -> HashSet<ShareIndex> {
        // TODO: [perf opt] Cache this
        self.share_ids_iter()
            .filter(|node_id| self.share_id_to_node(node_id).expect("valid ids").id == id)
            .collect::<HashSet<_>>()
    }

    /// Get an iterator on the nodes.
    pub fn iter(&self) -> impl Iterator<Item = &Node<G>> {
        self.nodes.iter()
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
        for d in 2..=50 {
            let sum = self.nodes.iter().map(|n| n.weight % d).sum::<u16>();
            if sum <= allowed_delta {
                max_d = d;
            } else {
                break;
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
        let n = nodes.iter().map(|n| n.weight as u32).sum::<u32>();
        let new_t = t / max_d + (t % max_d != 0) as u16;
        (Self { nodes, n }, new_t)
    }
}
