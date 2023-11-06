// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{Blake2b256, Digest, HashFunction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type PartyId = u16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node<G: GroupElement> {
    pub id: PartyId,
    pub pk: ecies::PublicKey<G>,
    pub weight: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nodes<G: GroupElement> {
    nodes: Vec<Node<G>>, // Party ids are 0..len(nodes)-1
    n: u32,              // Share ids are 1..n
    share_id_to_party_id: HashMap<ShareIndex, PartyId>,
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
        if nodes.len() > 1000 {
            return Err(FastCryptoError::InvalidInput);
        }
        // Get the total weight of the nodes
        let n = nodes.iter().map(|n| n.weight as u32).sum::<u32>();

        let share_id_to_party_id = Self::get_share_id_to_party_id(&nodes);

        Ok(Self {
            nodes,
            n,
            share_id_to_party_id,
        })
    }

    fn get_share_id_to_party_id(nodes: &Vec<Node<G>>) -> HashMap<ShareIndex, PartyId> {
        let mut curr_share_id = 1;
        let mut share_id_to_party_id = HashMap::new();
        for n in nodes {
            for _ in 1..=n.weight {
                let share_id = ShareIndex::new(curr_share_id).expect("nonzero");
                share_id_to_party_id.insert(share_id, n.id);
                curr_share_id += 1;
            }
        }
        share_id_to_party_id
    }

    /// Total weight of the nodes.
    pub fn n(&self) -> u32 {
        self.n
    }

    /// Number of nodes.
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Get an iterator on the share ids.
    pub fn share_ids_iter(&self) -> impl Iterator<Item = ShareIndex> {
        (1..=self.n).map(|i| ShareIndex::new(i).expect("nonzero"))
    }

    /// Get the node corresponding to a share id.
    pub fn share_id_to_node(&self, share_id: &ShareIndex) -> FastCryptoResult<&Node<G>> {
        self.share_id_to_party_id
            .get(share_id)
            .map(|id| self.node_id_to_node(*id))
            .ok_or(FastCryptoError::InvalidInput)?
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
        let share_id_to_party_id = Self::get_share_id_to_party_id(&nodes);
        let n = nodes.iter().map(|n| n.weight as u32).sum::<u32>();
        let new_t = t / max_d + (t % max_d != 0) as u16;
        (
            Self {
                nodes,
                n,
                share_id_to_party_id,
            },
            new_t,
        )
    }
}
