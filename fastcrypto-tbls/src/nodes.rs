// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1;
use crate::types::ShareIndex;
use crate::weight_reduction::solve;
use crate::weight_reduction::weight_reduction_checks::compute_precision_loss;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{Blake2b256, Digest, HashFunction};
use itertools::Itertools;
use num_rational::Ratio;
use serde::{Deserialize, Serialize};
use tracing::debug;

pub type PartyId = u16;

/// Best super_swiper candidate: reduced total weight W', per-party weights, precision loss δ, divisor d.
type SuperSwiperBest = (u64, Vec<u16>, Ratio<u64>, Ratio<u64>);

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

    /// Total weight of a subset of the parties. Returns error if any party does not exist.
    pub fn total_weight_of<'a>(
        &self,
        ids: impl Iterator<Item = &'a PartyId>,
    ) -> FastCryptoResult<u16> {
        ids.map(|id| self.weight_of(*id)).sum()
    }

    pub fn weight_of(&self, id: PartyId) -> FastCryptoResult<u16> {
        Ok(self.node_id_to_node(id)?.weight)
    }

    /// Number of nodes.
    pub fn num_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Get an iterator on the share ids.
    pub fn share_ids_iter(&self) -> impl Iterator<Item = ShareIndex> {
        (1..=self.total_weight).map(|i| ShareIndex::new(i).expect("nonzero"))
    }

    /// Get an iterator on the node ids.
    pub fn node_ids_iter(&self) -> impl Iterator<Item = PartyId> + '_ {
        self.nodes.iter().map(|n| n.id)
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
            // TODO: The reduction delta should be estimated here as it is done in `new_reduced_with_f`.
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
        let new_t = t.div_ceil(max_d);
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

    /// Create a new set of nodes using the super_swiper algorithm for weight reduction.
    ///
    /// Algorithm:
    /// 1. Outer loop: α from 0.10 to 0.90 in steps of 1/100. Inner loop: β from α + 0.01 to α + 0.20
    ///    in steps of 1/100 (skip β ≥ 1). Pass each (α, β) to [`solve`](crate::weight_reduction::solve).
    ///    Among pairs with 2·δ ≤ allowed_delta, W' ≥ total_weight_lower_bound, and β > α, keep the
    ///    reduction with smallest W' (tie-break: smaller δ when W' is equal).
    /// 2. Set t' = (t + δ)/d.
    ///
    /// # Parameters
    /// - `nodes_vec`: Input nodes with weights
    /// - `t`: Threshold
    /// - `allowed_delta`: Used in the feasibility condition 2·δ ≤ allowed_delta
    /// - `total_weight_lower_bound`: Minimum allowed total weight after reduction
    ///
    /// # Returns
    /// A tuple of (reduced Nodes, new threshold t').
    pub fn new_super_swiper_reduced(
        nodes_vec: Vec<Node<G>>,
        t: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<(Self, u16)> {
        let n = Self::new(nodes_vec)?;
        let original_total_weight = n.total_weight() as u64;

        // Validate total_weight_lower_bound (similar to new_reduced)
        if total_weight_lower_bound > n.total_weight
            || total_weight_lower_bound == 0
            || original_total_weight == 0
        {
            return Err(FastCryptoError::InvalidInput);
        }

        // Extract weights from nodes, sorted in descending order (required by super_swiper)
        let weights_sorted = n
            .nodes
            .iter()
            .map(|node| node.weight as u64)
            .sorted()
            .rev()
            .collect_vec();

        // Original weights for delta calculation (in original order)
        let original_weights: Vec<u64> = n.nodes.iter().map(|node| node.weight as u64).collect();

        // Map from sorted index back to original index (computed once, used in loop)
        let indexed_weights: Vec<(usize, u16)> = n
            .nodes
            .iter()
            .enumerate()
            .map(|(i, node)| (i, node.weight))
            .sorted_by_key(|(_, w)| *w)
            .rev()
            .collect_vec();

        // Double loop: α ∈ [0.10, 0.90] step 1/100; β ∈ [α+0.01, α+0.20] step 1/100; β < 1.
        let allowed_delta_ratio = Ratio::from_integer(allowed_delta as u64);
        let two = Ratio::from_integer(2u64);
        let one = Ratio::from_integer(1u64);
        // Keep tuple field order (W', weights, δ, d) consistent everywhere to avoid mixing up δ and weights.
        let (new_total_weight, new_weights, delta, d) = {
            let mut best: Option<SuperSwiperBest> = None;
            for a_numer in 10u64..=90u64 {
                let alpha = Ratio::new(a_numer, 100);
                for b_extra_numer in 1u64..=20u64 {
                    let beta = alpha + Ratio::new(b_extra_numer, 100);
                    if beta >= one {
                        continue;
                    }
                    let reduced_weights_sorted = solve(alpha, beta, &weights_sorted);
                    let new_total_weight: u64 = reduced_weights_sorted.iter().sum();
                    if new_total_weight < total_weight_lower_bound as u64 {
                        continue;
                    }
                    let mut new_weights = vec![0u16; n.nodes.len()];
                    for (idx_in_sorted, (original_idx, _)) in indexed_weights.iter().enumerate() {
                        if idx_in_sorted < reduced_weights_sorted.len() {
                            new_weights[*original_idx] =
                                reduced_weights_sorted[idx_in_sorted] as u16;
                        }
                    }
                    let reduced_weights: Vec<u64> =
                        new_weights.iter().copied().map(u64::from).collect();
                    let (delta, d) = compute_precision_loss(&original_weights, &reduced_weights);
                    if two * delta <= allowed_delta_ratio {
                        let take = match &best {
                            None => true,
                            Some((best_w, _, best_delta, _)) => {
                                new_total_weight < *best_w
                                    || (new_total_weight == *best_w && delta < *best_delta)
                            }
                        };
                        if take {
                            best = Some((new_total_weight, new_weights, delta, d));
                        }
                    }
                }
            }
            best.ok_or(FastCryptoError::InvalidInput)?
        };

        // t' = (t + δ)/d
        let t_prime = (Ratio::from_integer(t as u64) + delta) / d;
        let t_prime_int = t_prime.to_integer();

        // Build and return the result
        let nodes = n
            .nodes
            .into_iter()
            .zip(new_weights)
            .map(|(Node { id, pk, weight: _ }, new_weight)| Node {
                id,
                pk,
                weight: new_weight,
            })
            .collect_vec();

        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let nodes_with_nonzero_weight = Self::filter_nonzero_weights(&nodes);
        let new_t = t_prime_int as u16;

        Ok((
            Self {
                nodes,
                total_weight: new_total_weight as u16,
                accumulated_weights,
                nodes_with_nonzero_weight,
            },
            new_t,
        ))
    }

    /// Create a new set of nodes. Nodes must have consecutive ids starting from 0.
    /// Reduces weights up to an allowed delta in the original total weight.
    /// Finds the largest d such that:
    /// - The new threshold is ceil(t / d)
    /// - The new threshold for Byzantine parties is ceil(f / d)
    /// - The new weights are all divided by d (floor division)
    /// - The precision loss, counted as the sum of the remainders of the division by d, is at most
    ///   the allowed delta
    ///
    /// In practice, allowed delta will be the extra liveness we would assume above 2f+1.
    ///
    /// total_weight_lower_bound allows limiting the level of reduction (e.g., in benchmarks). To
    /// get the best results, set it to 1.
    pub fn new_reduced_with_f(
        nodes_vec: Vec<Node<G>>,
        t: u16,
        f: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<(Self, u16, u16)> {
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
            let delta = n.nodes.iter().map(|n| n.weight % d).sum::<u16>()
                + Self::neg_mod(t, d)
                + Self::neg_mod(f, d);
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
        let new_t = t.div_ceil(max_d);
        let new_f = f.div_ceil(max_d);
        Ok((
            Self {
                nodes,
                total_weight,
                accumulated_weights,
                nodes_with_nonzero_weight,
            },
            new_t,
            new_f,
        ))
    }

    /// Compute (-x) mod d = d * ceil(x/d) - x
    fn neg_mod(x: u16, d: u16) -> u16 {
        (-(x as i32)).rem_euclid(d as i32) as u16
    }
}
