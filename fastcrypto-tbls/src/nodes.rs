// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies_v1;
use crate::types::ShareIndex;
use crate::weight_reduction::solve;
use crate::weight_reduction::weight_reduction_checks::get_delta;
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::GroupElement;
use fastcrypto::hash::{Blake2b256, Digest, HashFunction};
use itertools::Itertools;
use num_rational::Ratio;
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

    /// Create a new set of nodes using the super_swiper algorithm for weight reduction.
    /// This uses the swiper algorithms from the `weight_reduction` directory.
    ///
    /// # Parameters
    /// - `nodes_vec`: Input nodes with weights
    /// - `t`: Threshold (adversarial weight threshold in absolute terms)
    /// - `allowed_delta`: Maximum allowed delta value
    /// - `total_weight_lower_bound`: Minimum allowed total weight after reduction
    ///
    /// # Returns
    /// A tuple of (reduced Nodes, new threshold, beta numerator, beta denominator)
    pub fn new_super_swiper_reduced(
        nodes_vec: Vec<Node<G>>,
        t: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<(Self, u16, Ratio<u64>)> {
        let n = Self::new(nodes_vec)?;
        let original_total_weight = n.total_weight() as u64;

        // Validate total_weight_lower_bound (similar to new_reduced)
        if total_weight_lower_bound > n.total_weight
            || total_weight_lower_bound == 0
            || original_total_weight == 0
        {
            return Err(FastCryptoError::InvalidInput);
        }

        let alpha = Ratio::new(t as u64, original_total_weight);

        // Extract weights from nodes, sorted in descending order (required by super_swiper)
        // Sort in descending order as required by super_swiper
        let weights_sorted = n
            .nodes
            .iter()
            .map(|node| node.weight as u64)
            .sorted()
            .rev()
            .collect_vec();

        // Set initial beta = alpha + 1/100
        let beta_denom = 100u64;
        // Calculate alpha + 1/100 = (alpha_numer * 100 + alpha_denom) / (alpha_denom * 100)
        // Then convert to denominator 100: beta_numer = (alpha_numer * 100 + alpha_denom) / alpha_denom
        let mut beta_numer = (alpha.numer() * beta_denom + alpha.denom()) / alpha.denom();

        // Safety limit to prevent infinite loops
        const MAX_BETA_ITERATIONS: u64 = 50; // Allow more iterations for slack-based approach
        let mut iterations = 0;

        loop {
            iterations += 1;
            if iterations > MAX_BETA_ITERATIONS {
                return Err(FastCryptoError::InvalidInput);
            }

            // Call super_swiper to get ticket assignments (which are the reduced weights)
            let reduced_weights_sorted =
                solve(alpha, Ratio::new(beta_numer, beta_denom), &weights_sorted);

            // Calculate the new total weight
            let new_total_weight: u64 = reduced_weights_sorted.iter().sum();

            // Map the reduced weights back to nodes
            let indexed_weights = n
                .nodes
                .iter()
                .enumerate()
                .map(|(i, node)| (i, node.weight))
                .sorted_by_key(|(_, w)| *w)
                .rev()
                .collect_vec();

            let mut new_weights = vec![0u16; n.nodes.len()];
            for (idx_in_sorted, (original_idx, _original_weight)) in
                indexed_weights.iter().enumerate()
            {
                if idx_in_sorted < reduced_weights_sorted.len() {
                    new_weights[*original_idx] = reduced_weights_sorted[idx_in_sorted] as u16;
                }
            }

            // Prepare weights for delta calculation (in original order)
            let original_weights = n.nodes.iter().map(|node| node.weight as u64).collect_vec();
            let reduced_weights = new_weights.iter().copied().map(u64::from).collect_vec();
            let t_prime = (Ratio::new(beta_numer, beta_denom) * new_total_weight).to_integer();

            // Get delta - this is the primary validation check
            // Use n=2 random subsets in addition to top and bottom checks
            let delta = get_delta(
                t_prime,
                &original_weights,
                &reduced_weights,
                t as u64,
                2, // n_random: number of random subsets to test
            );

            // Use delta as the primary check instead of other validations
            // The constraint should be: delta >= allowed_delta (lower bound, like the old slack constraint)
            // This ensures w1 >= t + allowed_delta, which means the reduction is not too aggressive
            // If delta < allowed_delta, we need to increase beta to get a larger t_prime and thus larger w1
            let delta_acceptable = if let Some(delta_value) = delta {
                delta_value >= allowed_delta as u64
            } else {
                // If delta calculation failed (negative delta or t_prime cannot be reached), try increasing beta
                // This might help by increasing t_prime and potentially getting a valid subset
                false
            };

            // Check if reduction went below the lower bound (similar to new_reduced)
            let lower_bound_ok = new_total_weight >= total_weight_lower_bound as u64;

            // Check both constraints: lower bound and delta
            // If either fails, try increasing beta (which helps both constraints)
            if !lower_bound_ok || !delta_acceptable {
                // Try to increase beta to improve both constraints
                // Increasing beta increases new_total_weight (helps lower bound) and increases delta (helps delta constraint)
                if beta_numer < 50 {
                    beta_numer += 1;
                    continue;
                } else {
                    // Can't increase beta further
                    // If we've tried many times, accept the current result if it at least meets the lower bound
                    // Otherwise return error
                    if iterations < 20 || !lower_bound_ok {
                        // Give more iterations to find a solution
                        return Err(FastCryptoError::InvalidInput);
                    }
                    // Lower bound is met, accept even if delta constraint not perfectly met
                }
            }

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

            // These are required fields for the Nodes struct
            let accumulated_weights = Self::get_accumulated_weights(&nodes);
            let nodes_with_nonzero_weight = Self::filter_nonzero_weights(&nodes);

            // Calculate new threshold
            let beta = Ratio::new(beta_numer, beta_denom);
            let new_t = (beta * new_total_weight).to_integer() as u16;

            return Ok((
                Self {
                    nodes,
                    total_weight: new_total_weight as u16,
                    accumulated_weights,
                    nodes_with_nonzero_weight,
                },
                new_t,
                beta,
            ));
        }
    }
}
