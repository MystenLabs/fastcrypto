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
            let delta =
                n.nodes.iter().map(|n| n.weight % d).sum::<u16>() + neg_mod(t, d) + neg_mod(f, d);
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

    /// Same API as [`Nodes::new_reduced_with_f`], with two changes relative to
    /// the integer-only routine:
    ///
    ///   1. The integer divisor sweep goes *downward* from `40` to `2`, breaking
    ///      on the first feasible integer `d_int`. Going down, the first feasible
    ///      candidate is by definition the largest feasible *integer* `d`, so
    ///      no further integer steps need to be evaluated. (The criterion is not
    ///      monotone in `d`, so an upward sweep cannot use this early-termination
    ///      shortcut: e.g.\ for `t = 100`, `neg_mod(t, 10) = 0` but
    ///      `neg_mod(t, 11) = 10`, then `neg_mod(t, 100) = 0` again.)
    ///
    ///   2. After locking onto the first feasible integer `d_int`, the routine
    ///      fine-sweeps the unit interval `(d_int, d_int + 1)` at granularity
    ///      `0.01`, decreasing-first, and takes the first hit. Since `d_int`
    ///      is feasible and `d_int + 1` is infeasible (or out of range), the
    ///      criterion's feasibility boundary lives somewhere in `(d_int, d_int+1)`,
    ///      and the largest fractional candidate at `0.01` granularity in that
    ///      interval is returned (or `d_int` itself if no fractional candidate
    ///      satisfies the criterion).
    ///
    /// The criterion is the natural fractional-`d` extension of the one used
    /// by [`Nodes::new_reduced_with_f`]:
    ///
    ///   `Σ_i (w_i mod d) + neg_mod(t, d) + neg_mod(f, d) ≤ allowed_delta`,
    ///
    /// with `(w mod d) = w - floor(w/d) * d ∈ [0, d)` and
    /// `neg_mod(w, d) = ceil(w/d) * d - w ∈ [0, d)` for any real `d > 0`.
    /// Stage-2 outputs `w'_i = floor(w_i / d)`, `t' = ceil(t / d)`,
    /// `f' = ceil(f / d)` use only floor/ceiling identities and integer
    /// arithmetic on the reduced weights, so the safety, liveness, and
    /// Byzantine-removal proofs go through verbatim for fractional `d`.
    ///
    /// All fractional arithmetic is carried out in u64 against the integer
    /// representation `d_x100 = 100 * d` (so `d_x100 ∈ {200, ..., 4099}` covers
    /// the integer sweep `[2, 40]` and the fractional sweep `(d_int, d_int+1)`
    /// at `0.01` granularity); no floating-point is involved.
    ///
    /// Because every candidate considered by [`Nodes::new_reduced_with_f`] is
    /// also considered here, `W'_prop ≤ W'_new` on every input. When the chosen
    /// `d` is integer (i.e., `d_x100` is a multiple of 100), the two routines
    /// return identical reduced weights and `(t', f')`.
    ///
    /// Returns `(reduced_nodes, t', f', d_x100)` where `d_x100 = 100 * d` is
    /// the chosen divisor in integer form; the divisor itself is `d_x100 / 100`.
    pub fn prop_reduce(
        nodes_vec: Vec<Node<G>>,
        t: u16,
        f: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<(Self, u16, u16, u32)> {
        let n = Self::new(nodes_vec)?; // checks the input, etc
        assert!(total_weight_lower_bound <= n.total_weight && total_weight_lower_bound > 0);

        let allowed_delta_x100: u64 = (allowed_delta as u64) * 100;
        let mut max_d_x100: u32 = 100; // d = 1, no reduction (fallback if no d in [2, 40] works)

        'outer: for d_int in (2u16..=40).rev() {
            // Integer-d feasibility check (identical to new_reduced_with_f).
            let new_total_int = n.nodes.iter().map(|n| n.weight / d_int).sum::<u16>();
            if new_total_int < total_weight_lower_bound {
                continue;
            }
            let delta_int = n.nodes.iter().map(|n| n.weight % d_int).sum::<u16>()
                + neg_mod(t, d_int)
                + neg_mod(f, d_int);
            if delta_int > allowed_delta {
                continue;
            }
            // First feasible integer d_int going down: lock it as the fallback,
            // then fine-sweep (d_int, d_int + 1) at 0.01 in decreasing order to
            // see whether a strictly larger fractional d is also feasible.
            max_d_x100 = (d_int as u32) * 100;
            for k in (1..100u32).rev() {
                let d_x100 = (d_int as u32) * 100 + k;
                let new_w_total: u32 = n
                    .nodes
                    .iter()
                    .map(|node| ((node.weight as u32) * 100) / d_x100)
                    .sum();
                if (new_w_total as u16) < total_weight_lower_bound {
                    continue;
                }
                // Σ_i (w_i mod d) * 100 = W * 100 - W' * d_x100 (telescopes by floor).
                let sum_mod_x100: u64 =
                    (n.total_weight as u64) * 100 - (new_w_total as u64) * (d_x100 as u64);
                let delta_x100: u64 =
                    sum_mod_x100 + neg_mod_x100(t, d_x100) + neg_mod_x100(f, d_x100);
                if delta_x100 <= allowed_delta_x100 {
                    max_d_x100 = d_x100;
                    break;
                }
            }
            break 'outer;
        }

        debug!(
            "Nodes::prop_reduce reducing from {} with d_x100 {}, allowed_delta {}, total_weight_lower_bound {}",
            n.total_weight, max_d_x100, allowed_delta, total_weight_lower_bound
        );

        let nodes = n
            .nodes
            .iter()
            .map(|node| Node {
                id: node.id,
                pk: node.pk.clone(),
                weight: (((node.weight as u32) * 100) / max_d_x100) as u16,
            })
            .collect::<Vec<_>>();
        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let nodes_with_nonzero_weight = Self::filter_nonzero_weights(&nodes);
        let total_weight = nodes.iter().map(|n| n.weight).sum::<u16>();
        let new_t = (((t as u64) * 100).div_ceil(max_d_x100 as u64)) as u16;
        let new_f = (((f as u64) * 100).div_ceil(max_d_x100 as u64)) as u16;
        Ok((
            Self {
                nodes,
                total_weight,
                accumulated_weights,
                nodes_with_nonzero_weight,
            },
            new_t,
            new_f,
            max_d_x100,
        ))
    }
}

/// Compute `(-x) mod d = d * ceil(x/d) - x` for an integer divisor `d > 0`.
fn neg_mod(x: u16, d: u16) -> u16 {
    (-(x as i32)).rem_euclid(d as i32) as u16
}

/// Compute `((-w) mod d) * 100`, the ceiling overhead of `w` against the
/// possibly-fractional divisor `d = d_x100 / 100`, scaled by 100. The result
/// equals `(ceil(w/d) * d - w) * 100` and is a non-negative integer in `[0, d_x100)`.
fn neg_mod_x100(w: u16, d_x100: u32) -> u64 {
    let r = ((w as u64) * 100) % (d_x100 as u64);
    if r == 0 {
        0
    } else {
        (d_x100 as u64) - r
    }
}
