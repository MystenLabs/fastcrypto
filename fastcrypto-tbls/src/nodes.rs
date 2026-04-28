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

    /// Same API shape as [`Nodes::new_reduced`]: takes `nodes_vec`, signing threshold
    /// `t`, precision budget `allowed_delta`, and `total_weight_lower_bound`, and
    /// returns the reduced [`Nodes`] together with `t' = ceil(t * W' / W)` for the
    /// effective divisor implied by the reduced profile (`W` / `W'`).
    ///
    /// Internally this runs [`Nodes::prop_reduce`] (fractional divisor search with
    /// exact per-profile `delta` and the `delta + 2*d <= allowed_delta` criterion)
    /// and then applies the same ceiling scaling as Stage 2 for the `t` parameter only.
    pub fn prop_reduced(
        nodes_vec: Vec<Node<G>>,
        t: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<(Self, u16)> {
        let w_orig = Self::new(nodes_vec.clone())?.total_weight();
        let reduced = Self::prop_reduce(nodes_vec, allowed_delta, total_weight_lower_bound)?;
        let w_prime = reduced.total_weight();
        let (new_t, _) = derive_reduced_params(t, 0, w_orig, w_prime);
        Ok((reduced, new_t))
    }

    /// Same API shape as [`Nodes::new_reduced_with_f`]: takes `nodes_vec`, `t`, `f`,
    /// `allowed_delta`, and `total_weight_lower_bound`, and returns the reduced
    /// [`Nodes`] together with `t' = ceil(t * W' / W)` and `f' = ceil(f * W' / W)`.
    ///
    /// Internally this runs [`Nodes::prop_reduce`] and then applies the same
    /// ceiling scaling as Stage 2 for both parameters.
    pub fn prop_reduced_with_f(
        nodes_vec: Vec<Node<G>>,
        t: u16,
        f: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<(Self, u16, u16)> {
        let w_orig = Self::new(nodes_vec.clone())?.total_weight();
        let reduced = Self::prop_reduce(nodes_vec, allowed_delta, total_weight_lower_bound)?;
        let w_prime = reduced.total_weight();
        let (new_t, new_f) = derive_reduced_params(t, f, w_orig, w_prime);
        Ok((reduced, new_t, new_f))
    }

    /// Stage 1 of the `prop` two-stage weight-reduction API. The reduction depends *only* on the original weights and the
    /// precision budget `allowed_delta`; the threshold parameters `(t, f)` are not
    /// inputs here. Stage 2 (see [`derive_reduced_params`]) turns any subsequent
    /// `(t, f)` into reduced-space `(t', f')` in closed form.
    ///
    /// Behaves as a unilateral reduction: each reduced weight is `w'_i = floor(w_i / D)`
    /// for a trial divisor `D`, and the routine searches for the largest feasible `D`
    /// in `[2, 100]` at granularity `1/100`. At each candidate it evaluates the *exact*
    /// precision loss `delta = sum_i max(w_i - w'_i * d, 0)` against the effective
    /// divisor `d = W / W'` (rather than the conservative `sum_i (w_i mod D)` surrogate
    /// used by `new_reduced` / `new_reduced_with_f`).
    ///
    /// The Stage-1 search criterion is the conservative bound
    ///
    ///   `delta + 2 * d <= allowed_delta`.
    ///
    /// The constant `2` is the worst-case sum of the two ceiling overheads
    /// `delta_t = ceil(t/d) * d - t` and `delta_f = ceil(f/d) * d - f` that any
    /// later Stage-2 instantiation can introduce; reserving `2 * d` of the budget
    /// up front pre-pays the worst case for *every* `(t, f)` a caller might pass
    /// to [`derive_reduced_params`]. As a result, the resulting reduction admits
    /// the clean liveness statement
    ///
    ///   `w(S) >= t + f + allowed_delta  =>  w'(S) >= t' + f'`,
    ///
    /// uniformly across all valid `(t, f)`.
    ///
    /// The sweep follows the structure of the spec: each integer step `D = 2..=100`
    /// is followed, when it overshoots the budget, by a fine sweep of the preceding
    /// unit interval `(D - 1, D)` in `0.01` increments; the search then stops at the
    /// first integer overshoot.
    ///
    /// `total_weight_lower_bound` allows limiting the level of reduction (e.g., in
    /// benchmarks). Set to `1` to get the smallest committee the budget admits.
    pub fn prop_reduce(
        nodes_vec: Vec<Node<G>>,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<Self> {
        let n = Self::new(nodes_vec)?; // checks the input, etc
        assert!(total_weight_lower_bound <= n.total_weight && total_weight_lower_bound > 0);

        let total_weight = n.total_weight as u32;
        let allowed_delta_u64 = allowed_delta as u64;
        let lower_bound = total_weight_lower_bound as u32;

        // The trial divisor `D` is represented as `D * 100` in u32 so that the sweep
        // step `0.01` corresponds to a single integer unit.
        let mut best_d_x100: u32 = 100; // D = 1, i.e., no reduction.

        'sweep: for d_int in 2u32..=100 {
            let d_x100 = d_int * 100;
            let (w_total, delta_scaled) = check_outcome(&n.nodes, d_x100, total_weight);
            if w_total < lower_bound {
                // Further increases of D can only shrink W'; nothing more to find.
                break 'sweep;
            }
            if is_feasible(delta_scaled, w_total, total_weight, allowed_delta_u64) {
                best_d_x100 = d_x100;
                continue;
            }
            // Integer step overshoots: fine-sweep the preceding unit interval
            // (d_int - 1, d_int) at 0.01 granularity, scanning largest-first so the
            // first feasible candidate is the largest feasible D in that interval.
            for k in (1..100).rev() {
                let d_frac_x100 = (d_int - 1) * 100 + k;
                let (w_total_frac, delta_frac_scaled) =
                    check_outcome(&n.nodes, d_frac_x100, total_weight);
                if w_total_frac < lower_bound {
                    continue;
                }
                if is_feasible(
                    delta_frac_scaled,
                    w_total_frac,
                    total_weight,
                    allowed_delta_u64,
                ) {
                    if d_frac_x100 > best_d_x100 {
                        best_d_x100 = d_frac_x100;
                    }
                    break;
                }
            }
            break 'sweep;
        }

        let nodes: Vec<Node<G>> = n
            .nodes
            .iter()
            .map(|node| Node {
                id: node.id,
                pk: node.pk.clone(),
                weight: ((node.weight as u32 * 100) / best_d_x100) as u16,
            })
            .collect();

        let total_weight_reduced = nodes.iter().map(|n| n.weight as u32).sum::<u32>();
        debug!(
            "Nodes::prop_reduce reducing from {} to {} with D*100 = {}, allowed_delta {}, total_weight_lower_bound {}",
            n.total_weight, total_weight_reduced, best_d_x100, allowed_delta, total_weight_lower_bound
        );

        let total_weight_reduced_u16 = total_weight_reduced as u16;
        let accumulated_weights = Self::get_accumulated_weights(&nodes);
        let nodes_with_nonzero_weight = Self::filter_nonzero_weights(&nodes);
        Ok(Self {
            nodes,
            total_weight: total_weight_reduced_u16,
            accumulated_weights,
            nodes_with_nonzero_weight,
        })
    }
}

/// Stage 2 of the `prop` two-stage weight-reduction API. Given the original-space
/// flexible-threshold parameters `(t, f)` and the totals implied by Stage 1
/// (`total_weight_orig` = `W`, `total_weight_reduced` = `W'`), returns
///
///   `t' = ceil(t * W' / W)`,
///   `f' = ceil(f * W' / W)`.
///
/// This is the same ceiling scaling used by [`Nodes::prop_reduced`] /
/// [`Nodes::prop_reduced_with_f`] after [`Nodes::prop_reduce`]. It is purely
/// arithmetic --- no search over the weight profile --- so the same Stage-1
/// output can be reused across many `(t, f)` choices without re-running
/// [`Nodes::prop_reduce`].
///
/// The flexible-threshold protocol assumes `t > f` in original space; this
/// function does not assert that. The two ceilings can collapse to `t' = f'`
/// when `t - f` is small relative to the effective divisor `d = W / W'`; this
/// is operationally harmless because `f'` only feeds reduced-space certification
/// thresholds, not the AVSS `t > f` check.
pub fn derive_reduced_params(
    t: u16,
    f: u16,
    total_weight_orig: u16,
    total_weight_reduced: u16,
) -> (u16, u16) {
    assert!(total_weight_orig > 0);
    let w_o = total_weight_orig as u64;
    let w_p = total_weight_reduced as u64;
    let t_prime = (t as u64 * w_p).div_ceil(w_o) as u16;
    let f_prime = (f as u64 * w_p).div_ceil(w_o) as u16;
    (t_prime, f_prime)
}

/// Compute (-x) mod d = d * ceil(x/d) - x
fn neg_mod(x: u16, d: u16) -> u16 {
    (-(x as i32)).rem_euclid(d as i32) as u16
}

/// Helper for [`Nodes::prop_reduce`]. Tests the Stage-1 search criterion
/// `δ + 2d ≤ δ_allowed`, multiplied through by `W'` to keep everything in integers:
///
/// ```text
///   (δ + 2d) * W'  ≤  δ_allowed * W'
///   ⟺  δ_scaled + 2 * W  ≤  δ_allowed * W'.
/// ```
///
/// `delta_scaled = δ * W' = Σ max(w_i * W' - w'_i * W, 0)` is computed by
/// [`check_outcome`].
fn is_feasible(delta_scaled: u64, w_total: u32, total_weight: u32, allowed_delta: u64) -> bool {
    let lhs = delta_scaled + 2 * (total_weight as u64);
    let rhs = allowed_delta * (w_total as u64);
    lhs <= rhs
}

/// Helper for [`Nodes::prop_reduce`]. Returns `(W', delta * W')` for the reduced
/// profile `w'_i = floor(w_i * 100 / d_x100)`. The product `delta * W'` is returned
/// in place of `delta` so that feasibility can be tested in fully-integer arithmetic
/// (see [`is_feasible`]). When `W' = 0` we return `u64::MAX` for the scaled delta
/// to flag the candidate as infeasible.
fn check_outcome<G: GroupElement>(nodes: &[Node<G>], d_x100: u32, total_weight: u32) -> (u32, u64) {
    let mut w_total: u32 = 0;
    let mut w_prime: Vec<u16> = Vec::with_capacity(nodes.len());
    for node in nodes {
        let w_p = ((node.weight as u32 * 100) / d_x100) as u16;
        w_total += w_p as u32;
        w_prime.push(w_p);
    }
    if w_total == 0 {
        return (0, u64::MAX);
    }
    // delta = sum_i max(w_i - w'_i * d, 0) with d = W / W'.
    // Multiplying through by W' gives delta * W' = sum_i max(w_i * W' - w'_i * W, 0),
    // which is the integer quantity we accumulate below.
    let total_weight_u64 = total_weight as u64;
    let w_total_u64 = w_total as u64;
    let mut delta_scaled: u64 = 0;
    for (node, &w_p) in nodes.iter().zip(w_prime.iter()) {
        let lhs = (node.weight as u64) * w_total_u64;
        let rhs = (w_p as u64) * total_weight_u64;
        if lhs > rhs {
            delta_scaled += lhs - rhs;
        }
    }
    (w_total, delta_scaled)
}
