// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! [`ShareConfig`] bundles the `(nodes, t, f)` configuration behind one validated constructor and
//! exposes the derived quantities (`W − 2f`, `t + f`, `W − (t−1)`, …) as named getters.

use crate::nodes::{Node, Nodes, PartyId};
use crate::threshold_schnorr::Parameters;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::GroupElement;
use serde::Serialize;
use std::sync::Arc;

/// A validated `(nodes, t, f)` configuration.
///
/// Constructing a `ShareConfig` guarantees the structural and trust invariants (`0 < f`, `0 < t`,
/// `t ≤ W`, `t ≥ f`). The functional requirement `W > 2f` is checked on demand by
/// [`recoverable_weight`](Self::recoverable_weight).
#[derive(Clone, Debug)]
pub struct ShareConfig<G: GroupElement> {
    nodes: Arc<Nodes<G>>,
    params: Parameters,
}

impl<G: GroupElement + Serialize> ShareConfig<G> {
    /// Bundle `nodes` with threshold parameters, validating the structural and trust invariants
    /// (`0 < f`, `0 < t`, `t ≤ W`, `t ≥ f`) via [`Parameters::validate`]. Returns
    /// [`InvalidInput`](fastcrypto::error::FastCryptoError::InvalidInput) if they do not hold.
    pub fn new(nodes: Nodes<G>, params: Parameters) -> FastCryptoResult<Self> {
        params.validate(nodes.total_weight())?;
        Ok(Self {
            nodes: Arc::new(nodes),
            params,
        })
    }

    /// The underlying node set.
    pub fn nodes(&self) -> &Nodes<G> {
        &self.nodes
    }

    /// A cheap `Arc` handle to the node set.
    pub fn nodes_arc(&self) -> Arc<Nodes<G>> {
        Arc::clone(&self.nodes)
    }

    /// The threshold parameters `(t, f)`.
    pub fn parameters(&self) -> Parameters {
        self.params
    }

    /// `W` — total weight of all parties.
    pub fn total_weight(&self) -> u16 {
        self.nodes.total_weight()
    }

    /// `f` — the Byzantine weight bound (trust assumption input).
    pub fn byzantine_bound(&self) -> u16 {
        self.params.f
    }

    /// `t` — the reconstruction / signing threshold (trust assumption input).
    pub fn reconstruction_threshold(&self) -> u16 {
        self.params.t
    }

    /// `t − 1` — the degree at which secrets are shared (and the privacy threshold: any coalition
    /// of `< t` weight learns nothing). Well-defined because `t ≥ 1` is a constructor invariant.
    pub fn sharing_degree(&self) -> u16 {
        self.params.t - 1
    }

    /// `W − f` — honest weight guaranteed available once the Byzantine set is removed. Trust-side;
    /// well-defined because `f ≤ t < W`.
    pub fn honest_weight(&self) -> u16 {
        self.total_weight() - self.params.f
    }

    /// `t + f` — a quorum weight that contains at least `t` honest weight when up to `f` is
    /// Byzantine. Returned as `u32` so the sum cannot overflow for large weights.
    pub fn certificate_quorum(&self) -> u32 {
        self.params.t as u32 + self.params.f as u32
    }

    /// `W − (t − 1)` — the number of presignatures that remain unbiased given the degree-`(t−1)`
    /// nonce sharing. Well-defined because `t − 1 < W`.
    pub fn safe_presignatures(&self) -> u16 {
        self.total_weight() - self.sharing_degree()
    }

    /// Whether the parties in `ids` jointly hold at least the reconstruction threshold `t` by
    /// weight — i.e. enough to reconstruct a shared secret. Returns
    /// [`InvalidInput`](fastcrypto::error::FastCryptoError::InvalidInput) if any id is not a party
    /// in this set. The caller chooses which error to raise when the threshold is not met.
    pub fn has_reconstruction_threshold<'a>(
        &self,
        ids: impl Iterator<Item = &'a PartyId>,
    ) -> FastCryptoResult<bool> {
        Ok(self.nodes.total_weight_of(ids)? >= self.params.t)
    }

    /// `W − 2f`, the message length of the `(W, W − 2f)` Reed-Solomon code. Returns
    /// [`InvalidInput`](fastcrypto::error::FastCryptoError::InvalidInput) unless `W > 2f`.
    pub fn recoverable_weight(&self) -> FastCryptoResult<u16> {
        Self::recoverable_weight_from(self.total_weight(), self.params.f)
    }

    /// `W − 2f` for a given total weight `W` and Byzantine bound `f`. Returns
    /// [`InvalidInput`](fastcrypto::error::FastCryptoError::InvalidInput) if `f == 0` or `W ≤ 2f`.
    pub(crate) fn recoverable_weight_from(total_weight: u16, f: u16) -> FastCryptoResult<u16> {
        if f == 0 {
            return Err(InvalidInput);
        }
        total_weight
            .checked_sub(2 * f)
            .filter(|&k| k > 0)
            .ok_or(InvalidInput)
    }

    /// Reduce weights by the largest integer divisor `d` whose precision loss stays within
    /// `allowed_delta`, scaling both thresholds by `⌈·/d⌉`. Delegates to
    /// [`Nodes::new_reduced_with_f`] and re-wraps the result as a `ShareConfig`, so the returned
    /// config is fully re-validated: the trust invariant `t ≥ f` survives by construction (`⌈·/d⌉`
    /// is monotone), while the functional `t ≤ W'` is re-checked in [`new`](Self::new).
    ///
    /// `total_weight_lower_bound` caps how far weight may fall (set to `1` for maximal reduction).
    pub fn reduce(
        &self,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<Self> {
        let (nodes, t, f) = Nodes::new_reduced_with_f(
            self.node_vec(),
            self.params.t,
            self.params.f,
            allowed_delta,
            total_weight_lower_bound,
        )?;
        Self::new(nodes, Parameters { t, f })
    }

    /// Like [`reduce`](Self::reduce) but permits a fractional divisor (0.01 granularity) for a
    /// possibly-tighter reduction. Delegates to [`Nodes::prop_reduce`].
    pub fn reduce_fractional(
        &self,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) -> FastCryptoResult<Self> {
        let (nodes, t, f) = Nodes::prop_reduce(
            self.node_vec(),
            self.params.t,
            self.params.f,
            allowed_delta,
            total_weight_lower_bound,
        )?;
        Self::new(nodes, Parameters { t, f })
    }

    fn node_vec(&self) -> Vec<Node<G>> {
        self.nodes.iter().cloned().collect()
    }
}
