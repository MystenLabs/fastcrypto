// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A single, validated home for the `(nodes, t, f)` configuration and every derived quantity the
//! AVSS / AVID protocols compute from it.
//!
//! Today the three quantities have two owners — `W` lives in [`Nodes`], `(t, f)` live in
//! [`Parameters`] — and the relationships between them are re-derived ad hoc at each call site
//! (`Avid::new`'s `W − 2f`, `batch_avss`'s `t ≤ W`, presigning's `W − (t−1)`, …). [`ShareConfig`]
//! bundles them behind one constructor and exposes the combinations as named getters, so the
//! invariants are enforced once and the arithmetic has a single source of truth.
//!
//! # Invariant taxonomy
//!
//! The requirements split along two axes — *what breaks if violated*, and *whether weight
//! reduction preserves them for free*:
//!
//! | Invariant   | Kind                    | Violated ⇒                                   | Preserved by [`reduce`](ShareConfig::reduce)? |
//! |-------------|-------------------------|----------------------------------------------|-----------------------------------------------|
//! | `0 < f`     | structural              | no fault budget                              | ✅ `⌈f/d⌉ ≥ 1`                                 |
//! | `0 < t`     | structural              | trivial threshold                            | ✅ `⌈t/d⌉ ≥ 1`                                 |
//! | `t ≤ W`     | functional              | secret can never be reconstructed            | ❌ `W` shrinks — re-checked in [`new`](ShareConfig::new) |
//! | `t ≥ f`     | **trust**               | adversary alone reconstructs (loss of secrecy)| ✅ `⌈·/d⌉` monotone: `t ≥ f ⇒ ⌈t/d⌉ ≥ ⌈f/d⌉`  |
//! | `W > 2f`    | **functional** (AVID)   | Reed-Solomon message length `≤ 0`, decode breaks| ❌ only within `allowed_delta` — re-checked   |
//!
//! Structural + trust invariants are **constructor preconditions**: any `ShareConfig` that exists
//! satisfies them. The AVID-only functional requirement `W > 2f` is *not* globally required (only
//! the dispersal path needs it), so it is exposed as the fallible getter
//! [`recoverable_weight`](ShareConfig::recoverable_weight) rather than baked into `new` — you
//! cannot obtain `W − 2f` without its precondition having been checked.
//!
//! [`reduce`](ShareConfig::reduce) returns a `ShareConfig` (never a bare `(Nodes, t, f)` tuple), so
//! the reduced thresholds can never drift apart from the reduced weights, and the re-checkable
//! invariants run again in `new`.

use crate::nodes::{Node, Nodes};
use crate::threshold_schnorr::Parameters;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::GroupElement;
use serde::Serialize;

/// A validated `(nodes, t, f)` configuration for the AVSS / AVID protocols.
///
/// Constructing a `ShareConfig` guarantees the structural and trust invariants (`0 < f`, `0 < t`,
/// `t ≤ W`, `t ≥ f`); see the [module docs](self) for the full taxonomy. The functional
/// requirement `W > 2f` is checked on demand by [`recoverable_weight`](Self::recoverable_weight).
#[derive(Clone, Debug)]
pub struct ShareConfig<G: GroupElement> {
    nodes: Nodes<G>,
    params: Parameters,
}

impl<G: GroupElement + Serialize> ShareConfig<G> {
    /// Bundle `nodes` with threshold parameters, validating the structural and trust invariants
    /// (`0 < f`, `0 < t`, `t ≤ W`, `t ≥ f`) via [`Parameters::validate`]. Returns
    /// [`InvalidInput`](fastcrypto::error::FastCryptoError::InvalidInput) if they do not hold.
    pub fn new(nodes: Nodes<G>, params: Parameters) -> FastCryptoResult<Self> {
        params.validate(nodes.total_weight())?;
        Ok(Self { nodes, params })
    }

    // --- accessors -----------------------------------------------------------------------------

    /// The underlying node set.
    pub fn nodes(&self) -> &Nodes<G> {
        &self.nodes
    }

    /// The threshold parameters `(t, f)`.
    pub fn parameters(&self) -> Parameters {
        self.params
    }

    // --- raw quantities, always well-defined ---------------------------------------------------

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

    // --- derived quantities, tagged by invariant class -----------------------------------------

    /// `W − f` — honest weight guaranteed available once the Byzantine set is removed. Trust-side;
    /// well-defined because `f ≤ t < W`.
    pub fn honest_weight(&self) -> u16 {
        self.total_weight() - self.params.f
    }

    /// `t + f` — the certificate / vote quorum: the signer weight a dispersal certificate must
    /// gather so that at least `t` of it is honest. Trust-side (BFT liveness). Returned as `u32` to
    /// keep the sum overflow-free for large weights.
    pub fn certificate_quorum(&self) -> u32 {
        self.params.t as u32 + self.params.f as u32
    }

    /// `W − (t − 1)` — the number of presignatures that remain unbiased given the degree-`(t−1)`
    /// nonce sharing. Well-defined because `t − 1 < W`.
    pub fn safe_presignatures(&self) -> u16 {
        self.total_weight() - self.sharing_degree()
    }

    /// `W − 2f` — the weight of authenticated shards needed to reconstruct in the AVID dispersal
    /// path, i.e. the message length of the `(W, W − 2f)` Reed-Solomon code.
    ///
    /// **Functional invariant (AVID only):** returns
    /// [`InvalidInput`](fastcrypto::error::FastCryptoError::InvalidInput) unless `W > 2f`. This is
    /// the single source of truth shared with `Avid::new`; non-dispersal protocols never call it,
    /// which is why `W > 2f` is not a global constructor precondition.
    pub fn recoverable_weight(&self) -> FastCryptoResult<u16> {
        Self::recoverable_weight_from(self.total_weight(), self.params.f)
    }

    /// The `W > 2f ⇒ W − 2f` computation, factored out so `Avid::new` (which only knows
    /// `(nodes, f)`, not `t`) shares one implementation with [`recoverable_weight`](Self::recoverable_weight).
    pub(crate) fn recoverable_weight_from(total_weight: u16, f: u16) -> FastCryptoResult<u16> {
        if f == 0 {
            return Err(InvalidInput);
        }
        total_weight
            .checked_sub(2 * f)
            .filter(|&k| k > 0)
            .ok_or(InvalidInput)
    }

    // --- weight reduction ----------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecies_v1;
    use crate::ecies_v1::PublicKey;
    use crate::threshold_schnorr::EG;
    use fastcrypto::traits::AllowedRng;

    fn node(id: u16, weight: u16, rng: &mut impl AllowedRng) -> Node<EG> {
        let sk = ecies_v1::PrivateKey::<EG>::new(rng);
        Node {
            id,
            pk: PublicKey::from_private_key(&sk),
            weight,
        }
    }

    fn nodes(weights: &[u16]) -> Nodes<EG> {
        let mut rng = rand::thread_rng();
        Nodes::new(
            weights
                .iter()
                .enumerate()
                .map(|(i, &w)| node(i as u16, w, &mut rng))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn structural_and_trust_invariants_enforced_at_construction() {
        let n = nodes(&[1, 2, 2, 2]); // W = 7
                                      // t < f is rejected (trust).
        assert!(ShareConfig::new(n.clone(), Parameters { t: 1, f: 2 }).is_err());
        // t >= W is rejected (functional).
        assert!(ShareConfig::new(n.clone(), Parameters { t: 7, f: 2 }).is_err());
        // f == 0 is rejected (structural).
        assert!(ShareConfig::new(n.clone(), Parameters { t: 3, f: 0 }).is_err());
        // t = 3, f = 2 over W = 7 is valid.
        assert!(ShareConfig::new(n, Parameters { t: 3, f: 2 }).is_ok());
    }

    #[test]
    fn recoverable_weight_gates_on_w_gt_2f() {
        // W = 7, f = 2 => W > 2f, recoverable = 3.
        let ok = ShareConfig::new(nodes(&[1, 2, 2, 2]), Parameters { t: 3, f: 2 }).unwrap();
        assert_eq!(ok.recoverable_weight().unwrap(), 3);
        assert_eq!(ok.certificate_quorum(), 5); // t + f
        assert_eq!(ok.honest_weight(), 5); // W - f
        assert_eq!(ok.safe_presignatures(), 5); // W - (t - 1)

        // W = 4, f = 2 => W = 2f, recoverable_weight must fail even though (t, f) are valid.
        let no_avid = ShareConfig::new(nodes(&[1, 1, 1, 1]), Parameters { t: 3, f: 2 }).unwrap();
        assert!(no_avid.recoverable_weight().is_err());
    }

    #[test]
    fn reduce_returns_a_revalidated_config() {
        let config = ShareConfig::new(nodes(&[10, 20, 20, 20]), Parameters { t: 30, f: 20 }).unwrap();
        let reduced = config.reduce(config.total_weight() / 10, 1).unwrap();
        // The trust invariant t >= f survives reduction by construction.
        assert!(reduced.reconstruction_threshold() >= reduced.byzantine_bound());
        assert!(reduced.total_weight() <= config.total_weight());
    }
}
