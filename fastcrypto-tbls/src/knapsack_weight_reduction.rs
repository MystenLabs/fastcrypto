// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Knapsack-verified weight reduction.
//!
//! Replaces weights `w_1..w_n` (total `W`) by smaller weights `w'_1..w'_n`
//! (total `W'`) and thresholds `t', f'`, minimizing `W'` while preserving the
//! security of the weighted protocols when instantiated with
//! `(t', f', W')` in place of `(t, f, W)`. Inputs are the privacy threshold
//! `t`, the Byzantine weight bound `f` (with `t > f` and
//! `W >= t + 2f + delta` enforced), and the
//! allowed liveness degradation `delta` in original weight units.
//!
//! # Guarantees
//!
//! Let `g(b) = max { w'(S) : w(S) <= b }`, computed exactly by a knapsack DP,
//! and set `t' = g(t-1) + 1`, `f' = g(f)`. For every subset S of parties:
//!
//! - (P) Privacy: `w(S) < t  =>  w'(S) < t'`.
//! - (B) Byzantine bound: `w(S) <= f  =>  w'(S) <= f'`.
//! - (L1) Liveness: `w(S) >= t + delta  =>  w'(S) >= t'`. Sets that could
//!   reconstruct originally (with `delta` slack) still reach the reduced
//!   threshold.
//! - (L2) Liveness: `w(S) >= t + f + delta  =>  w'(S) >= t' + f'`. Sets that
//!   could form a Byzantine-tolerant quorum originally still can.
//!
//! The reduced-space feasibility conditions follow:
//! - `t > f` => `t' > f'` - follows from monotonicity of `g`.
//! - `W >= t + 2f + delta` => `t' + 2f' <= W'` - let T be a set with `w(T) <= f`
//!   and `w'(T) = f'` (one exists because `f'` is defined as the maximum of
//!   `w'` over the nonempty finite family `{S : w(S) <= f}`).
//!   T's complement C has `w(C) = W - w(T) >= W - f >= t + f + delta`, so (L2)
//!   gives `w'(C) >= t' + f'`.
//!   Since T and C partition the parties, we have
//!   `W' = w'(T) + w'(C) >= f' + (t' + f') = t' + 2f'`.
//!
//! # Algorithm
//!
//! Candidates are scaled roundings `w'_i = floor(w_i / d)` or
//! `w'_i = round(w_i / d)` for divisors `d` on a 0.01 grid.
//! For a fixed rounding, `W'` is non-increasing in `d`, so the sweep goes downward
//! and returns the first candidate that passes the feasibility check.
//! It starts at the largest useful divisor (`max weight` for floor,
//! `2 * max weight` for nearest). Consecutive grid points usually
//! produce identical reduced vectors, so the sweep jumps directly between
//! "breakpoints" where some `w'_i` changes.
//!
//! The same DP powers `verify_reduction`, an `O(n * W')` exact checker of the
//! above four properties for an arbitrary candidate `(w', t', f')`.
//!
//! The implementation follows the weight-reduction framework of Swiper (Tonkikh and
//! Freitas, PODC 2024, <https://arxiv.org/abs/2307.15561>): scaled-rounding
//! candidates verified via knapsack computations.
//! Our variant differs in enforcing the four absolute predicates above with tight
//! output thresholds `t', f'`, trying two rounding profiles, and sweeping divisors
//! downward instead of binary search, as our feasibility predicate is non-monotone
//! in `d`.

use fastcrypto::error::{FastCryptoError, FastCryptoResult};

const MAX_PARTIES: usize = 1000;
const MAX_WEIGHT: u16 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReducedWeights {
    /// Same order as the input, entries may be zero.
    pub weights: Vec<u16>,
    pub t: u16,
    pub f: u16,
}

#[derive(Clone, Copy)]
enum Rounding {
    Floor,
    Nearest,
}

pub(crate) fn reduce_weights(
    weights: &[u16],
    t: u16,
    f: u16,
    delta: u16,
    total_weight_lower_bound: u16,
) -> FastCryptoResult<ReducedWeights> {
    // Sanity checks on input parameters.
    if weights.is_empty() || weights.len() > MAX_PARTIES || weights.iter().any(|&w| w > MAX_WEIGHT)
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let total_weight = weights.iter().map(|&w| w as u32).sum::<u32>();
    if total_weight == 0 || total_weight > u16::MAX as u32 {
        return Err(FastCryptoError::InvalidInput);
    }
    let w_total = total_weight as u16;
    if t == 0
        || t > w_total
        || f >= t
        || (t as u32) + 2 * (f as u32) + (delta as u32) > total_weight
    {
        return Err(FastCryptoError::InvalidInput);
    }
    if total_weight_lower_bound == 0 || total_weight_lower_bound > w_total {
        return Err(FastCryptoError::InvalidInput);
    }

    // Prefer fewer total shares, then a lower reconstruction threshold.
    let rank = |c: &ReducedWeights| (c.weights.iter().map(|&w| w as u32).sum::<u32>(), c.t);

    // Start from the identity fallback (d = 1).
    let mut best = ReducedWeights {
        weights: weights.to_vec(),
        t,
        f,
    };
    // Try both roundings and keep the best.
    for rounding in [Rounding::Floor, Rounding::Nearest] {
        if let Some(candidate) = sweep(
            weights,
            w_total,
            t,
            f,
            delta,
            total_weight_lower_bound,
            rounding,
        ) {
            if rank(&candidate) < rank(&best) {
                best = candidate;
            }
        }
    }
    Ok(best)
}

/// Sweep divisors downward (largest first) on the 0.01 grid for one rounding,
/// jumping between "breakpoints" where the reduced vector changes, and return the
/// first candidate that passes the feasibility check.
fn sweep(
    weights: &[u16],
    w_total: u16,
    t: u16,
    f: u16,
    delta: u16,
    lower_bound: u16,
    rounding: Rounding,
) -> Option<ReducedWeights> {
    let max_weight = *weights.iter().max().expect("non-empty") as u32;

    // The candidate divisor currently under test, times 100 (0.01 grid),
    // starting from the largest useful divisor.
    // To have at least one party with non-zero reduced weight, we need
    // round(w/d) > 0.
    let mut d_candidate = match rounding {
        // round(w/d) > 0 <-> floor(w/d) > 0 <-> w/d > 0 <-> d <= w
        Rounding::Floor => max_weight * 100,
        // round(w/d) > 0 <-> floor(w/d + 1/2) > 0 <-> w/d > 1/2 <-> d <= 2w
        Rounding::Nearest => max_weight * 200,
    };

    while d_candidate > 100 {
        let reduced = weights
            .iter()
            .map(|&w| reduce_weight(w, d_candidate, rounding))
            .collect::<Vec<_>>();
        let reduced_total = reduced.iter().map(|&w| w as u32).sum::<u32>();
        if reduced_total >= lower_bound as u32 {
            if let Ok((tp, fp)) = check_candidate(weights, w_total, t, f, delta, &reduced) {
                return Some(ReducedWeights {
                    weights: reduced,
                    t: tp,
                    f: fp,
                });
            }
        }

        // Jump to the largest divisor where some reduced weight increases; all
        // divisors in between yield the current (just rejected) vector again.
        // Reduced weights only grow as d shrinks; for each party we compute the
        // largest grid divisor d' at which its q ticks up to q+1.
        let next = weights
            .iter()
            .zip(reduced.iter())
            .map(|(&w, &q)| match rounding {
                // floor(w/d') >= q+1 <-> w/d' >= q+1 <-> d' <= w/(q+1),
                // i.e., d' <= 100w/(q+1) on the 0.01 grid.
                Rounding::Floor => (w as u32) * 100 / (q as u32 + 1),
                // round(w/d') = floor(w/d' + 1/2) >= q+1 <-> w/d' >= q + 1/2
                // <-> d' <= 2w/(2q+1), i.e., d' <= 200w/(2q+1) on the grid.
                Rounding::Nearest => (w as u32) * 200 / (2 * q as u32 + 1),
            })
            .max()
            .expect("non-empty");
        d_candidate = next.min(d_candidate - 1);
    }
    None
}

fn reduce_weight(w: u16, d: u32, rounding: Rounding) -> u16 {
    let w = w as u32;
    (match rounding {
        // floor(w / (d/100)) = floor(100w / d).
        Rounding::Floor => w * 100 / d,
        // round(w / (d/100)) = floor(100w/d + 1/2) = floor((200w + d) / 2d).
        Rounding::Nearest => (w * 200 + d) / (2 * d),
    }) as u16
}

/// The value-space knapsack table `min_original_weight[v] = min { w(S) : w'(S) = v }` for
/// `v in [0, W']`, computed in `O(n * W')`.
fn knapsack_min_original(weights: &[u16], reduced: &[u16], reduced_total: u32) -> Vec<u32> {
    let mut min_original_weight = vec![u32::MAX; reduced_total as usize + 1];
    min_original_weight[0] = 0;
    for (&w, &q) in weights.iter().zip(reduced.iter()) {
        let (w, q) = (w as u32, q as usize);
        if q == 0 {
            continue;
        }
        for v in (q..min_original_weight.len()).rev() {
            if min_original_weight[v - q] != u32::MAX {
                min_original_weight[v] = min_original_weight[v].min(min_original_weight[v - q] + w);
            }
        }
    }
    min_original_weight
}

/// `g(weight) = max { w'(S) : w(S) <= weight }`.
/// In other words, the largest reduced weight a subset can have while its
/// original weight <= `weight`: w(S) <= weight => w'(S) <= g(weight).
fn max_reduced_weight(min_original_weight: &[u32], weight: u32) -> u32 {
    min_original_weight
        .iter()
        .rposition(|&x| x <= weight)
        .expect("min_original_weight[0] = 0 always qualifies") as u32
}

/// Feasibility check of a candidate. Returns `(t', f')` if all constraints hold,
/// an error if liveness fails.
fn check_candidate(
    weights: &[u16],
    w_total: u16,
    t: u16,
    f: u16,
    delta: u16,
    reduced: &[u16],
) -> FastCryptoResult<(u16, u16)> {
    let reduced_total = reduced.iter().map(|&w| w as u32).sum::<u32>();
    let min_original_weight_map = knapsack_min_original(weights, reduced, reduced_total);

    // t' is the smallest threshold that maintains privacy (P): w(S) < t => w'(S) < t'.
    let tp = max_reduced_weight(&min_original_weight_map, (t - 1) as u32) + 1;

    // f' is the smallest bound satisfying (B): w(S) <= f => w'(S) <= f'.
    let fp = max_reduced_weight(&min_original_weight_map, f as u32);

    // Liveness (L1): w(S) >= t + delta => w'(S) >= t'.
    // Checked via the complement T of the worst such S:
    //   min { w'(S) : w(S) >= t + delta } = W' - max { w'(T) : w(T) <= W - t - delta }.
    let b1 = (w_total as u32) - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < tp {
        return Err(FastCryptoError::GeneralError("L1 violated".to_string()));
    }

    // Liveness (L2): w(S) >= t + f + delta => w'(S) >= t' + f'.
    // Checked via the complement T of the worst such S:
    //   min { w'(S) : w(S) >= t + f + delta } = W' - max { w'(T) : w(T) <= W - t - f - delta }.
    let b2 = (w_total as u32) - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2) < tp + fp {
        return Err(FastCryptoError::GeneralError("L2 violated".to_string()));
    }

    // tp <= t and fp <= f, so both fit u16.
    Ok((tp as u16, fp as u16))
}

/// Verifier for a candidate reduction: checks conditions (P), (B), (L1), and (L2)
/// for an arbitrary `(weights', t', f')` in `O(n * W')` time. Returns
/// `InvalidInput` for malformed inputs and a `GeneralError` naming the first
/// violated condition otherwise.
pub(crate) fn verify_reduction(
    weights: &[u16],
    t: u16,
    f: u16,
    delta: u16,
    reduction: &ReducedWeights,
) -> FastCryptoResult<()> {
    let w_total = weights.iter().map(|&w| w as u32).sum::<u32>();
    let reduced_total = reduction.weights.iter().map(|&w| w as u32).sum::<u32>();
    if weights.len() != reduction.weights.len()
        || weights.len() > MAX_PARTIES
        || t == 0
        || (t as u32) > w_total
        || w_total > u16::MAX as u32
        || reduced_total > u16::MAX as u32
        || reduction.t == 0
    {
        return Err(FastCryptoError::InvalidInput);
    }
    // Same sanity checks as reduce_weights, in both spaces. The reduced-space
    // feasibility t' + 2f' <= W' is required by the protocols run on the
    // reduced weights (e.g., AVID); reduce_weights outputs satisfy it by the
    // module-docs argument, but arbitrary candidates need the explicit check.
    if f >= t
        || reduction.f >= reduction.t
        || (t as u32) + 2 * (f as u32) + (delta as u32) > w_total
        || (reduction.t as u32) + 2 * (reduction.f as u32) > reduced_total
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let min_original_weight_map = knapsack_min_original(weights, &reduction.weights, reduced_total);

    // (P): max { w'(S) : w(S) <= t-1 } <= t' - 1.
    if max_reduced_weight(&min_original_weight_map, (t - 1) as u32) > (reduction.t - 1) as u32 {
        return Err(FastCryptoError::GeneralError("P violated".to_string()));
    }

    // (B): max { w'(S) : w(S) <= f } <= f'.
    if max_reduced_weight(&min_original_weight_map, f as u32) > reduction.f as u32 {
        return Err(FastCryptoError::GeneralError("B violated".to_string()));
    }

    // (L1): min { w'(S) : w(S) >= t + delta } >= t'.
    let b1 = w_total - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < reduction.t as u32 {
        return Err(FastCryptoError::GeneralError("L1 violated".to_string()));
    }

    // (L2): min { w'(S) : w(S) >= t + f + delta } >= t' + f'.
    let b2 = w_total - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2)
        < reduction.t as u32 + reduction.f as u32
    {
        return Err(FastCryptoError::GeneralError("L2 violated".to_string()));
    }
    Ok(())
}
