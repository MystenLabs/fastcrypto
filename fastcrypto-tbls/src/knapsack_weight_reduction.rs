// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Knapsack-verified weight reduction.
//!
//! Replaces weights `w_1..w_n` (total `W`) by smaller weights `w'_1..w'_n`
//! (total `W'`) and thresholds `t', f'`, minimizing `W'` while preserving the
//! security of the weighted protocols when instantiated with
//! `(t', f', W')` in place of `(t, f, W)`. Inputs are the privacy threshold
//! `t`, the Byzantine weight bound `f` (with `t > f`, `t + 2f <= W` and
//! `t + f + delta <= W` enforced), and the
//! allowed liveness degradation `delta` in original weight units.
//!
//! # Guarantees
//!
//! Let `g(b) = max { w'(S) : w(S) <= b }`, computed exactly by a knapsack DP,
//! and set `t' = g(t-1) + 1`, `f' = g(f)`. For every subset S of parties:
//!
//! - (P) Privacy: `w(S) < t  =>  w'(S) < t'`.
//! - (L1) Liveness: `w(S) >= t + f + delta  =>  w'(S) >= t' + f'`. Sets that
//!   could form a Byzantine-tolerant quorum originally still can.
//! - (L2) Byzantine bound: `w(S) <= f  =>  w'(S) <= f'`. Limits how much of
//!   the (L1) quorum might be Byzantine.
//! - (L3) Liveness: `w(S) >= t + delta  =>  w'(S) >= t'`. Sets that could
//!   reconstruct originally (with `delta` slack) still reach the reduced
//!   threshold.
//!
//! `t > f` => `t' > f'` follows from monotonicity of `g`.
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
        || (t as u32) + 2 * (f as u32) > total_weight
        || (t as u32) + (f as u32) + (delta as u32) > total_weight
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
        if reduced_total >= lower_bound as u32
            && !greedy_reject(weights, &reduced, w_total, t, f, delta, reduced_total)
        {
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

/// A cheap rejection test that costs `O(n log n)`. It never errs when claiming
/// infeasibility.
fn greedy_reject(
    weights: &[u16],
    reduced: &[u16],
    w_total: u16,
    t: u16,
    f: u16,
    delta: u16,
    reduced_total: u32,
) -> bool {
    // Sort by "density", i.e., reduced_weight/original_weight, densest first.
    // Densities are compared using cross-multiplication,
    // reduced_weight_a / original_weight_a > reduced_weight_b / original_weight_b <=>
    // reduced_weight_a * original_weight_b > reduced_weight_b * original_weight_a
    let mut by_density = (0..weights.len())
        .filter(|&i| reduced[i] > 0)
        .collect::<Vec<_>>();
    by_density.sort_by(|&a, &b| {
        ((reduced[b] as u32) * (weights[a] as u32))
            .cmp(&((reduced[a] as u32) * (weights[b] as u32)))
    });

    // Lower bound on g(weight): *any* ordering of the parties would work for a lower bound.
    // We chose the density-sorted ordering because it can be proven to guarantee:
    //  g(weight) − g_lower(weight) < max_i reduced_weight
    // thus fairly tight.
    let g_lower = |weight: u32| {
        let (mut remaining_weight, mut reduced_weight) = (weight, 0u32);
        for &i in &by_density {
            let w = weights[i] as u32;
            if w <= remaining_weight {
                remaining_weight -= w;
                reduced_weight += reduced[i] as u32;
            }
        }
        reduced_weight
    };

    // 1. (L3) requires w(S) >= t + delta => w'(S) >= t'. A set S has
    //    w(S) >= t + delta exactly when its complement T fits the budget
    //    w(T) = W - w(S) <= W - t - delta, and w'(S) = W' - w'(T), so
    //    minimizing w'(S) is maximizing w'(T):
    //      min { w'(S) : w(S) >= t + delta } = W' - g(W-t-delta) >= t'.
    // 2. Substituting t' = g(t-1) + 1 and rearranging:
    //      (L3) => g(t-1) + g(W-t-delta) <= W' - 1.
    //    Doing the same for (L1) with t' + f' = g(t-1) + 1 + g(f):
    //      (L1) => g(t-1) + g(f) + g(W-t-f-delta) <= W' - 1.
    // 3. g_lower(b) <= g(b) by construction.

    // Lower bound on (L3): g_lower(t-1) + g_lower(W-t-delta) <= W' - 1.
    if g_lower((t - 1) as u32) + g_lower(w_total as u32 - t as u32 - delta as u32) >= reduced_total
    {
        return true;
    }
    // Lower bound on (L1): g_lower(t-1) + g_lower(f) + g_lower(W-t-f-delta) <= W' - 1.
    g_lower((t - 1) as u32)
        + g_lower(f as u32)
        + g_lower(w_total as u32 - t as u32 - f as u32 - delta as u32)
        >= reduced_total
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

    // f' is the smallest bound satisfying (L2): w(S) <= f => w'(S) <= f'.
    let fp = max_reduced_weight(&min_original_weight_map, f as u32);

    // Liveness (L3): w(S) >= t + delta => w'(S) >= t'.
    // Checked via the complement T of the worst such S:
    //   min { w'(S) : w(S) >= t + delta } = W' - max { w'(T) : w(T) <= W - t - delta }.
    let b1 = (w_total as u32) - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < tp {
        return Err(FastCryptoError::GeneralError("L3 violated".to_string()));
    }

    // Liveness (L1): w(S) >= t + f + delta => w'(S) >= t' + f'.
    // Checked via the complement T of the worst such S:
    //   min { w'(S) : w(S) >= t + f + delta } = W' - max { w'(T) : w(T) <= W - t - f - delta }.
    let b2 = (w_total as u32) - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2) < tp + fp {
        return Err(FastCryptoError::GeneralError("L1 violated".to_string()));
    }

    // tp <= t and fp <= f, so both fit u16.
    Ok((tp as u16, fp as u16))
}

/// Verifier for a candidate reduction: checks conditions (P), (L1), (L2), and (L3)
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
    // Same sanity checks as reduce_weights, in both spaces.
    if f >= t
        || reduction.f >= reduction.t
        || (t as u32) + 2 * (f as u32) > w_total
        || (t as u32) + (f as u32) + (delta as u32) > w_total
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let min_original_weight_map = knapsack_min_original(weights, &reduction.weights, reduced_total);

    // (P): max { w'(S) : w(S) <= t-1 } <= t' - 1.
    if max_reduced_weight(&min_original_weight_map, (t - 1) as u32) > (reduction.t - 1) as u32 {
        return Err(FastCryptoError::GeneralError("P violated".to_string()));
    }

    // (L2): max { w'(S) : w(S) <= f } <= f'.
    if max_reduced_weight(&min_original_weight_map, f as u32) > reduction.f as u32 {
        return Err(FastCryptoError::GeneralError("L2 violated".to_string()));
    }

    // (L3): min { w'(S) : w(S) >= t + delta } >= t'.
    let b1 = w_total - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < reduction.t as u32 {
        return Err(FastCryptoError::GeneralError("L3 violated".to_string()));
    }

    // (L1): min { w'(S) : w(S) >= t + f + delta } >= t' + f'.
    let b2 = w_total - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2)
        < reduction.t as u32 + reduction.f as u32
    {
        return Err(FastCryptoError::GeneralError("L1 violated".to_string()));
    }
    Ok(())
}
