// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Annotated copy of the verified functions in `fastcrypto-tbls/src/knapsack_weight_reduction.rs`
//! (the region between `BEGIN CREUSOT-VERIFIED` and `END CREUSOT-VERIFIED`), with their Creusot
//! contracts, loop invariants and proof steps. See README.md for what is proved.
//!
//! The test `creusot_copy_matches_production` in transform_code_test.rs checks that this region, with
//! the annotations and comments removed, is token-for-token the production code. Only these
//! kinds of annotations may be added, each on its own lines: `#[requires]`, `#[ensures]`,
//! `#[invariant]`, `#[variant]`, `proof_assert!` statements and `let x = snapshot!` statements.

use creusot_std::prelude::{vec, *};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};

// Stand-ins for the production definitions the verified functions use.
const MAX_PARTIES: usize = 1000;

pub struct ReducedWeights {
    pub weights: Vec<u16>,
    pub t: u16,
    pub f: u16,
}

// ---------------------------------------------------------------------------------------------
// Logic definitions, used only in the proofs. A subset `S` is modelled as a sequence of booleans
// `s`: party `i` is in `S` iff `s[i]`.
// ---------------------------------------------------------------------------------------------

/// `sum { ws[i] : i < k, s[i] == b }`: the weight of the subset `s` (if `b`) or of its
/// complement (if `!b`), restricted to the first `k` parties.
#[logic(open)]
#[variant(k)]
pub fn wsum(ws: Seq<u16>, s: Seq<bool>, b: bool, k: Int) -> Int {
    pearlite! {
        if k <= 0 {
            0
        } else {
            wsum(ws, s, b, k - 1) + if s[k - 1] == b { ws[k - 1]@ } else { 0 }
        }
    }
}

/// `sum { ws[i] : i < k }`.
#[logic(open)]
#[variant(k)]
pub fn total(ws: Seq<u16>, k: Int) -> Int {
    pearlite! {
        if k <= 0 { 0 } else { total(ws, k - 1) + ws[k - 1]@ }
    }
}

/// A subset and its complement partition the parties.
#[logic]
#[variant(k)]
#[ensures(forall<s: Seq<bool>> wsum(ws, s, true, k) + wsum(ws, s, false, k) == total(ws, k))]
pub fn lemma_complement(ws: Seq<u16>, k: Int) {
    pearlite! {
        if k > 0 { lemma_complement(ws, k - 1) }
    }
}

/// `total` is non-decreasing.
#[logic]
#[variant(k - j)]
#[requires(j <= k)]
#[ensures(total(ws, j) <= total(ws, k))]
pub fn lemma_total_mono(ws: Seq<u16>, j: Int, k: Int) {
    pearlite! {
        if j < k { lemma_total_mono(ws, j, k - 1) }
    }
}

// BEGIN CREUSOT-VERIFIED

/// The sum of `values`. Doesn't overflow as long as `values.len() <= 65537`.
#[requires(values@.len() <= 65537)]
#[ensures(result@ == total(values@, values@.len()))]
pub(crate) fn sum_u16(values: &[u16]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    #[invariant(i@ <= values@.len())]
    #[invariant(sum@ == total(values@, i@))]
    #[invariant(sum@ <= i@ * 65535)]
    while i < values.len() {
        sum += values[i] as u32;
        i += 1;
    }
    sum
}

/// The value-space knapsack table `min_original_weight[v] = min { w(S) : w'(S) = v }` for
/// `v in [0, W']`, computed in `O(n * W')`.
///
/// The proof only establishes that `min_original_weight[w'(S)] <= w(S)` for every subset `S`,
/// i.e. that each entry is at most the true minimum. That is the direction soundness needs.
#[requires(weights@.len() == reduced@.len())]
#[requires(reduced_total@ == total(reduced@, reduced@.len()))]
#[requires(total(weights@, weights@.len()) <= 65535)]
#[ensures(result@.len() == reduced_total@ + 1)]
#[ensures(result@[0]@ == 0)]
#[ensures(forall<s: Seq<bool>, b: bool>
    0 <= wsum(reduced@, s, b, reduced@.len())
    && wsum(reduced@, s, b, reduced@.len()) <= reduced_total@
    && result@[wsum(reduced@, s, b, reduced@.len())]@ <= wsum(weights@, s, b, weights@.len()))]
pub(crate) fn knapsack_min_original(
    weights: &[u16],
    reduced: &[u16],
    reduced_total: u32,
) -> Vec<u32> {
    let mut min_original_weight = vec![u32::MAX; reduced_total as usize + 1];
    min_original_weight[0] = 0;
    let n = weights.len().min(reduced.len());
    let mut i = 0;
    #[invariant(n@ == weights@.len())]
    #[invariant(0 <= i@ && i@ <= n@)]
    #[invariant(min_original_weight@.len() == reduced_total@ + 1)]
    #[invariant(min_original_weight@[0]@ == 0)]
    #[invariant(forall<u: Int> 0 <= u && u < min_original_weight@.len() ==>
        min_original_weight@[u] == u32::MAX || min_original_weight@[u]@ <= total(weights@, i@))]
    #[invariant(forall<s: Seq<bool>, b: bool>
        0 <= wsum(reduced@, s, b, i@) && wsum(reduced@, s, b, i@) <= total(reduced@, i@))]
    #[invariant(forall<s: Seq<bool>, b: bool>
        min_original_weight@[wsum(reduced@, s, b, i@)]@ <= wsum(weights@, s, b, i@))]
    while i < n {
        let w = weights[i] as u32;
        let q = reduced[i] as usize;
        proof_assert! {
            lemma_total_mono(reduced@, i@ + 1, n@);
            lemma_total_mono(weights@, i@ + 1, n@);
            total(reduced@, i@ + 1) <= reduced_total@ && total(weights@, i@ + 1) <= 65535
        };
        let old = snapshot! { min_original_weight };
        // Iterate downward so that each party is used at most once.
        let mut v = min_original_weight.len();
        #[invariant(min_original_weight@.len() == old@.len())]
        #[invariant(q@ <= v@ && v@ <= min_original_weight@.len())]
        // Entries below `v` are untouched.
        #[invariant(forall<u: Int> 0 <= u && u < v@ ==>
            min_original_weight@[u] == old@[u])]
        // Entries from `v` on have been relaxed with party `i`.
        #[invariant(forall<u: Int> v@ <= u && u < min_original_weight@.len() ==>
            min_original_weight@[u]@ <= old@[u]@
            && (old@[u - q@] != u32::MAX ==> min_original_weight@[u]@ <= old@[u - q@]@ + w@))]
        #[invariant(forall<u: Int> 0 <= u && u < min_original_weight@.len() ==>
            min_original_weight@[u] == u32::MAX
            || min_original_weight@[u]@ <= total(weights@, i@ + 1))]
        while v > q {
            v -= 1;
            if min_original_weight[v - q] != u32::MAX {
                let candidate = min_original_weight[v - q] + w;
                if candidate < min_original_weight[v] {
                    min_original_weight[v] = candidate;
                }
            }
        }
        i += 1;
    }
    min_original_weight
}

/// `g(weight) = max { w'(S) : w(S) <= weight }`.
/// In other words, the largest reduced weight a subset can have while its
/// original weight <= `weight`: w(S) <= weight => w'(S) <= g(weight).
#[requires(
    min_original_weight@.len() >= 1 && min_original_weight@.len() <= 65536)]
#[requires(min_original_weight@[0]@ == 0)]
#[ensures(result@ < min_original_weight@.len())]
#[ensures(forall<u: Int> 0 <= u && u < min_original_weight@.len()
    && min_original_weight@[u]@ <= weight@ ==> u <= result@)]
pub(crate) fn max_reduced_weight(min_original_weight: &[u32], weight: u32) -> u32 {
    let mut v = min_original_weight.len();
    #[invariant(v@ <= min_original_weight@.len())]
    #[invariant(forall<u: Int> v@ <= u && u < min_original_weight@.len() ==>
        min_original_weight@[u]@ > weight@)]
    while v > 0 {
        v -= 1;
        if min_original_weight[v] <= weight {
            return v as u32;
        }
    }
    panic!("min_original_weight[0] = 0 always qualifies")
}

/// Verifier for a candidate reduction: checks conditions (P), (L1), (L2), and (L3)
/// for an arbitrary `(weights', t', f')` in `O(n * W')` time. Returns
/// `InvalidInput` for malformed inputs and a `GeneralError` naming the first
/// violated condition otherwise.
///
/// Main theorem: if it accepts, (P), (L1), (L2) and (L3) hold for every subset of the parties.
#[ensures(match result {
    Ok(_) => forall<s: Seq<bool>>
        (wsum(weights@, s, true, weights@.len()) < t@
            ==> wsum(reduction.weights@, s, true, weights@.len()) < reduction.t@)
        && (wsum(weights@, s, true, weights@.len()) >= t@ + f@ + delta@
            ==> wsum(reduction.weights@, s, true, weights@.len()) >= reduction.t@ + reduction.f@)
        && (wsum(weights@, s, true, weights@.len()) <= f@
            ==> wsum(reduction.weights@, s, true, weights@.len()) <= reduction.f@)
        && (wsum(weights@, s, true, weights@.len()) >= t@ + delta@
            ==> wsum(reduction.weights@, s, true, weights@.len()) >= reduction.t@),
    Err(_) => true,
})]
pub(crate) fn verify_reduction(
    weights: &[u16],
    t: u16,
    f: u16,
    delta: u16,
    reduction: &ReducedWeights,
) -> FastCryptoResult<()> {
    // Check the lengths first so that the sums below cannot overflow.
    if weights.len() != reduction.weights.len() || weights.len() > MAX_PARTIES {
        return Err(FastCryptoError::InvalidInput);
    }
    let w_total = sum_u16(weights);
    let reduced_total = sum_u16(&reduction.weights);
    if t == 0
        || f == 0
        || (t as u32) > w_total
        || w_total > u16::MAX as u32
        || reduced_total > u16::MAX as u32
        || reduction.t == 0
        || reduction.f == 0
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
    proof_assert! {
        lemma_complement(weights@, weights@.len());
        lemma_complement(reduction.weights@, weights@.len());
        true
    };

    // (P): max { w'(S) : w(S) <= t-1 } <= t' - 1.
    if max_reduced_weight(&min_original_weight_map, (t - 1) as u32) > (reduction.t - 1) as u32 {
        return Err(FastCryptoError::GeneralError("P violated".to_owned()));
    }

    // (L2): max { w'(S) : w(S) <= f } <= f'.
    if max_reduced_weight(&min_original_weight_map, f as u32) > reduction.f as u32 {
        return Err(FastCryptoError::GeneralError("L2 violated".to_owned()));
    }

    // (L3): min { w'(S) : w(S) >= t + delta } >= t'.
    let b1 = w_total - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < reduction.t as u32 {
        return Err(FastCryptoError::GeneralError("L3 violated".to_owned()));
    }

    // (L1): min { w'(S) : w(S) >= t + f + delta } >= t' + f'.
    let b2 = w_total - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2)
        < reduction.t as u32 + reduction.f as u32
    {
        return Err(FastCryptoError::GeneralError("L1 violated".to_owned()));
    }
    Ok(())
}
// END CREUSOT-VERIFIED
