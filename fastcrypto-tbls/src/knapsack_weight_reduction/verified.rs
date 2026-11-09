// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The formally verified part of the weight reduction: the knapsack table and the checker
//! [verify_reduction].
//!
//! These functions are verified with [Creusot](https://github.com/creusot-rs/creusot), which
//! proves that [verify_reduction] is sound: whenever it accepts a reduction `(w', t', f')` of the
//! weights `w`, then for **every** subset `S` of the parties
//!
//! - (P)  `w(S) < t                 =>  w'(S) < t'`
//! - (L1) `w(S) >= t + f + delta    =>  w'(S) >= t' + f'`
//! - (L2) `w(S) <= f                =>  w'(S) <= f'`
//! - (L3) `w(S) >= t + delta        =>  w'(S) >= t'`
//!
//! and that none of these functions can panic or overflow. The proof annotations only exist when
//! compiling with `cfg(creusot)`, so they don't affect normal builds. See
//! `fastcrypto-tbls/verification/README.md` for how to run the proofs; changes to this file must
//! keep them passing.
//!
//! The code uses index loops rather than iterator adaptors because Creusot has no
//! specifications for most of the latter.

#[cfg(creusot)]
use creusot_std::{
    macros::*,
    prelude::{vec, Int, Seq},
};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};

pub(crate) const MAX_PARTIES: usize = 1000;

// ---------------------------------------------------------------------------------------------
// Logic definitions, used only in the proofs. A subset `S` is modelled as a sequence of booleans
// `s`: party `i` is in `S` iff `s[i]`.
// ---------------------------------------------------------------------------------------------

/// `sum { ws[i] : i < k, s[i] == b }`: the weight of the subset `s` (if `b`) or of its
/// complement (if `!b`), restricted to the first `k` parties.
#[cfg(creusot)]
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
#[cfg(creusot)]
#[logic(open)]
#[variant(k)]
pub fn total(ws: Seq<u16>, k: Int) -> Int {
    pearlite! {
        if k <= 0 { 0 } else { total(ws, k - 1) + ws[k - 1]@ }
    }
}

/// A subset and its complement partition the parties.
#[cfg(creusot)]
#[logic]
#[variant(k)]
#[ensures(forall<s: Seq<bool>> wsum(ws, s, true, k) + wsum(ws, s, false, k) == total(ws, k))]
pub fn lemma_complement(ws: Seq<u16>, k: Int) {
    pearlite! {
        if k > 0 { lemma_complement(ws, k - 1) }
    }
}

/// `total` is non-decreasing.
#[cfg(creusot)]
#[logic]
#[variant(k - j)]
#[requires(j <= k)]
#[ensures(total(ws, j) <= total(ws, k))]
pub fn lemma_total_mono(ws: Seq<u16>, j: Int, k: Int) {
    pearlite! {
        if j < k { lemma_total_mono(ws, j, k - 1) }
    }
}

// ---------------------------------------------------------------------------------------------
// Verified functions
// ---------------------------------------------------------------------------------------------

/// The sum of `values`. Doesn't overflow as long as `values.len() <= 65537`.
#[cfg_attr(creusot, requires(values@.len() <= 65537))]
#[cfg_attr(creusot, ensures(result@ == total(values@, values@.len())))]
pub(crate) fn sum_u16(values: &[u16]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    #[cfg_attr(creusot, invariant(i@ <= values@.len()))]
    #[cfg_attr(creusot, invariant(sum@ == total(values@, i@)))]
    #[cfg_attr(creusot, invariant(sum@ <= i@ * 65535))]
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
#[cfg_attr(creusot, requires(weights@.len() == reduced@.len()))]
#[cfg_attr(creusot, requires(reduced_total@ == total(reduced@, reduced@.len())))]
#[cfg_attr(creusot, requires(total(weights@, weights@.len()) <= 65535))]
#[cfg_attr(creusot, ensures(result@.len() == reduced_total@ + 1))]
#[cfg_attr(creusot, ensures(result@[0]@ == 0))]
#[cfg_attr(creusot, ensures(forall<s: Seq<bool>, b: bool>
    0 <= wsum(reduced@, s, b, reduced@.len())
    && wsum(reduced@, s, b, reduced@.len()) <= reduced_total@
    && result@[wsum(reduced@, s, b, reduced@.len())]@ <= wsum(weights@, s, b, weights@.len())))]
pub(crate) fn knapsack_min_original(
    weights: &[u16],
    reduced: &[u16],
    reduced_total: u32,
) -> Vec<u32> {
    let mut min_original_weight = vec![u32::MAX; reduced_total as usize + 1];
    min_original_weight[0] = 0;
    let n = weights.len().min(reduced.len());
    let mut i = 0;
    #[cfg_attr(creusot, invariant(n@ == weights@.len()))]
    #[cfg_attr(creusot, invariant(0 <= i@ && i@ <= n@))]
    #[cfg_attr(creusot, invariant(min_original_weight@.len() == reduced_total@ + 1))]
    #[cfg_attr(creusot, invariant(min_original_weight@[0]@ == 0))]
    #[cfg_attr(creusot, invariant(forall<u: Int> 0 <= u && u < min_original_weight@.len() ==>
        min_original_weight@[u] == u32::MAX || min_original_weight@[u]@ <= total(weights@, i@)))]
    #[cfg_attr(creusot, invariant(forall<s: Seq<bool>, b: bool>
        0 <= wsum(reduced@, s, b, i@) && wsum(reduced@, s, b, i@) <= total(reduced@, i@)))]
    #[cfg_attr(creusot, invariant(forall<s: Seq<bool>, b: bool>
        min_original_weight@[wsum(reduced@, s, b, i@)]@ <= wsum(weights@, s, b, i@)))]
    while i < n {
        let w = weights[i] as u32;
        let q = reduced[i] as usize;
        #[cfg(creusot)]
        proof_assert! {
            lemma_total_mono(reduced@, i@ + 1, n@);
            lemma_total_mono(weights@, i@ + 1, n@);
            total(reduced@, i@ + 1) <= reduced_total@ && total(weights@, i@ + 1) <= 65535
        };
        #[cfg(creusot)]
        let old = snapshot! { min_original_weight };
        // Iterate downward so that each party is used at most once.
        let mut v = min_original_weight.len();
        #[cfg_attr(creusot, invariant(min_original_weight@.len() == old@.len()))]
        #[cfg_attr(creusot, invariant(q@ <= v@ && v@ <= min_original_weight@.len()))]
        // Entries below `v` are untouched.
        #[cfg_attr(creusot, invariant(forall<u: Int> 0 <= u && u < v@ ==>
            min_original_weight@[u] == old@[u]))]
        // Entries from `v` on have been relaxed with party `i`.
        #[cfg_attr(creusot, invariant(forall<u: Int> v@ <= u && u < min_original_weight@.len() ==>
            min_original_weight@[u]@ <= old@[u]@
            && (old@[u - q@] != u32::MAX ==> min_original_weight@[u]@ <= old@[u - q@]@ + w@)))]
        #[cfg_attr(creusot, invariant(forall<u: Int> 0 <= u && u < min_original_weight@.len() ==>
            min_original_weight@[u] == u32::MAX
            || min_original_weight@[u]@ <= total(weights@, i@ + 1)))]
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
#[cfg_attr(creusot, requires(
    min_original_weight@.len() >= 1 && min_original_weight@.len() <= 65536))]
#[cfg_attr(creusot, requires(min_original_weight@[0]@ == 0))]
#[cfg_attr(creusot, ensures(result@ < min_original_weight@.len()))]
#[cfg_attr(creusot, ensures(forall<u: Int> 0 <= u && u < min_original_weight@.len()
    && min_original_weight@[u]@ <= weight@ ==> u <= result@))]
pub(crate) fn max_reduced_weight(min_original_weight: &[u32], weight: u32) -> u32 {
    let mut v = min_original_weight.len();
    #[cfg_attr(creusot, invariant(v@ <= min_original_weight@.len()))]
    #[cfg_attr(creusot, invariant(forall<u: Int> v@ <= u && u < min_original_weight@.len() ==>
        min_original_weight@[u]@ > weight@))]
    while v > 0 {
        v -= 1;
        if min_original_weight[v] <= weight {
            return v as u32;
        }
    }
    panic!("min_original_weight[0] = 0 always qualifies")
}

/// Verifier for a candidate reduction `(reduced, reduced_t, reduced_f)`: checks conditions (P),
/// (L1), (L2), and (L3) in `O(n * W')` time. Returns `InvalidInput` for malformed inputs and a
/// `GeneralError` naming the first violated condition otherwise.
#[cfg_attr(creusot, ensures(match result {
    Ok(_) => forall<s: Seq<bool>>
        (wsum(weights@, s, true, weights@.len()) < t@
            ==> wsum(reduced@, s, true, weights@.len()) < reduced_t@)
        && (wsum(weights@, s, true, weights@.len()) >= t@ + f@ + delta@
            ==> wsum(reduced@, s, true, weights@.len()) >= reduced_t@ + reduced_f@)
        && (wsum(weights@, s, true, weights@.len()) <= f@
            ==> wsum(reduced@, s, true, weights@.len()) <= reduced_f@)
        && (wsum(weights@, s, true, weights@.len()) >= t@ + delta@
            ==> wsum(reduced@, s, true, weights@.len()) >= reduced_t@),
    Err(_) => true,
}))]
pub(crate) fn verify_reduction(
    weights: &[u16],
    t: u16,
    f: u16,
    delta: u16,
    reduced: &[u16],
    reduced_t: u16,
    reduced_f: u16,
) -> FastCryptoResult<()> {
    // Check the lengths first so that the sums below cannot overflow.
    if weights.len() != reduced.len() || weights.len() > MAX_PARTIES {
        return Err(FastCryptoError::InvalidInput);
    }
    let w_total = sum_u16(weights);
    let reduced_total = sum_u16(reduced);
    if t == 0
        || f == 0
        || (t as u32) > w_total
        || w_total > u16::MAX as u32
        || reduced_total > u16::MAX as u32
        || reduced_t == 0
        || reduced_f == 0
    {
        return Err(FastCryptoError::InvalidInput);
    }
    // Same sanity checks as reduce_weights, in both spaces.
    if f >= t
        || reduced_f >= reduced_t
        || (t as u32) + 2 * (f as u32) > w_total
        || (t as u32) + (f as u32) + (delta as u32) > w_total
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let min_original_weight_map = knapsack_min_original(weights, reduced, reduced_total);
    #[cfg(creusot)]
    proof_assert! {
        lemma_complement(weights@, weights@.len());
        lemma_complement(reduced@, weights@.len());
        true
    };

    // (P): max { w'(S) : w(S) <= t-1 } <= t' - 1.
    if max_reduced_weight(&min_original_weight_map, (t - 1) as u32) > (reduced_t - 1) as u32 {
        return Err(FastCryptoError::GeneralError("P violated".to_owned()));
    }

    // (L2): max { w'(S) : w(S) <= f } <= f'.
    if max_reduced_weight(&min_original_weight_map, f as u32) > reduced_f as u32 {
        return Err(FastCryptoError::GeneralError("L2 violated".to_owned()));
    }

    // (L3): min { w'(S) : w(S) >= t + delta } >= t'.
    let b1 = w_total - (t as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b1) < reduced_t as u32 {
        return Err(FastCryptoError::GeneralError("L3 violated".to_owned()));
    }

    // (L1): min { w'(S) : w(S) >= t + f + delta } >= t' + f'.
    let b2 = w_total - (t as u32 + f as u32 + delta as u32);
    if reduced_total - max_reduced_weight(&min_original_weight_map, b2)
        < reduced_t as u32 + reduced_f as u32
    {
        return Err(FastCryptoError::GeneralError("L1 violated".to_owned()));
    }
    Ok(())
}
