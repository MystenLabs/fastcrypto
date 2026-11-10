// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Annotated copy of the verified function in
//! `fastcrypto-threshold/src/threshold_schnorr/avid.rs` (the region between `BEGIN CREUSOT-VERIFIED`
//! and `END CREUSOT-VERIFIED`), with its Creusot contract and loop invariants. See README.md for
//! what is proved.
//!
//! The test `creusot_copy_matches_production` in transform_code_test.rs checks that this region,
//! with the annotations and comments removed, is token-for-token the production code.

use creusot_std::prelude::{vec, *};
use fastcrypto::error::FastCryptoError::{InvalidInput, NotEnoughWeight};
use fastcrypto::error::FastCryptoResult;

// Stand-in for the production definition.
type PartyId = u16;

/// The sum of `weights[senders[i]]` for `i < k`.
#[logic(open)]
#[variant(k)]
pub fn sender_weight(senders: Seq<u16>, weights: Seq<u16>, k: Int) -> Int {
    pearlite! {
        if k <= 0 {
            0
        } else {
            sender_weight(senders, weights, k - 1) + weights[senders[k - 1]@]@
        }
    }
}

/// `senders` is nonempty, every sender is a party, the senders are distinct, and their total
/// weight is at least `required`.
#[logic(open)]
pub fn is_quorum(senders: Seq<u16>, weights: Seq<u16>, required: Int) -> bool {
    pearlite! {
        senders.len() > 0
            && (forall<i: Int> 0 <= i && i < senders.len() ==> senders[i]@ < weights.len())
            && (forall<i: Int, j: Int> 0 <= i && i < j && j < senders.len()
                ==> senders[i] != senders[j])
            && required <= sender_weight(senders, weights, senders.len())
    }
}

// BEGIN CREUSOT-VERIFIED
// `decode_or_complain` calls this to check its echoes, and returns its error. It is formally
// verified with Creusot, on an annotated copy in verification/fastcrypto-threshold/avid_quorum, and
// a test there checks that the copy, minus its annotations, matches the code here. Changes here
// must be made there too.

/// Checks that `senders` are distinct parties, with total weight at least `required`.
/// `weights[i]` is the weight of party `i`.
#[requires(weights@.len() <= 65536)]
#[ensures(match result { Ok(_) => is_quorum(senders@, weights@, required@), Err(_) => true })]
#[ensures(is_quorum(senders@, weights@, required@) && senders@.len() <= weights@.len()
    ==> match result { Ok(_) => true, Err(_) => false })]
pub(crate) fn check_quorum(
    senders: &[PartyId],
    weights: &[u16],
    required: u16,
) -> FastCryptoResult<()> {
    if senders.is_empty() || senders.len() > weights.len() {
        return Err(InvalidInput);
    }
    let mut seen = vec![false; weights.len()];
    let mut total = 0u32;
    let mut i = 0;
    #[invariant(i@ <= senders@.len())]
    #[invariant(seen@.len() == weights@.len())]
    #[invariant(forall<x: Int> 0 <= x && x < seen@.len()
        ==> seen@[x] == (exists<k: Int> 0 <= k && k < i@ && senders@[k]@ == x))]
    #[invariant(forall<k: Int> 0 <= k && k < i@ ==> senders@[k]@ < weights@.len())]
    #[invariant(forall<a: Int, b: Int> 0 <= a && a < b && b < i@ ==> senders@[a] != senders@[b])]
    #[invariant(total@ == sender_weight(senders@, weights@, i@))]
    #[invariant(total@ <= i@ * 65535)]
    while i < senders.len() {
        let id = senders[i] as usize;
        if id >= weights.len() || seen[id] {
            return Err(InvalidInput);
        }
        seen[id] = true;
        total += weights[id] as u32;
        i += 1;
    }
    if total < required as u32 {
        return Err(NotEnoughWeight(required as usize));
    }
    Ok(())
}
// END CREUSOT-VERIFIED
