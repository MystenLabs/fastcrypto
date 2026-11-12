// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The sender check of AVID, formally verified with Verus. The annotations only apply when Verus
//! runs, so this crate does not depend on it. To check the proof, install Verus and run
//! `verus --crate-type=lib fastcrypto-threshold/src/quorum.rs -Zcrate-attr='feature(proc_macro_hygiene)'`.

#[cfg(verus_keep_ghost)]
use vstd::{prelude::*, set_lib::*};

#[cfg(verus_keep_ghost)]
verus! {

/// `senders` is nonempty, and its elements are distinct parties `< n`.
pub open spec fn valid_senders(senders: Seq<u16>, n: int) -> bool {
    senders.len() > 0 && senders.no_duplicates() && forall|i: int| 0 <= i < senders.len() ==> senders[i] < n
}

/// The sum of `weights[s]` over the elements `s` of `senders`.
pub open spec fn weight_of(senders: Seq<u16>, weights: Seq<u16>) -> int
    decreases senders.len(),
{
    if senders.len() == 0 {
        0
    } else {
        weight_of(senders.drop_last(), weights) + weights[senders.last() as int]
    }
}

/// There are at most 2^16 distinct `u16`s.
proof fn lemma_distinct_len(s: Seq<u16>)
    requires
        s.no_duplicates(),
    ensures
        s.len() <= 65536,
{
    broadcast use vstd::seq_lib::group_seq_properties;
    let t = s.map_values(|x: u16| x as int);
    assert(t.no_duplicates());
    t.unique_seq_to_set();
    lemma_int_range(0, 65536);
    assert(t.to_set().subset_of(set_int_range(0, 65536)));
    lemma_len_subset(t.to_set(), set_int_range(0, 65536));
}

} // verus!

/// The total weight of `senders`, or `None` if they are not nonempty, distinct parties.
/// `weights[i]` is the weight of party `i`.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == if valid_senders(senders@, weights@.len() as int) {
        Some(weight_of(senders@, weights@) as u32)
    } else {
        None
    }
))]
pub(crate) fn senders_weight(senders: &[u16], weights: &[u16]) -> Option<u32> {
    if senders.is_empty() {
        return None;
    }
    let mut seen = vec![false; weights.len()];
    let mut total = 0u32;
    let mut i = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= senders.len(),
            seen@.len() == weights.len(),
            forall|x: int| 0 <= x < seen@.len() ==>
                (seen@[x] <==> exists|k: int| 0 <= k < i && senders@[k] == x),
            valid_senders(senders@.take(i as int), weights@.len() as int) || i == 0,
            total == weight_of(senders@.take(i as int), weights@),
            total <= i * 65535,
        decreases senders.len() - i
    ))]
    while i < senders.len() {
        let id = senders[i] as usize;
        if id >= weights.len() || seen[id] {
            return None;
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(senders@.take(i + 1).drop_last() =~= senders@.take(i as int));
            lemma_distinct_len(senders@.take(i + 1));
        }
        seen[id] = true;
        total += weights[id] as u32;
        i += 1;
    }
    #[cfg(verus_keep_ghost)]
    proof! { assert(senders@.take(i as int) =~= senders@); }
    Some(total)
}
