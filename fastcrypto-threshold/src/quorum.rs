// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The quorum check of AVID, formally verified with Creusot: `check_quorum` returns `Ok` only if
//! the senders are nonempty, valid and distinct with enough weight, and it never panics or
//! overflows. To check the proof, install Creusot 0.14.0 and run `cargo creusot` in
//! that crate.
//!
//! The annotations only apply under `cfg(creusot)`, so this crate does not depend on Creusot. The
//! crate that runs the proof is in verification/fastcrypto-threshold/avid_quorum, and includes this
//! file directly.

#[cfg(creusot)]
use creusot_std::prelude::{vec, *};
use fastcrypto::error::FastCryptoError::{InvalidInput, NotEnoughWeight};
use fastcrypto::error::FastCryptoResult;

type PartyId = u16;

/// The sum of `weights[senders[i]]` for `i < k`.
#[cfg(creusot)]
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
#[cfg(creusot)]
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

/// Checks that `senders` are distinct parties, with total weight at least `required`.
/// `weights[i]` is the weight of party `i`.
#[cfg_attr(creusot, requires(weights@.len() <= 65536))]
#[cfg_attr(creusot, ensures(match result { Ok(_) => is_quorum(senders@, weights@, required@), Err(_) => true }))]
#[cfg_attr(creusot, ensures(is_quorum(senders@, weights@, required@) && senders@.len() <= weights@.len()
    ==> match result { Ok(_) => true, Err(_) => false }))]
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
    #[cfg_attr(creusot, invariant(i@ <= senders@.len()))]
    #[cfg_attr(creusot, invariant(seen@.len() == weights@.len()))]
    #[cfg_attr(creusot, invariant(forall<x: Int> 0 <= x && x < seen@.len()
        ==> seen@[x] == (exists<k: Int> 0 <= k && k < i@ && senders@[k]@ == x)))]
    #[cfg_attr(creusot, invariant(forall<k: Int> 0 <= k && k < i@ ==> senders@[k]@ < weights@.len()))]
    #[cfg_attr(creusot, invariant(forall<a: Int, b: Int> 0 <= a && a < b && b < i@ ==> senders@[a] != senders@[b]))]
    #[cfg_attr(creusot, invariant(total@ == sender_weight(senders@, weights@, i@)))]
    #[cfg_attr(creusot, invariant(total@ <= i@ * 65535))]
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
