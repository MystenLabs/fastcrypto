// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Annotated copy of `Party::merge` and `UsedProcessedMessages::from` in
//! `fastcrypto-threshold/src/dkg_v1.rs`, and of `Nodes::node_id_to_node` in
//! `fastcrypto-threshold/src/nodes.rs` (the regions between the `BEGIN VERUS-VERIFIED: <name>` and
//! `END VERUS-VERIFIED: <name>` markers), with their Verus contracts, loop invariants and proof
//! steps. See README.md for what is proved.
//!
//! The test `verus_copy_matches_production` in transform_code_test.rs checks that each region,
//! with the annotations and comments removed, is token-for-token the production code. Only
//! `#[verus_spec(...)]` attributes and `proof! { ... }` statements may be added.
//!
//! Verus can't use fastcrypto's `GroupElement` trait (see README.md), so the types below are
//! stand-ins for the production types, without the `GroupElement` bounds. They keep the fields the
//! verified functions use and replace the others with `Opaque`. Since the verified functions don't
//! use the bounds, proving them for every `G` and `EG` covers the production code.

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use std::collections::HashSet;
use vstd::prelude::*;

// Stand-ins for the `tracing` macros: no-ops, so their arguments are not verified.
macro_rules! debug {
    ($($t:tt)*) => {};
}
macro_rules! info {
    ($($t:tt)*) => {};
}
macro_rules! error {
    ($($t:tt)*) => {};
}

verus! {

broadcast use vstd::std_specs::hash::group_hash_axioms;

#[verifier::external_type_specification]
pub struct ExFastCryptoError(FastCryptoError);

// ---------------------------------------------------------------------------------------------
// Stand-ins for the production types (see the comment at the top of the file).
// ---------------------------------------------------------------------------------------------

pub type PartyId = u16;

/// Stand-in for the fields the verified functions don't look at.
#[verifier::external_body]
#[verifier::reject_recursive_types(T)]
pub struct Opaque<T>(core::marker::PhantomData<T>);

#[verifier::reject_recursive_types(G)]
pub struct Node<G> {
    pub id: PartyId,
    pub pk: Opaque<G>,
    pub weight: u16,
}

#[verifier::reject_recursive_types(G)]
pub struct Nodes<G> {
    pub nodes: Vec<Node<G>>,
}

#[verifier::external_body]
#[verifier::reject_recursive_types(EG)]
pub struct Complaint<EG>(Opaque<EG>);

// The derived `Clone` of the production types copies the value.
impl<EG> Clone for Complaint<EG> {
    #[verifier::external_body]
    fn clone(&self) -> (r: Self)
        ensures r == *self,
    {
        unimplemented!()
    }
}

#[verifier::reject_recursive_types(G)]
#[verifier::reject_recursive_types(EG)]
pub struct Message<G, EG> {
    pub sender: PartyId,
    pub vss_pk: Opaque<G>,
    pub encrypted_shares: Opaque<EG>,
}

#[verifier::reject_recursive_types(G)]
#[verifier::reject_recursive_types(EG)]
pub struct ProcessedMessage<G, EG> {
    pub message: Message<G, EG>,
    pub shares: Opaque<G>,
    pub complaint: Option<Complaint<EG>>,
}

impl<G, EG> Clone for ProcessedMessage<G, EG> {
    #[verifier::external_body]
    fn clone(&self) -> (r: Self)
        ensures r == *self,
    {
        unimplemented!()
    }
}

#[verifier::reject_recursive_types(EG)]
pub struct Confirmation<EG> {
    pub sender: PartyId,
    pub complaints: Vec<Complaint<EG>>,
}

#[verifier::reject_recursive_types(G)]
#[verifier::reject_recursive_types(EG)]
pub struct UsedProcessedMessages<G, EG>(pub Vec<ProcessedMessage<G, EG>>);

#[verifier::reject_recursive_types(G)]
#[verifier::reject_recursive_types(EG)]
pub struct Party<G, EG> {
    pub id: PartyId,
    pub nodes: Nodes<EG>,
    pub t: u16,
    pub old_t: Option<u16>,
    pub rest: Opaque<G>,
}

// ---------------------------------------------------------------------------------------------
// Spec definitions.
// ---------------------------------------------------------------------------------------------

// `from` below states its own, stronger postcondition.
impl<'a, G, EG> vstd::std_specs::convert::FromSpecImpl<&'a [ProcessedMessage<G, EG>]>
    for UsedProcessedMessages<G, EG>
{
    open spec fn obeys_from_spec() -> bool {
        false
    }

    open spec fn from_spec(v: &'a [ProcessedMessage<G, EG>]) -> Self {
        arbitrary()
    }
}

/// The senders of `msgs`, in order.
pub open spec fn sender_seq<G, EG>(msgs: Seq<ProcessedMessage<G, EG>>) -> Seq<PartyId> {
    msgs.map_values(|m: ProcessedMessage<G, EG>| m.message.sender)
}

/// The set of senders of `msgs`.
pub open spec fn sender_set<G, EG>(msgs: Seq<ProcessedMessage<G, EG>>) -> Set<PartyId> {
    sender_seq(msgs).to_set()
}

/// `msgs` with only the first message of each sender, in order.
pub open spec fn first_by_sender<G, EG>(msgs: Seq<ProcessedMessage<G, EG>>) -> Seq<ProcessedMessage<G, EG>>
    decreases msgs.len(),
{
    if msgs.len() == 0 {
        msgs
    } else if sender_set(msgs.drop_last()).contains(msgs.last().message.sender) {
        first_by_sender(msgs.drop_last())
    } else {
        first_by_sender(msgs.drop_last()).push(msgs.last())
    }
}

/// The total weight of the senders of `msgs`.
pub open spec fn weight_of_senders<G, EG>(nodes: &Nodes<EG>, msgs: Seq<ProcessedMessage<G, EG>>) -> int
    decreases msgs.len(),
{
    if msgs.len() == 0 {
        0
    } else {
        weight_of_senders(nodes, msgs.drop_last())
            + nodes.nodes@[msgs.last().message.sender as int].weight as int
    }
}

/// The complaints in `msgs`, in order.
pub open spec fn complaints<G, EG>(msgs: Seq<ProcessedMessage<G, EG>>) -> Seq<Complaint<EG>>
    decreases msgs.len(),
{
    if msgs.len() == 0 {
        Seq::empty()
    } else {
        match msgs.last().complaint {
            Some(c) => complaints(msgs.drop_last()).push(c),
            None => complaints(msgs.drop_last()),
        }
    }
}

/// Adding a message adds its sender.
pub proof fn lemma_sender_seq_push<G, EG>(msgs: Seq<ProcessedMessage<G, EG>>, m: ProcessedMessage<G, EG>)
    ensures
        sender_seq(msgs.push(m)) == sender_seq(msgs).push(m.message.sender),
        sender_set(msgs.push(m)) == sender_set(msgs).insert(m.message.sender),
{
    broadcast use Seq::lemma_push_to_set_commute;
    assert(sender_seq(msgs.push(m)) =~= sender_seq(msgs).push(m.message.sender));
}

/// `first_by_sender` keeps a subset of the messages, with the same senders and no duplicates.
pub proof fn lemma_first_by_sender<G, EG>(msgs: Seq<ProcessedMessage<G, EG>>)
    ensures
        forall|j: int| 0 <= j < first_by_sender(msgs).len()
            ==> msgs.contains(#[trigger] first_by_sender(msgs)[j]),
        sender_set(first_by_sender(msgs)) == sender_set(msgs),
        sender_seq(first_by_sender(msgs)).no_duplicates(),
    decreases msgs.len(),
{
    if msgs.len() > 0 {
        let prefix = msgs.drop_last();
        let m = msgs.last();
        lemma_first_by_sender(prefix);
        assert(prefix.push(m) == msgs);
        lemma_sender_seq_push(prefix, m);
        let f = first_by_sender(prefix);
        assert forall|j: int| 0 <= j < first_by_sender(msgs).len()
            implies msgs.contains(#[trigger] first_by_sender(msgs)[j]) by {
            if j < f.len() {
                assert(prefix.contains(f[j]));
                let k = choose|k: int| 0 <= k < prefix.len() && prefix[k] == f[j];
                assert(msgs[k] == f[j]);
            } else {
                assert(msgs[msgs.len() - 1] == m);
            }
        }
        if !sender_set(prefix).contains(m.message.sender) {
            lemma_sender_seq_push(f, m);
        }
    }
}

/// At most `n` distinct ids are below `n`.
pub proof fn lemma_distinct_ids_bounded(ids: Seq<PartyId>, n: int)
    requires
        ids.no_duplicates(),
        0 <= n,
        forall|i: int| 0 <= i < ids.len() ==> (#[trigger] ids[i] as int) < n,
    ensures
        ids.len() <= n,
{
    ids.unique_seq_to_set();
    let s = ids.to_set();
    let f = |v: PartyId| v as int;
    let t = s.map(f);
    vstd::set_lib::lemma_map_size(s, t, f);
    vstd::set_lib::lemma_int_range(0, n);
    assert forall|x: int| #[trigger] t.contains(x) implies vstd::set_lib::set_int_range(0, n).contains(x) by {
        let v = choose|v: PartyId| s.contains(v) && f(v) == x;
        assert(ids.contains(v));
    }
    vstd::set_lib::lemma_len_subset(t, vstd::set_lib::set_int_range(0, n));
}

} // verus!

#[verus_verify]
impl<G> Nodes<G> {
    // BEGIN VERUS-VERIFIED: node_id_to_node
    #[verus_spec(r =>
        ensures
            (party_id as int) < self.nodes@.len() ==> (r matches Ok(n) && *n == self.nodes@[party_id as int]),
            (party_id as int) >= self.nodes@.len() ==> r is Err,
    )]
    pub fn node_id_to_node(&self, party_id: PartyId) -> FastCryptoResult<&Node<G>> {
        self.nodes
            .get(party_id as usize)
            .ok_or(FastCryptoError::InvalidInput)
    }
    // END VERUS-VERIFIED: node_id_to_node
}

#[verus_verify]
impl<G, EG> From<&[ProcessedMessage<G, EG>]> for UsedProcessedMessages<G, EG> {
    // BEGIN VERUS-VERIFIED: used_processed_messages_from
    // Assumes all parties see the same order of messages.
    #[verus_spec(r =>
        ensures r.0@ == first_by_sender(msgs@),
    )]
    fn from(msgs: &[ProcessedMessage<G, EG>]) -> Self {
        // Keep the first message from each sender, in order.
        let mut senders = HashSet::new();
        let mut filtered = Vec::new();
        let mut i = 0;
        #[verus_spec(
            invariant
                i <= msgs@.len(),
                senders@ == sender_set(msgs@.take(i as int)),
                filtered@ == first_by_sender(msgs@.take(i as int)),
            decreases msgs@.len() - i,
        )]
        while i < msgs.len() {
            proof! {
                assert(msgs@.take(i as int + 1).drop_last() == msgs@.take(i as int));
                lemma_sender_seq_push(msgs@.take(i as int), msgs@[i as int]);
                assert(msgs@.take(i as int).push(msgs@[i as int]) == msgs@.take(i as int + 1));
            }
            if senders.insert(msgs[i].message.sender) {
                filtered.push(msgs[i].clone());
            }
            i += 1;
        }
        proof! {
            assert(msgs@.take(msgs@.len() as int) == msgs@);
        }
        Self(filtered)
    }
    // END VERUS-VERIFIED: used_processed_messages_from
}

#[verus_verify]
impl<G, EG> Party<G, EG> {
    // BEGIN VERUS-VERIFIED: merge
    #[verus_spec(r =>
        requires
            forall|i: int| 0 <= i < processed_messages@.len()
                ==> (#[trigger] processed_messages@[i]).message.sender < self.nodes.nodes@.len(),
        ensures
            r matches Ok((conf, used)) ==> {
                &&& used.0@ == first_by_sender(processed_messages@)
                &&& weight_of_senders(&self.nodes, used.0@) >= self.old_t.unwrap_or(self.t)
                &&& conf.sender == self.id
                &&& conf.complaints@ == complaints(used.0@)
                &&& exists|i: int| 0 <= i < used.0@.len() && (#[trigger] used.0@[i]).complaint is None
            },
    )]
    pub fn merge(
        &self,
        processed_messages: &[ProcessedMessage<G, EG>],
    ) -> FastCryptoResult<(Confirmation<EG>, UsedProcessedMessages<G, EG>)> {
        debug!("DKG: Trying to merge {} messages", processed_messages.len());
        let filtered_messages = UsedProcessedMessages::from(processed_messages);
        // Verify we have enough messages
        let mut total_weight = 0u32;
        let mut i = 0;
        proof! {
            lemma_first_by_sender(processed_messages@);
            let used = filtered_messages.0@;
            assert forall|j: int| 0 <= j < used.len()
                implies (#[trigger] used[j]).message.sender < self.nodes.nodes@.len() by {
                assert(processed_messages@.contains(used[j]));
            }
            // Party ids are u16, so at most 65536 senders are distinct.
            lemma_distinct_ids_bounded(sender_seq(used), 65536);
        }
        #[verus_spec(
            invariant
                i <= filtered_messages.0@.len(),
                filtered_messages.0@.len() <= 65536,
                forall|j: int| 0 <= j < filtered_messages.0@.len()
                    ==> (#[trigger] filtered_messages.0@[j]).message.sender < self.nodes.nodes@.len(),
                total_weight == weight_of_senders(&self.nodes, filtered_messages.0@.take(i as int)),
                total_weight <= i * 65535,
            decreases filtered_messages.0@.len() - i,
        )]
        while i < filtered_messages.0.len() {
            proof! {
                assert(filtered_messages.0@.take(i as int + 1).drop_last()
                    == filtered_messages.0@.take(i as int));
            }
            total_weight += self
                .nodes
                .node_id_to_node(filtered_messages.0[i].message.sender)
                .expect("checked in process_message")
                .weight as u32;
            i += 1;
        }
        proof! {
            assert(filtered_messages.0@.take(filtered_messages.0@.len() as int) == filtered_messages.0@);
        }
        let required_t = self.old_t.unwrap_or(self.t);
        if total_weight < (required_t as u32) {
            debug!("Merge failed with total weight {total_weight}");
            return Err(FastCryptoError::NotEnoughInputs);
        }

        info!("DKG: Merging messages with total weight {total_weight}");

        // Log used parties.
        debug!(
            "DKG: Using messages from parties: {}",
            filtered_messages
                .0
                .iter()
                .map(|m| m.message.sender.to_string())
                .collect::<Vec<String>>()
                .join(",")
        );

        let mut conf = Confirmation {
            sender: self.id,
            complaints: Vec::new(),
        };
        #[verus_spec(iter =>
            invariant
                conf.sender == self.id,
                conf.complaints@ == complaints(filtered_messages.0@.take(iter.index())),
        )]
        for m in &filtered_messages.0 {
            proof! {
                assert(filtered_messages.0@.take(iter.index() + 1).drop_last()
                    == filtered_messages.0@.take(iter.index()));
            }
            if let Some(complaint) = &m.complaint {
                info!("DKG: Including a complaint on party {}", m.message.sender);
                conf.complaints.push(complaint.clone());
            }
        }

        proof! {
            assert(filtered_messages.0@.take(filtered_messages.0@.len() as int) == filtered_messages.0@);
        }
        if filtered_messages.0.iter().all(
            #[verus_spec(b: bool => ensures b == m.complaint is Some)]
            |m| m.complaint.is_some(),
        ) {
            error!("DKG: All processed messages resulted in complaints, this should never happen");
            return Err(FastCryptoError::GeneralError(
                "All processed messages resulted in complaints".to_string(),
            ));
        }

        Ok((conf, filtered_messages))
    }
    // END VERUS-VERIFIED: merge
}
