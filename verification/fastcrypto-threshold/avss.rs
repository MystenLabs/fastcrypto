// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verus spec functions for `threshold_schnorr::avss`, compiled only when Verus runs. This is a
//! child module of `avss`, so it can read the private fields of its types.

use super::*;
pub use crate::verification::{spec_share_ids, spec_valid_id};
use vstd::prelude::*;

verus! {

/// `shares.verify(message, ids, receiver)` is `Ok`.
pub uninterp spec fn spec_verifies(
    shares: SharesForNode,
    message: Message,
    ids: Seq<ShareIndex>,
    receiver: PartyId,
) -> bool;

// Types of `avss` with only public fields. The specs look into the transparent ones but not the
// opaque ones. `Receiver`, `Message` and `VerifiedComplaintResponse` are declared in `avss.rs`,
// since a transparent declaration here cannot have private fields.
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExSharesForNode(SharesForNode);

#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExComplaint(Complaint);

#[verifier::external_type_specification]
pub struct ExAvssOutput(AvssOutput);

#[verifier::external_type_specification]
pub struct ExComplaintResponse(ComplaintResponse);

#[verifier::external_type_specification]
pub struct ExProcessedMessage(ProcessedMessage);

// Functions of `avss` that the proofs call but do not look into.

/// `shares.verify(message, ids, receiver)` is `Ok` exactly when `verifies(..)` holds.
pub assume_specification[ SharesForNode::verify ](
    shares: &SharesForNode,
    message: &Message,
    expected_share_ids: &[ShareIndex],
    receiver: PartyId,
) -> (r: FastCryptoResult<()>)
    ensures
        r is Ok <==> spec_verifies(*shares, *message, expected_share_ids@, receiver),
;

/// `my_indices()` is `share_ids_of(nodes, id)`, and its `unwrap` does not panic.
pub assume_specification[ Receiver::my_indices ](receiver: &Receiver) -> (r: Vec<ShareIndex>)
    ensures
        r@ == spec_share_ids(receiver.spec_nodes(), receiver.spec_id()),
;

pub assume_specification[ Receiver::recover_shares ](
    receiver: &Receiver,
    message: &Message,
    responses: Vec<VerifiedComplaintResponse>,
) -> FastCryptoResult<SharesForNode>;

pub assume_specification[ warn_unverified_recovery ](e: &FastCryptoError);

/// Whether `check_message` accepts `message` depends only on the message and the receiver's
/// shared configuration, not on its id or key.
pub assume_specification[ Receiver::check_message ](
    receiver: &Receiver,
    message: &Message,
) -> (r: FastCryptoResult<()>)
    ensures
        r is Ok <==> spec_message_ok(*message, receiver.spec_config()),
;

/// `check_message` accepts `message` for a receiver with this configuration.
pub uninterp spec fn spec_message_ok(message: Message, config: Config) -> bool;

/// The configuration that all receivers share: `nodes`, `params`, `sid` and `commitment`.
pub type Config = (Nodes<EG>, Parameters, Vec<u8>, Option<G>);

pub assume_specification[ Receiver::decrypt_my_shares ](
    receiver: &Receiver,
    message: &Message,
) -> FastCryptoResult<SharesForNode>;

pub assume_specification<R: AllowedRng>[ Receiver::create_complaint::<R> ](
    receiver: &Receiver,
    message: &Message,
    rng: &mut R,
) -> Complaint;

pub assume_specification[ Receiver::check_complaint ](
    receiver: &Receiver,
    message: &Message,
    accuser_id: PartyId,
    complaint: &Complaint,
    my_output: &AvssOutput,
) -> FastCryptoResult<()>;

/// `shares.clone()` is `shares`.
pub assume_specification[ <SharesForNode as Clone>::clone ](shares: &SharesForNode) -> (r: SharesForNode)
    ensures
        r == *shares,
;

/// `response_verifies`: for receivers `Rᵢ` and `Rⱼ` with the same `nodes`, if
/// `Rⱼ.process_message(m) = Valid(o)` and `Rⱼ.handle_complaint(m, i, c, o) = Ok(r)`, then
/// `Rᵢ.verify_complaint_response(m, j, r)` is `Ok`.
#[allow(dead_code)]
fn response_verifies<R: AllowedRng>(
    r_i: &Receiver,
    r_j: &Receiver,
    m: &Message,
    c: &Complaint,
    rng: &mut R,
)
    requires
        r_i.spec_nodes() == r_j.spec_nodes(),
{
    if let Ok(ProcessedMessage::Valid(o)) = r_j.process_message(m, rng) {
        if let Ok(r) = r_j.handle_complaint(m, r_i.id, c, &o) {
            let v = r_i.verify_complaint_response(m, r_j.id, r);
            assert(v is Ok);
        }
    }
}

/// `process_invalid_iff`: for receivers `Rᵢ` and `Rⱼ` configured alike,
/// `Rᵢ.process_message(m)` is `Err` exactly when `Rⱼ.process_message(m)` is.
#[allow(dead_code)]
fn process_invalid_iff<R: AllowedRng>(r_i: &Receiver, r_j: &Receiver, m: &Message, rng: &mut R)
    requires
        r_i.spec_config() == r_j.spec_config(),
{
    let a = r_i.process_message(m, rng);
    let b = r_j.process_message(m, rng);
    assert(a is Err <==> b is Err);
}

impl Receiver {
    /// This receiver's `nodes`.
    pub open(super) spec fn spec_nodes(&self) -> Nodes<EG> {
        self.nodes
    }

    /// This receiver's id.
    pub open(super) spec fn spec_id(&self) -> PartyId {
        self.id
    }

    /// This receiver's shared configuration.
    pub open(super) spec fn spec_config(&self) -> Config {
        (self.nodes, self.params, self.sid, self.commitment)
    }
}

impl VerifiedComplaintResponse {
    /// The party that sent this response.
    pub open(super) spec fn spec_responder_id(&self) -> PartyId {
        self.responder_id
    }
}

} // verus!
