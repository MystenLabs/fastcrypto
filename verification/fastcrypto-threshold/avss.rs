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

impl Receiver {
    /// This receiver's `nodes`.
    pub open(super) spec fn spec_nodes(&self) -> Nodes<EG> {
        self.nodes
    }

    /// This receiver's id.
    pub open(super) spec fn spec_id(&self) -> PartyId {
        self.id
    }
}

impl VerifiedComplaintResponse {
    /// The party that sent this response.
    pub open(super) spec fn spec_responder_id(&self) -> PartyId {
        self.responder_id
    }
}

} // verus!
