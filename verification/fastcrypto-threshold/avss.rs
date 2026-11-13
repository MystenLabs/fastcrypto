// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verus spec functions for `threshold_schnorr::avss`, compiled only when Verus runs. This is a
//! child module of `avss`, so it can read the private fields of its types.

use super::*;
pub use crate::verification::spec_share_ids;
use vstd::prelude::*;

verus! {

/// `shares.verify(message, ids, receiver)` is `Ok`.
pub uninterp spec fn spec_verifies(
    shares: SharesForNode,
    message: Message,
    ids: Seq<ShareIndex>,
    receiver: PartyId,
) -> bool;

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
