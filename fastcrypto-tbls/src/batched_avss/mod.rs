// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::Eval;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use serde::{Deserialize, Serialize};

pub mod avss;
mod certificate;
pub(crate) mod complaint;
pub mod dkg;
mod ro_extension;

/// This represents a set of shares for a node. A total of <i>L</i> secrets/nonces are being shared,
/// If we say that node <i>i</i> has a weight `W_i`, we have
/// `indices().len() == shares_for_secret(i).len() == weight() = W_i`
pub trait SharesForNode<C>:
    Serialize + for<'de> Deserialize<'de> + Clone + std::fmt::Debug
{
    /// Get the weight of this node (number of shares it has).
    fn weight(&self) -> usize;

    /// Get all shares this node has for the <i>i</i>-th secret/nonce in the batch.
    fn shares_for_secret(&self, i: usize) -> FastCryptoResult<Vec<Eval<C>>>; // W_i shares for secret i

    /// Get the indices of all shares this node has.
    fn indices(&self) -> Vec<ShareIndex>;

    /// Serialize to bytes using BCS. See also [from_bytes].
    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).unwrap()
    }

    /// Deserialize from bytes using BCS. See also [to_bytes].
    fn from_bytes(bytes: impl AsRef<[u8]>) -> FastCryptoResult<Self> {
        bcs::from_bytes(bytes.as_ref()).map_err(|_| InvalidInput)
    }

    /// Assuming that enough shares are given, recover the shares for this node.
    fn recover(indices: Vec<ShareIndex>, other_shares: &[Self]) -> FastCryptoResult<Self>;

    /// The size of the batch <i>L</i>.
    fn batch_size(&self) -> usize;
}
