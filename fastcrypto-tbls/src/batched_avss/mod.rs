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

/// This represents a set of shares for a node. A total of L secrets/nonces are being shared,
/// If we say that node <i>i</i> has a weight `W_i`, we have
/// `indices().len() == shares_for_index(i).len() == weight() = W_i`
pub trait SharesForNode<C>:
    Serialize + for<'de> Deserialize<'de> + Clone + std::fmt::Debug
{
    fn weight(&self) -> usize;

    fn shares_for_secret(&self, i: usize) -> FastCryptoResult<Vec<Eval<C>>>; // W_i shares for secret i

    fn indices(&self) -> Vec<ShareIndex>;

    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).unwrap()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> FastCryptoResult<Self> {
        bcs::from_bytes(bytes.as_ref()).map_err(|_| InvalidInput)
    }

    /// Assuming that enough shares are given, recover the shares for this node.
    fn recover(indices: Vec<ShareIndex>, other_shares: &[Self]) -> FastCryptoResult<Self>;

    /// The size of the batch (number of secrets/nonces being shared).
    fn batch_size(&self) -> usize;
}
