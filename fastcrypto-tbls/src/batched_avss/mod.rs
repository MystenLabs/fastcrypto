// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::batched_avss::Extension::{Challenge, Encryption, Recovery};
use crate::nodes::PartyId;
use crate::polynomial::Eval;
use crate::random_oracle::RandomOracle;
use crate::types::ShareIndex;
use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use serde::{Deserialize, Serialize};

pub mod avss;
pub mod dkg;

/// This represents a set of shares for a node:
///  * A total of L secrets/nonces are being shared,
///  * Node i has a weight W_i,
///
/// So the following holds: indices().len() == shares_for_index(i).len() == weight() = W_i
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

    fn batch_size(&self) -> usize {
        // TODO: Do we need to handle nodes with zero weight?
        self.shares_for_secret(0).map(|s| s.len()).unwrap_or(0)
    }
}

/// A certificate on a [Message].
pub trait Certificate<M> {
    fn is_valid(&self, message: &M, threshold: usize) -> bool;
    fn includes(&self, id: &PartyId) -> bool;
}

pub(crate) enum Extension {
    Recovery(PartyId),
    Encryption,
    Challenge,
}

/// Helper trait to extend a random oracle with context-specific strings.
pub(crate) trait RandomOracleExtensions {
    fn base(&self) -> &RandomOracle;

    /// Extend the base random oracle with a context-specific string.
    fn random_oracle_extension(&self, extension: Extension) -> RandomOracle {
        let extension_string = match extension {
            Recovery(accuser) => &format!("recovery of {accuser}"),
            Encryption => "encryption",
            Challenge => "challenge",
        };
        self.base().extend(extension_string)
    }
}
