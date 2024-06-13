// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nizk::DdhTupleNizk;
use fastcrypto::groups::GroupElement;
use serde::{Deserialize, Serialize};

// TODO: Use ZeroizeOnDrop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateKey<G: GroupElement>(pub(crate) G::ScalarType);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey<G: GroupElement>(pub(crate) G);

/// A recovery package that allows decrypting a *specific* ECIES Encryption.
/// It also includes a NIZK proof of correctness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPackage<G: GroupElement> {
    pub(crate) ephemeral_key: G,
    pub(crate) proof: DdhTupleNizk<G>,
}

pub const AES_KEY_LENGTH: usize = 32;
