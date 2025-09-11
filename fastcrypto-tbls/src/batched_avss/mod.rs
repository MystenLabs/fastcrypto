// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use serde::{Deserialize, Serialize};

pub mod avss;
mod certificate;
pub(crate) mod complaint;
pub mod dkg;
mod ro_extension;

/// Convenience trait for types that can be serialized/deserialized to/from bytes using BCS.
pub trait BCSSerialized: Serialize + for<'de> Deserialize<'de> {
    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).unwrap()
    }

    fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self>
    where
        Self: Sized,
    {
        bcs::from_bytes(bytes).map_err(|_| FastCryptoError::InvalidInput)
    }
}
