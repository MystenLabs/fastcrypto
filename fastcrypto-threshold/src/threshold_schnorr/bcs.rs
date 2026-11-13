// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use serde::{Deserialize, Serialize};

/// Convenience trait for types that can be serialized/deserialized to/from bytes using BCS.
pub trait BCSSerialized: Serialize + for<'de> Deserialize<'de> {
    fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).unwrap()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> FastCryptoResult<Self>
    where
        Self: Sized,
    {
        bcs::from_bytes(bytes.as_ref()).map_err(|_| InvalidInput)
    }
}

/// The length of the ULEB128 encoding of `n`, which BCS uses for sequence lengths. See
/// <https://github.com/diem/bcs#uleb128-encoded-integers>.
pub(crate) fn uleb128_length(n: usize) -> usize {
    // Each byte holds 7 bits of `n`, and zero takes one byte.
    let bits = usize::BITS - n.leading_zeros();
    bits.div_ceil(7).max(1) as usize
}
