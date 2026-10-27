// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integers modulo `Q`.

use crate::error::FastCryptoError;
use crate::groups::RejectionSample;
use serde::{Deserialize, Serialize};
use std::ops::{AddAssign, SubAssign};

/// An integer modulo `Q`, stored as a reduced `u32`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Zq32<const Q: u32>(u32);

impl<const Q: u32> TryFrom<u32> for Zq32<Q> {
    type Error = FastCryptoError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value >= Q {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self(value))
    }
}

impl<const Q: u32> From<Zq32<Q>> for u32 {
    fn from(value: Zq32<Q>) -> Self {
        value.0
    }
}

impl<const Q: u32> AddAssign for Zq32<Q> {
    /// Both inputs are below `Q`, so the sum is below 2Q and at most one subtraction of `Q` is
    /// needed.
    fn add_assign(&mut self, other: Self) {
        // There are three cases:
        // 1. No overflow and s < Q: the sum is s.
        // 2. No overflow and s >= Q: the sum is s - Q, and wrapping_sub does not wrap.
        // 3. Overflow: the sum is s + 2^32 and s < Q, so s.wrapping_sub(Q) gives s + 2^32 - Q.
        let (s, overflow) = self.0.overflowing_add(other.0);
        self.0 = if overflow || s >= Q {
            s.wrapping_sub(Q)
        } else {
            s
        };
    }
}

impl<const Q: u32> SubAssign for Zq32<Q> {
    fn sub_assign(&mut self, other: Self) {
        let (d, borrow) = self.0.overflowing_sub(other.0);
        self.0 = if borrow { d.wrapping_add(Q) } else { d };
    }
}

impl<const Q: u32> RejectionSample for Zq32<Q> {
    /// Samples little-endian u32s and rejects values that are not below `Q`.
    fn sample<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        loop {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            let value = u32::from_le_bytes(bytes);
            if value < Q {
                return Ok(Self(value));
            }
        }
    }
}
