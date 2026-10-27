// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Integers modulo `Q`.

use crate::error::FastCryptoError;
use crate::groups::RejectionSample;
use digest::XofReader;
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
    /// Both inputs are reduced, so one conditional subtraction of `Q` suffices. On u32 overflow,
    /// the sum is s + 2^32, and s.wrapping_sub(Q) gives s + 2^32 - Q.
    fn add_assign(&mut self, other: Self) {
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
    fn sample<R: XofReader>(reader: &mut R) -> Self {
        loop {
            let mut bytes = [0u8; 4];
            reader.read(&mut bytes);
            let value = u32::from_le_bytes(bytes);
            if value < Q {
                return Self(value);
            }
        }
    }
}
