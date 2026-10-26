// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vectors of integers modulo `Q`.

use crate::error::FastCryptoError;
use crate::groups::HashToGroupElement;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::{AddAssign, SubAssign};

/// A vector of `N` integers modulo `Q`, stored as reduced `u32`s.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ZqVectorU32Unchecked<N>")]
pub struct ZqVectorU32<const N: usize, const Q: u32> {
    #[serde_as(as = "[_; N]")]
    elements: [u32; N],
}

/// Deserialization target for [ZqVectorU32]. Elements must be reduced.
#[serde_as]
#[derive(Deserialize)]
struct ZqVectorU32Unchecked<const N: usize> {
    #[serde_as(as = "[_; N]")]
    elements: [u32; N],
}

impl<const N: usize, const Q: u32> TryFrom<ZqVectorU32Unchecked<N>> for ZqVectorU32<N, Q> {
    type Error = FastCryptoError;

    fn try_from(unchecked: ZqVectorU32Unchecked<N>) -> Result<Self, Self::Error> {
        if unchecked.elements.iter().any(|e| *e >= Q) {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Self {
            elements: unchecked.elements,
        })
    }
}

impl<const N: usize, const Q: u32> Default for ZqVectorU32<N, Q> {
    fn default() -> Self {
        Self { elements: [0; N] }
    }
}

impl<const N: usize, const Q: u32> AddAssign for ZqVectorU32<N, Q> {
    /// Both inputs are reduced, so one conditional subtraction of `Q` suffices. On u32 overflow,
    /// the sum is s + 2^32, and s.wrapping_sub(Q) gives s + 2^32 - Q.
    fn add_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements.iter())
            .for_each(|(a, b)| {
                let (s, overflow) = a.overflowing_add(*b);
                *a = if overflow || s >= Q {
                    s.wrapping_sub(Q)
                } else {
                    s
                };
            });
    }
}

impl<const N: usize, const Q: u32> SubAssign for ZqVectorU32<N, Q> {
    fn sub_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements.iter())
            .for_each(|(a, b)| {
                let (d, borrow) = a.overflowing_sub(*b);
                *a = if borrow { d.wrapping_add(Q) } else { d };
            });
    }
}

/// Number of elements sampled per XOF read in [ZqVectorU32::hash_to_group_element].
const ELEMENTS_PER_READ: usize = 64;

impl<const N: usize, const Q: u32> HashToGroupElement for ZqVectorU32<N, Q> {
    /// Elements are sampled from SHAKE256 as little-endian u32s with rejection of values that are
    /// not below `Q`.
    fn hash_to_group_element(msg: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut xof = sha3::Shake256::default();
        xof.update(msg);
        let mut reader = xof.finalize_xof();

        let mut elements = [0u32; N];
        let mut bytes = [0u8; 4 * ELEMENTS_PER_READ];
        for chunk in elements.chunks_mut(ELEMENTS_PER_READ) {
            let bytes = &mut bytes[..4 * chunk.len()];
            reader.read(bytes);
            chunk
                .iter_mut()
                .zip(bytes.chunks_exact(4))
                .for_each(|(e, b)| *e = u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        }
        for e in elements.iter_mut() {
            while *e >= Q {
                let mut resample = [0u8; 4];
                reader.read(&mut resample);
                *e = u32::from_le_bytes(resample);
            }
        }
        Self { elements }
    }
}
