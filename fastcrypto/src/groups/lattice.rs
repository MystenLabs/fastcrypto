// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vectors of 32-bit lanes modulo a prime, used by lattice-based multiset hashes.

use crate::groups::HashToGroupElement;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::{AddAssign, SubAssign};

/// Number of lanes in a [LatticeVectorU32].
pub const LANES: usize = 1024;

/// Modulus for the lanes of a [LatticeVectorU32]. This is the largest prime below 2^32.
pub const MODULUS: u32 = 0xFFFF_FFFB;

/// A vector of [LANES] lanes modulo the prime [MODULUS].
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "LatticeVectorU32Unchecked")]
pub struct LatticeVectorU32 {
    #[serde_as(as = "[_; LANES]")]
    lanes: [u32; LANES],
}

/// Deserialization target for [LatticeVectorU32]. Lanes must be reduced.
#[serde_as]
#[derive(Deserialize)]
struct LatticeVectorU32Unchecked {
    #[serde_as(as = "[_; LANES]")]
    lanes: [u32; LANES],
}

impl TryFrom<LatticeVectorU32Unchecked> for LatticeVectorU32 {
    type Error = &'static str;

    fn try_from(unchecked: LatticeVectorU32Unchecked) -> Result<Self, Self::Error> {
        if unchecked.lanes.iter().any(|lane| *lane >= MODULUS) {
            return Err("LatticeVectorU32 lane is not reduced modulo the prime");
        }
        Ok(Self {
            lanes: unchecked.lanes,
        })
    }
}

impl Default for LatticeVectorU32 {
    fn default() -> Self {
        Self { lanes: [0; LANES] }
    }
}

impl AddAssign for LatticeVectorU32 {
    /// Both inputs are reduced, so one conditional subtraction of the modulus suffices. On u32
    /// overflow, the sum is s + 2^32, and s.wrapping_sub(modulus) gives s + 5.
    fn add_assign(&mut self, other: Self) {
        self.lanes
            .iter_mut()
            .zip(other.lanes.iter())
            .for_each(|(a, b)| {
                let (s, overflow) = a.overflowing_add(*b);
                *a = if overflow || s >= MODULUS {
                    s.wrapping_sub(MODULUS)
                } else {
                    s
                };
            });
    }
}

impl SubAssign for LatticeVectorU32 {
    fn sub_assign(&mut self, other: Self) {
        self.lanes
            .iter_mut()
            .zip(other.lanes.iter())
            .for_each(|(a, b)| {
                let (d, borrow) = a.overflowing_sub(*b);
                *a = if borrow { d.wrapping_add(MODULUS) } else { d };
            });
    }
}

impl HashToGroupElement for LatticeVectorU32 {
    /// Lanes are sampled from SHAKE256 with rejection, which happens with probability 5/2^32.
    fn hash_to_group_element(msg: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut xof = sha3::Shake256::default();
        xof.update(msg);
        let mut reader = xof.finalize_xof();
        let mut bytes = [0u8; 4 * LANES];
        reader.read(&mut bytes);

        let mut lanes = [0u32; LANES];
        lanes
            .iter_mut()
            .zip(bytes.chunks_exact(4))
            .for_each(|(lane, chunk)| {
                *lane = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                while *lane >= MODULUS {
                    let mut resample = [0u8; 4];
                    reader.read(&mut resample);
                    *lane = u32::from_le_bytes(resample);
                }
            });
        Self { lanes }
    }
}
