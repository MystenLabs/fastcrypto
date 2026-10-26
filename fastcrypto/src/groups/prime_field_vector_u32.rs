// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vectors over prime fields of order below 2^32, used by lattice-based multiset hashes.

use crate::groups::HashToGroupElement;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::{AddAssign, SubAssign};

/// A vector of `N` elements of the prime field of order `P`, stored as reduced `u32`s.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PrimeFieldVectorU32Unchecked<N>")]
pub struct PrimeFieldVectorU32<const N: usize, const P: u32> {
    #[serde_as(as = "[_; N]")]
    elements: [u32; N],
}

/// Deserialization target for [PrimeFieldVectorU32]. Elements must be reduced.
#[serde_as]
#[derive(Deserialize)]
struct PrimeFieldVectorU32Unchecked<const N: usize> {
    #[serde_as(as = "[_; N]")]
    elements: [u32; N],
}

impl<const N: usize, const P: u32> TryFrom<PrimeFieldVectorU32Unchecked<N>>
    for PrimeFieldVectorU32<N, P>
{
    type Error = &'static str;

    fn try_from(unchecked: PrimeFieldVectorU32Unchecked<N>) -> Result<Self, Self::Error> {
        if unchecked.elements.iter().any(|e| *e >= P) {
            return Err("PrimeFieldVectorU32 element is not reduced modulo the prime");
        }
        Ok(Self {
            elements: unchecked.elements,
        })
    }
}

impl<const N: usize, const P: u32> Default for PrimeFieldVectorU32<N, P> {
    fn default() -> Self {
        Self { elements: [0; N] }
    }
}

impl<const N: usize, const P: u32> AddAssign for PrimeFieldVectorU32<N, P> {
    /// Both inputs are reduced, so one conditional subtraction of `P` suffices. On u32 overflow,
    /// the sum is s + 2^32, and s.wrapping_sub(P) gives s + 2^32 - P.
    fn add_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements.iter())
            .for_each(|(a, b)| {
                let (s, overflow) = a.overflowing_add(*b);
                *a = if overflow || s >= P {
                    s.wrapping_sub(P)
                } else {
                    s
                };
            });
    }
}

impl<const N: usize, const P: u32> SubAssign for PrimeFieldVectorU32<N, P> {
    fn sub_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements.iter())
            .for_each(|(a, b)| {
                let (d, borrow) = a.overflowing_sub(*b);
                *a = if borrow { d.wrapping_add(P) } else { d };
            });
    }
}

/// Number of elements sampled per XOF read in [PrimeFieldVectorU32::hash_to_group_element].
const ELEMENTS_PER_READ: usize = 64;

impl<const N: usize, const P: u32> HashToGroupElement for PrimeFieldVectorU32<N, P> {
    /// Elements are sampled from SHAKE256 as little-endian u32s with rejection of values that are
    /// not below `P`.
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
            while *e >= P {
                let mut resample = [0u8; 4];
                reader.read(&mut resample);
                *e = u32::from_le_bytes(resample);
            }
        }
        Self { elements }
    }
}
