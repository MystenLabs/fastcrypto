// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vectors over the prime field of order [MODULUS], used by lattice-based multiset hashes.

use crate::groups::HashToGroupElement;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::{AddAssign, SubAssign};

/// The order of the prime field. This is the largest prime below 2^32.
pub const MODULUS: u32 = 0xFFFF_FFFB;

/// A vector of `N` elements of the prime field of order [MODULUS].
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PrimeFieldVectorUnchecked<N>")]
pub struct PrimeFieldVector<const N: usize> {
    #[serde_as(as = "[_; N]")]
    elements: [u32; N],
}

/// Deserialization target for [PrimeFieldVector]. Elements must be reduced.
#[serde_as]
#[derive(Deserialize)]
struct PrimeFieldVectorUnchecked<const N: usize> {
    #[serde_as(as = "[_; N]")]
    elements: [u32; N],
}

impl<const N: usize> TryFrom<PrimeFieldVectorUnchecked<N>> for PrimeFieldVector<N> {
    type Error = &'static str;

    fn try_from(unchecked: PrimeFieldVectorUnchecked<N>) -> Result<Self, Self::Error> {
        if unchecked.elements.iter().any(|e| *e >= MODULUS) {
            return Err("PrimeFieldVector element is not reduced modulo the prime");
        }
        Ok(Self {
            elements: unchecked.elements,
        })
    }
}

impl<const N: usize> Default for PrimeFieldVector<N> {
    fn default() -> Self {
        Self { elements: [0; N] }
    }
}

impl<const N: usize> AddAssign for PrimeFieldVector<N> {
    /// Both inputs are reduced, so one conditional subtraction of the modulus suffices. On u32
    /// overflow, the sum is s + 2^32, and s.wrapping_sub(modulus) gives s + 2^32 - modulus.
    fn add_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements.iter())
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

impl<const N: usize> SubAssign for PrimeFieldVector<N> {
    fn sub_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements.iter())
            .for_each(|(a, b)| {
                let (d, borrow) = a.overflowing_sub(*b);
                *a = if borrow { d.wrapping_add(MODULUS) } else { d };
            });
    }
}

/// Number of elements sampled per XOF read in [PrimeFieldVector::hash_to_group_element].
const ELEMENTS_PER_READ: usize = 64;

impl<const N: usize> HashToGroupElement for PrimeFieldVector<N> {
    /// Elements are sampled from SHAKE256 with rejection, which happens with probability 5/2^32.
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
            while *e >= MODULUS {
                let mut resample = [0u8; 4];
                reader.read(&mut resample);
                *e = u32::from_le_bytes(resample);
            }
        }
        Self { elements }
    }
}
