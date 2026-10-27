// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vectors of group elements with element-wise addition.

use crate::groups::{HashToGroupElement, RejectionSample};
use digest::XofReader;
use rand::RngCore;
use rand_core::impls;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::ops::{AddAssign, SubAssign};

/// A vector of `N` elements of `T` with element-wise addition and subtraction.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>"))]
pub struct VectorGroup<T, const N: usize> {
    #[serde_as(as = "[_; N]")]
    elements: [T; N],
}

impl<T: Default, const N: usize> Default for VectorGroup<T, N> {
    fn default() -> Self {
        Self {
            elements: std::array::from_fn(|_| T::default()),
        }
    }
}

impl<T: AddAssign, const N: usize> AddAssign for VectorGroup<T, N> {
    fn add_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements)
            .for_each(|(a, b)| *a += b);
    }
}

impl<T: SubAssign, const N: usize> SubAssign for VectorGroup<T, N> {
    fn sub_assign(&mut self, other: Self) {
        self.elements
            .iter_mut()
            .zip(other.elements)
            .for_each(|(a, b)| *a -= b);
    }
}

impl<T: RejectionSample, const N: usize> HashToGroupElement for VectorGroup<T, N> {
    /// Elements are sampled one at a time from SHAKE256.
    fn hash_to_group_element(msg: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};

        let mut xof = sha3::Shake256::default();
        xof.update(msg);
        let mut rng = XofRng(xof.finalize_xof());
        Self {
            elements: std::array::from_fn(|_| T::sample(&mut rng)),
        }
    }
}

/// Adapter that lets [RejectionSample] read bytes from an extendable-output function.
struct XofRng<R>(R);

impl<R: XofReader> RngCore for XofRng<R> {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
