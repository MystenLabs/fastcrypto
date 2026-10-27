// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Vectors of group elements with element-wise addition.

use crate::groups::{HashToGroupElement, RejectionSample};
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
        let mut reader = xof.finalize_xof();
        Self {
            elements: std::array::from_fn(|_| T::sample(&mut reader)),
        }
    }
}
