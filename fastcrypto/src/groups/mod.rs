// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::ops::{Add, Mul, Neg, Sub};

pub mod ristretto255;

/// Trait impl'd by elements of an additive group.
pub trait AdditiveGroupElement: Eq + Copy + Add + Sub + Neg + Mul<Self::Scalar> + Sized {
    /// Type of scalars used in the [Self::mul] multiplication method.
    type Scalar: Copy;

    /// Return an instance of the identity element in this group.
    fn identity() -> Self;
}
