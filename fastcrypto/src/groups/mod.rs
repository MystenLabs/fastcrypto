// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::ops::{Add, Mul, Neg, Sub};
use std::ops::{AddAssign, SubAssign};

pub mod ristretto255;

/// Trait impl'd by elements of an additive cyclic group.
pub trait AdditiveGroupElement:
    Eq + Add + Sub + Neg + AddAssign + SubAssign + Mul<Self::Scalar> + Sized
{
    /// Type of scalars used in the [Self::mul] multiplication method.
    type Scalar: ScalarType;

    /// Return an instance of the identity element in this group.
    fn zero() -> Self;

    /// Return an instance of the generator for this group.
    fn generator() -> Self;
}

/// Trait impl'd by scalars to be used with [AdditiveGroupElement].
pub trait ScalarType: AdditiveGroupElement<Scalar = Self> + Copy {}
