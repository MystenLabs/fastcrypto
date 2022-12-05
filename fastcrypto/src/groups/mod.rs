// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::AllowedRng;
use core::ops::{Add, Div, Mul, Neg, Sub};
use std::ops::{AddAssign, SubAssign};

pub mod ristretto255;

/// Trait impl'd by elements of an additive cyclic group.
pub trait GroupElement:
    Copy
    + Clone
    + Eq
    + Add<Output = Self>
    + AddAssign
    + for<'a> Add<&'a Self, Output = Self>
    + Sub<Output = Self>
    + SubAssign
    + for<'a> Sub<&'a Self, Output = Self>
    + Neg<Output = Self>
    + Mul<Self::ScalarType, Output = Self>
    + for<'a> Mul<&'a Self::ScalarType, Output = Self>
    + Sized
{
    /// Type of scalars used in the [Self::mul] multiplication method.
    type ScalarType: Scalar;

    /// Return an instance of the identity element in this group.
    fn zero() -> Self;

    /// Return an instance of the generator for this group.
    fn generator() -> Self;
}

/// Trait impl'd by scalars to be used with [AdditiveGroupElement].
pub trait Scalar:
    GroupElement<ScalarType = Self> + Copy + From<u64> + Div<Self, Output = Self>
{
    fn rand<R: AllowedRng>(rng: &mut R) -> Self;
}
