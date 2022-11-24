// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::fmt::Debug;
use std::iter::Sum;

pub mod ristretto;

/// This section is a PoC EC group trait, loosely inspired by zkcrypto::groups::Group.

/// A helper trait for types with a group operation.
pub trait GroupOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + AddAssign<Rhs> + SubAssign<Rhs>
{
}

impl<T, Rhs, Output> GroupOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + AddAssign<Rhs> + SubAssign<Rhs>
{
}

/// A helper trait for references with a group operation.
pub trait GroupOpsOwned<Rhs = Self, Output = Self>: for<'r> GroupOps<&'r Rhs, Output> {}
impl<T, Rhs, Output> GroupOpsOwned<Rhs, Output> for T where T: for<'r> GroupOps<&'r Rhs, Output> {}

/// A helper trait for types implementing group scalar multiplication.
pub trait ScalarMul<Rhs, Output = Self>: Mul<Rhs, Output = Output> + MulAssign<Rhs> {}

impl<T, Rhs, Output> ScalarMul<Rhs, Output> for T where T: Mul<Rhs, Output = Output> + MulAssign<Rhs>
{}

/// A helper trait for references implementing group scalar multiplication.
pub trait ScalarMulOwned<Rhs, Output = Self>: for<'r> ScalarMul<&'r Rhs, Output> {}
impl<T, Rhs, Output> ScalarMulOwned<Rhs, Output> for T where T: for<'r> ScalarMul<&'r Rhs, Output> {}

pub trait Group:
    Clone
    + Copy
    + Debug
    + Eq
    + Sized
    + Send
    + Sync
    + 'static
    + Sum
    + for<'a> Sum<&'a Self>
    + Neg<Output = Self>
    + GroupOps
    + GroupOpsOwned
    + ScalarMul<<Self as Group>::Scalar>
    + ScalarMulOwned<<Self as Group>::Scalar>
{
    /// Scalars modulo the order of this group's scalar field.
    type Scalar;

    /// Returns the additive identity, also known as the "neutral element".
    fn identity() -> Self;

    /// Determines if this point is the identity.
    fn is_identity(&self) -> bool;
}
