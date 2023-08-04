// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.
//!
//! Serialization is compatible with the chiavdf library (https://github.com/Chia-Network/chiavdf).

use class_group::BinaryQF;
use curv::arithmetic::One;
use curv::BigInt;
use std::ops::{Add, Mul};

mod compressed;

/// The size of a compressed quadratic form in bytes. We force all forms to have the same size (100 bytes)
pub const MAX_D_BITS: usize = 1024;
pub const FORM_SIZE: usize = (MAX_D_BITS + 31) / 32 * 3 + 4; // = 100 bytes

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QuadraticForm(BinaryQF);

impl Mul<&BigInt> for QuadraticForm {
    type Output = Self;

    // TODO: The current BigInt implementations is curv's wrapper of num-biginteger, but it should be wrapped or replaced with a more widely used BigInt implementation.
    fn mul(self, rhs: &BigInt) -> Self::Output {
        Self(self.0.exp(rhs))
    }
}

impl Mul<&BigInt> for &QuadraticForm {
    type Output = QuadraticForm;

    fn mul(self, rhs: &BigInt) -> Self::Output {
        QuadraticForm(self.0.exp(rhs))
    }
}

impl Add<&QuadraticForm> for &QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: &QuadraticForm) -> Self::Output {
        QuadraticForm(self.0.compose(&rhs.0).reduce())
    }
}

impl QuadraticForm {
    /// Compute self + self.
    pub fn double(&self) -> Self {
        self * &BigInt::from(2)
    }

    /// Create a new quadratic form with the given coordinates.
    pub fn from_a_b_c(a: BigInt, b: BigInt, c: BigInt) -> Self {
        Self(BinaryQF { a, b, c })
    }

    /// Create a new quadratic form given only the a and b coordinate and the discriminant.
    pub fn from_a_b_discriminant(a: BigInt, b: BigInt, discriminant: &BigInt) -> Self {
        let c = ((&b * &b) - discriminant) / (BigInt::from(4) * &a);
        Self(BinaryQF { a, b, c })
    }

    /// Return the identity element in a class group with a given discriminant, eg. (1, 1, X) where
    /// X is determined from the discriminant.
    pub fn identity(discriminant: &BigInt) -> Self {
        Self::from_a_b_discriminant(BigInt::one(), BigInt::one(), discriminant)
    }

    /// Return a generator (or, more precisely, an element with a presumed large order) in a class group
    /// with a given discriminant. We use the element `(2, 1, x)` where `x` is determined from the discriminant.
    pub fn generator(discriminant: &BigInt) -> Self {
        Self::from_a_b_discriminant(BigInt::from(2), BigInt::one(), discriminant)
    }

    /// Compute the discriminant `b^2 - 4ac` for this quadratic form.
    pub fn discriminant(&self) -> BigInt {
        self.0.discriminant()
    }
}
