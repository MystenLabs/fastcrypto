// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of imaginary class groups. Elements are represented by
//! binary quadratic forms which forms a group under composition. Here we use additive notation
//! for the composition.
//!
//! Serialization is compatible with the chiavdf library (https://github.com/Chia-Network/chiavdf).

use crate::error::FastCryptoResult;
use crate::groups::{ParameterizedGroupElement, UnknownOrderGroupElement};
use class_group::BinaryQF;
use curv::arithmetic::One;
use curv::BigInt;
use std::ops::Add;

mod compressed;

/// The size of a compressed quadratic form in bytes. We force all forms to have the same size (100 bytes)
pub const MAX_D_BITS: usize = 1024;
pub const FORM_SIZE: usize = (MAX_D_BITS + 31) / 32 * 3 + 4; // = 100 bytes

/// A binary quadratic form, (a, b, c) for arbitrary integers a, b, and c.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct QuadraticForm(BinaryQF);

impl Add<QuadraticForm> for QuadraticForm {
    type Output = QuadraticForm;

    fn add(self, rhs: QuadraticForm) -> Self::Output {
        QuadraticForm(self.0.compose(&rhs.0).reduce())
    }
}

impl QuadraticForm {
    /// Create a new quadratic form with the given coordinates.
    pub fn from_a_b_c(a: BigInt, b: BigInt, c: BigInt) -> Self {
        Self(BinaryQF { a, b, c })
    }

    /// Create a new quadratic form given only the a and b coordinate and the discriminant.
    pub fn from_a_b_discriminant(a: BigInt, b: BigInt, discriminant: &BigInt) -> Self {
        let c = ((&b * &b) - discriminant) / (BigInt::from(4) * &a);
        Self(BinaryQF { a, b, c })
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

impl ParameterizedGroupElement for QuadraticForm {
    /// Type of the discriminant.
    type ParameterType = BigInt;

    type ScalarType = BigInt;

    fn zero(discriminant: &Self::ParameterType) -> Self {
        Self::from_a_b_discriminant(BigInt::one(), BigInt::one(), discriminant)
    }

    fn mul(&self, scale: &BigInt) -> Self {
        Self(self.0.exp(scale))
    }

    fn to_byte_array(&self) -> FastCryptoResult<Vec<u8>> {
        self.serialize().map(|array| array.to_vec())
    }

    fn get_parameter(&self) -> Self::ParameterType {
        self.discriminant()
    }
}

impl UnknownOrderGroupElement for QuadraticForm {}
