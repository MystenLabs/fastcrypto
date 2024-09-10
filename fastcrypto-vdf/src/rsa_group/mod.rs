// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use num_bigint::BigUint;
use num_traits::One;
use serde::Serialize;
use std::ops::{Add, Mul};

use crate::math::parameterized_group::ParameterizedGroupElement;
use fastcrypto::groups::Doubling;
use modulus::RSAModulus;

pub mod modulus;

/// This represents an element of the subgroup of an RSA group <i>Z<sub>N</sub><sup>*</sup> / <±1></i>
/// where <i>N</i> is the product of two large primes. The set of supported moduli is a fixed list
/// of public RSA moduli from renowned CAs. See also [RSAModulus].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RSAGroupElement<'a> {
    value: BigUint,

    // We assume that the modulus is known from the context, so it is not serialized.
    #[serde(skip)]
    modulus: &'a RSAModulus,
}

impl<'a> RSAGroupElement<'a> {
    /// Create a new RSA group element with the given value and modulus. The value will be reduced to
    /// the subgroup <i>Z<sub>N</sub><sup>*</sup> / <±1></i>, so it does not need to be in canonical
    /// representation.
    pub fn new(value: BigUint, modulus: &'a RSAModulus) -> Self {
        Self {
            value: modulus.reduce(value),
            modulus,
        }
    }

    /// Return the canonical representation of this group element.
    pub fn value(&self) -> &BigUint {
        &self.value
    }
}

impl Add<&Self> for RSAGroupElement<'_> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        assert_eq!(self.modulus, rhs.modulus);
        Self::new(self.value.mul(&rhs.value), self.modulus)
    }
}

impl Doubling for RSAGroupElement<'_> {
    fn double(self) -> Self {
        Self::new(self.value.pow(2), self.modulus)
    }
}

impl<'a> ParameterizedGroupElement for RSAGroupElement<'a> {
    type ParameterType = &'a RSAModulus;

    fn zero(parameter: &Self::ParameterType) -> Self {
        Self::new(BigUint::one(), parameter)
    }

    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool {
        self.modulus == *parameter
    }
}

#[cfg(test)]
mod tests {
    use crate::math::parameterized_group::ParameterizedGroupElement;
    use crate::rsa_group::modulus::test::{AMAZON_2048, GOOGLE_4096};
    use crate::rsa_group::RSAGroupElement;
    use fastcrypto::groups::Doubling;
    use num_bigint::BigUint;
    use num_traits::One;
    use std::ops::Add;

    #[test]
    fn test_group_ops() {
        let zero = RSAGroupElement::zero(&GOOGLE_4096);
        let element = RSAGroupElement::new(BigUint::from(7u32), &GOOGLE_4096);
        let sum = element.clone().add(&zero);
        assert_eq!(&sum, &element);

        let expected_double = element.clone().add(&element);
        let double = element.double();
        assert_eq!(&double, &expected_double);

        let minus_one = RSAGroupElement::new(&GOOGLE_4096.value - BigUint::one(), &GOOGLE_4096);
        let one = RSAGroupElement::new(BigUint::one(), &GOOGLE_4096);
        assert_eq!(minus_one, one);
    }

    #[test]
    fn test_is_in_group() {
        let element = RSAGroupElement::new(BigUint::from(7u32), &GOOGLE_4096);
        assert!(element.is_in_group(&GOOGLE_4096));
        assert!(!element.is_in_group(&AMAZON_2048));
    }
}
