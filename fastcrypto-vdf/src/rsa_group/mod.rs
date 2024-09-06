// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, Mul};

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use serde::{Deserialize, Serialize};

use crate::math::parameterized_group::ParameterizedGroupElement;
use fastcrypto::groups::Doubling;
use modulus::RSAModulus;

/// Serialization and deserialization for `num_bigint::BigUint`. The format used in num_bigint is
/// a serialization of the u32 words which is hard to port to other platforms. Instead, we serialize
/// a big integer in big-endian byte order. See also [BigUint::to_bytes_be].
mod biguint_serde;
pub mod modulus;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RSAGroupElement {
    #[serde(with = "biguint_serde")]
    value: BigUint,
    modulus: RSAModulus,
}

impl RSAGroupElement {
    /// Create a new RSA group element with the given value and modulus.
    pub fn new(value: BigUint, modulus: RSAModulus) -> Self {
        Self { value, modulus }
    }

    /// Return the modulus of this group element.
    pub fn modulus(&self) -> &RSAModulus {
        &self.modulus
    }

    /// Return the canonical representation of this group element.
    pub fn value(&self) -> &BigUint {
        &self.value
    }
}

impl Add<&Self> for RSAGroupElement {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        assert_eq!(self.modulus, rhs.modulus);
        Self {
            value: self.value.mul(&rhs.value).mod_floor(self.modulus.value()),
            modulus: self.modulus,
        }
    }
}

impl Doubling for RSAGroupElement {
    fn double(self) -> Self {
        Self {
            value: self
                .value
                .modpow(&BigUint::from(2u8), self.modulus.value()),
            modulus: self.modulus,
        }
    }
}

impl ParameterizedGroupElement for RSAGroupElement {
    type ParameterType = RSAModulus;

    fn zero(parameter: &Self::ParameterType) -> Self {
        Self::new(BigUint::one(), parameter.clone())
    }

    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool {
        self.modulus == *parameter
    }
}

#[cfg(test)]
mod tests {
    use crate::math::parameterized_group::ParameterizedGroupElement;
    use crate::rsa_group::modulus::RSAModulus::{AmazonRSA2048, GoogleRSA4096};
    use crate::rsa_group::RSAGroupElement;
    use fastcrypto::groups::Doubling;
    use num_bigint::BigUint;
    use std::ops::Add;

    #[test]
    fn test_group_ops() {
        let zero = RSAGroupElement::zero(&GoogleRSA4096);
        let element = RSAGroupElement::new(BigUint::from(7u32), GoogleRSA4096);
        let sum = element.clone().add(&zero);
        assert_eq!(&sum, &element);

        let expected_double = element.clone().add(&element);
        let double = element.double();
        assert_eq!(&double, &expected_double);
    }

    #[test]
    fn test_is_in_group() {
        let element = RSAGroupElement::new(BigUint::from(7u32), GoogleRSA4096);
        assert!(element.is_in_group(&GoogleRSA4096));
        assert!(!element.is_in_group(&AmazonRSA2048));
    }
}
