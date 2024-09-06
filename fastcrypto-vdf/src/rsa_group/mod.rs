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

/// This represents an element of the subgroup of an RSA group <i>Z<sub>N</sub><sup>*</sup> / <±1></i>
/// where <i>N</i> is the product of two large primes. The set of supported moduli is a fixed list
/// of public RSA moduli from renowned CAs. See also [RSAModulus].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RSAGroupElement {
    #[serde(with = "biguint_serde")]
    value: BigUint,
    modulus: RSAModulus,
}

impl RSAGroupElement {
    /// Create a new RSA group element with the given value and modulus. The value will be reduced to
    /// the subgroup <i>Z<sub>N</sub><sup>*</sup> / <±1></i>, so it does not need to be in canonical
    /// representation.
    pub fn new(value: BigUint, modulus: RSAModulus) -> Self {
        Self {
            value: value.mod_floor(modulus.value()),
            modulus,
        }
        .reduce()
    }

    /// Return the modulus of this group element.
    pub fn modulus(&self) -> &RSAModulus {
        &self.modulus
    }

    /// Return the canonical representation of this group element.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Ensure that the value is in the subgroup <i>Z<sub>N</sub><sup>*</sup> / <±1></i>.
    fn reduce(self) -> Self {
        if &self.value < self.modulus.half_value() {
            self
        } else {
            Self {
                value: self.modulus.value() - self.value,
                modulus: self.modulus,
            }
        }
    }
}

impl Add<&Self> for RSAGroupElement {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        assert_eq!(self.modulus, rhs.modulus);
        Self::new(
            self.value.mul(&rhs.value).mod_floor(self.modulus.value()),
            self.modulus,
        )
    }
}

impl Doubling for RSAGroupElement {
    fn double(self) -> Self {
        Self::new(
            self.value.modpow(&BigUint::from(2u8), self.modulus.value()),
            self.modulus,
        )
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
    use num_traits::One;
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

        let minus_one = RSAGroupElement::new(GoogleRSA4096.value() - BigUint::one(), GoogleRSA4096);
        let one = RSAGroupElement::new(BigUint::one(), GoogleRSA4096);
        assert_eq!(minus_one, one);
    }

    #[test]
    fn test_is_in_group() {
        let element = RSAGroupElement::new(BigUint::from(7u32), GoogleRSA4096);
        assert!(element.is_in_group(&GoogleRSA4096));
        assert!(!element.is_in_group(&AmazonRSA2048));
    }
}
