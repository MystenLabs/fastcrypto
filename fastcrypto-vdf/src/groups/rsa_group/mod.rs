// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, Mul};
use std::rc::Rc;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;
use serde::{Deserialize, Serialize};

use fastcrypto::groups::Doubling;
use modulus::RSAModulus;

use crate::groups::ParameterizedGroupElement;

/// Serialization and deserialization for `num_bigint::BigUint`. The format used in num_bigint is
/// a serialization of the u32 words which is hard to port to other platforms. Instead, we serialize
/// a big integer in big-endian byte order. See also [BigUint::to_bytes_be].
mod biguint_serde;
pub mod modulus;
pub(crate) mod multiplier;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RSAGroupElement {
    #[serde(with = "biguint_serde")]
    value: BigUint,
    modulus: Rc<RSAModulus>,
}

impl Clone for RSAGroupElement {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            // Ensure that we don't do a deep clone of the modulus.
            modulus: Rc::clone(&self.modulus),
        }
    }
}

impl Add<Self> for RSAGroupElement {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(&rhs)
    }
}

impl Add<&Self> for RSAGroupElement {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        assert_eq!(self.modulus, rhs.modulus);
        Self {
            value: self.value.mul(&rhs.value).mod_floor(&self.modulus.value),
            modulus: self.modulus,
        }
    }
}

impl Doubling for RSAGroupElement {
    fn double(&self) -> Self {
        Self {
            value: self.value.modpow(&BigUint::from(2u8), &self.modulus.value),
            modulus: Rc::clone(&self.modulus),
        }
    }
}

impl ParameterizedGroupElement for RSAGroupElement {
    type ParameterType = Rc<RSAModulus>;

    fn zero(parameter: &Self::ParameterType) -> Self {
        Self {
            value: BigUint::one(),
            modulus: Rc::clone(parameter),
        }
    }

    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool {
        self.modulus.value == parameter.value
    }
}

impl RSAGroupElement {
    pub fn new(value: BigUint, modulus: &Rc<RSAModulus>) -> Self {
        Self {
            value,
            modulus: Rc::clone(modulus),
        }
    }

    pub fn modulus(&self) -> &BigUint {
        &self.modulus.value
    }

    pub fn value(&self) -> &BigUint {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use crate::groups::rsa_group::modulus::{RSAModulus, GOOGLE_RSA_MODULUS_4096};
    use crate::groups::rsa_group::RSAGroupElement;
    use crate::groups::ParameterizedGroupElement;
    use fastcrypto::groups::Doubling;
    use num_bigint::BigUint;
    use std::ops::Add;
    use std::rc::Rc;

    #[test]
    fn test_group_ops() {
        let modulus = Rc::new(GOOGLE_RSA_MODULUS_4096.clone());

        let zero = RSAGroupElement::zero(&modulus);
        let element = RSAGroupElement::new(BigUint::from(7u32), &modulus);
        let sum = element.clone().add(&zero);
        assert_eq!(&sum, &element);

        let double = element.double();
        let expected_double = element.clone().add(&element);
        assert_eq!(&double, &expected_double);
    }

    #[test]
    fn test_clone() {
        let modulus = Rc::new(GOOGLE_RSA_MODULUS_4096.clone());
        assert_eq!(Rc::strong_count(&modulus), 1);
        let element = RSAGroupElement::new(BigUint::from(7u32), &modulus);
        assert_eq!(Rc::strong_count(&modulus), 2);
        {
            let _cloned_element = element.clone();
            assert_eq!(Rc::strong_count(&modulus), 3);
        }
        assert_eq!(Rc::strong_count(&modulus), 2);
    }

    #[test]
    fn test_is_in_group() {
        let modulus = Rc::new(GOOGLE_RSA_MODULUS_4096.clone());
        let element = RSAGroupElement::new(BigUint::from(7u32), &modulus);
        assert!(element.is_in_group(&modulus));

        let other_modulus = Rc::new(RSAModulus {
            value: BigUint::from(15u32),
        });
        assert!(!element.is_in_group(&other_modulus));
    }
}
