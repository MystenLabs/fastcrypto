// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ops::{Add, Mul};
use std::rc::Rc;

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RSAGroupElement {
    #[serde(with = "biguint_serde")]
    pub value: BigUint,
    pub modulus: Rc<RSAModulus>,
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
    type ParameterType = RSAModulus;

    fn zero(parameter: &Self::ParameterType) -> Self {
        Self {
            value: BigUint::zero(),
            modulus: Rc::new(parameter.clone()),
        }
    }

    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool {
        self.modulus.value == parameter.value
    }
}

#[cfg(test)]
mod tests {}
