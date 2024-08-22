// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError::InvalidInput;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Doubling;
use num_bigint::BigUint;
use num_traits::Zero;
use std::ops::{Add, Neg};

/// This trait is implemented by types which can be used as parameters for a parameterized group.
/// See [ParameterizedGroupElement].
pub trait Parameter: Eq + Sized {
    /// Compute a random instance of a given size from a seed.
    fn from_seed(seed: &[u8], size_in_bits: usize) -> FastCryptoResult<Self>;
}

/// Trait implemented by elements of an additive group where the group is parameterized, for example
/// by the modulus in case of the group being Z mod N or the discriminant in case of class groups.
pub trait ParameterizedGroupElement:
    Sized + Clone + for<'a> Add<&'a Self, Output = Self> + Add<Output = Self> + Neg + Eq + Doubling
{
    /// The type of the parameter which uniquely defines this group.
    type ParameterType: Parameter;

    /// Return an instance of the identity element in this group.
    fn zero(parameter: &Self::ParameterType) -> Self;

    /// Returns true if this is an element of the group defined by `parameter`.
    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool;

    /// Compute self * scalar using a "Double-and-Add" algorithm for a positive scalar. Returns an
    /// `InvalidInput` error if the scalar is zero.
    fn multiply(
        &self,
        scalar: &BigUint,
        parameter: &Self::ParameterType,
    ) -> FastCryptoResult<Self> {
        if !self.is_in_group(parameter) {
            return Err(InvalidInput);
        }
        if scalar.is_zero() {
            return Ok(Self::zero(parameter));
        }
        let result = (0..scalar.bits())
            .rev()
            .map(|i| scalar.bit(i))
            .skip(1) // The most significant bit is always 1.
            .fold(self.clone(), |acc, bit| {
                let mut res = acc.double();
                if bit {
                    res = res + self;
                }
                res
            });
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::{Parameter, ParameterizedGroupElement};
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    #[test]
    fn test_scalar_multiplication() {
        let discriminant = Discriminant::from_seed(b"test", 256).unwrap();
        let input = QuadraticForm::generator(&discriminant);

        // Edge cases
        assert_eq!(
            QuadraticForm::zero(&discriminant),
            input.multiply(&BigUint::zero(), &discriminant).unwrap()
        );
        assert_eq!(
            input,
            input.multiply(&BigUint::one(), &discriminant).unwrap()
        );

        let exponent = 12345u64;
        let output = input
            .multiply(&BigUint::from(exponent), &discriminant)
            .unwrap();

        // Check alignment with repeated addition.
        let mut expected_output = input.clone();
        for _ in 1..exponent {
            expected_output = expected_output + &input;
        }
        assert_eq!(output, expected_output);
    }
}
