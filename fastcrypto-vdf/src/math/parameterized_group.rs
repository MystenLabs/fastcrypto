// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::groups::Doubling;
use num_bigint::BigUint;
use serde::Serialize;
use std::ops::Add;

/// Trait implemented by elements of an additive group where the group is parameterized, for example
/// by the modulus in case of the group being Z mod N or the discriminant in case of class groups.
pub trait ParameterizedGroupElement:
    Sized + Clone + for<'a> Add<&'a Self, Output = Self> + Eq + Doubling + Serialize
{
    /// The type of the parameter which uniquely defines this group.
    type ParameterType: Serialize;

    /// Return an instance of the identity element in this group.
    fn zero(parameter: &Self::ParameterType) -> Self;

    /// Returns true if this is an element of the group defined by `parameter`.
    fn is_in_group(&self, parameter: &Self::ParameterType) -> bool;

    /// Compute self * scalar.
    fn multiply(&self, scalar: &BigUint, parameter: &Self::ParameterType) -> Self {
        // Generic double-and-add algorithm.
        (0..scalar.bits())
            .rev()
            .map(|i| scalar.bit(i))
            .fold(Self::zero(parameter), |acc, bit| match bit {
                true => acc.double() + self,
                false => acc.double(),
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::ParameterizedGroupElement;
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    #[test]
    fn test_scalar_multiplication() {
        let discriminant = Discriminant::from_seed(b"test", 256).unwrap();
        let input = QuadraticForm::generator(&discriminant);

        // Edge cases
        assert_eq!(
            QuadraticForm::zero(&discriminant),
            input.multiply(&BigUint::zero(), &discriminant)
        );
        assert_eq!(input, input.multiply(&BigUint::one(), &discriminant));

        let exponent = 12345u64;
        let output = input.multiply(&BigUint::from(exponent), &discriminant);

        // Check alignment with repeated addition.
        let mut expected_output = input.clone();
        for _ in 1..exponent {
            expected_output = expected_output + &input;
        }
        assert_eq!(output, expected_output);
    }
}
