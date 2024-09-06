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
}

/// Compute self * scalar using a "Double-and-Add" algorithm for a positive scalar.
pub(crate) fn multiply<G: ParameterizedGroupElement>(
    input: &G,
    scalar: &BigUint,
    parameter: &G::ParameterType,
) -> G {
    (0..scalar.bits())
        .rev()
        .map(|i| scalar.bit(i))
        .fold(G::zero(parameter), |acc, bit| {
            let mut res = acc.double();
            if bit {
                res = res + input;
            }
            res
        })
}

#[cfg(test)]
mod tests {
    use crate::class_group::discriminant::Discriminant;
    use crate::class_group::QuadraticForm;
    use crate::math::parameterized_group::{multiply, ParameterizedGroupElement};
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    #[test]
    fn test_scalar_multiplication() {
        let discriminant = Discriminant::from_seed(b"test", 256).unwrap();
        let input = QuadraticForm::generator(&discriminant);

        // Edge cases
        assert_eq!(
            QuadraticForm::zero(&discriminant),
            multiply(&input, &BigUint::zero(), &discriminant)
        );
        assert_eq!(input, multiply(&input, &BigUint::one(), &discriminant));

        let exponent = 12345u64;
        let output = multiply(&input, &BigUint::from(exponent), &discriminant);

        // Check alignment with repeated addition.
        let mut expected_output = input.clone();
        for _ in 1..exponent {
            expected_output = expected_output + &input;
        }
        assert_eq!(output, expected_output);
    }
}
