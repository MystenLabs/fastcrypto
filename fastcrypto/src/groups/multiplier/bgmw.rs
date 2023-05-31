// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::multiplier::integer_utils::{compute_base_2w_expansion, div_ceil};
use crate::groups::multiplier::ScalarMultiplier;
use crate::groups::GroupElement;
use crate::serde_helpers::ToFromByteArray;

/// Performs scalar multiplication using a windowed method with a larger pre-computation table than
/// the one used in the `windowed` multiplier. We must have HEIGHT >= ceil(SCALAR_SIZE * 8 / ceil(log2(WIDTH))
/// where WIDTH is the window width, and the pre-computation tables will be of size WIDTH x HEIGHT.
/// Once pre-computation has been done, a scalar multiplication requires HEIGHT additions. Both `mul`
/// and `double_mul` are constant time assuming the group operations for `G` are constant time.
///
/// The algorithm used is the BGMW algorithm with base `2^WIDTH` and the basic digit set set to `0, ..., 2^WIDTH-1`.
///
/// This method is faster than the WindowedScalarMultiplier for a single multiplication, but it requires
/// a larger number of precomputed points.
pub struct BGMWScalarMultiplier<
    G: GroupElement<ScalarType = S>,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const WIDTH: usize,
    const HEIGHT: usize,
    const SCALAR_SIZE: usize,
> {
    /// Precomputed multiples of the base element, B, up to WIDTH x HEIGHT - 1.
    cache: [[G; WIDTH]; HEIGHT],
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const WIDTH: usize,
        const HEIGHT: usize,
        const SCALAR_SIZE: usize,
    > BGMWScalarMultiplier<G, S, WIDTH, HEIGHT, SCALAR_SIZE>
{
    /// The number of bits in the window. This is equal to the floor of the log2 of the `WIDTH`.
    const WINDOW_WIDTH: usize = (usize::BITS - WIDTH.leading_zeros() - 1) as usize;

    /// Get 2^{column * WINDOW_WIDTH} * row * base_point.
    fn get_precomputed_multiple(&self, row: usize, column: usize) -> G {
        self.cache[row][column]
    }
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const WIDTH: usize,
        const HEIGHT: usize,
        const SCALAR_SIZE: usize,
    > ScalarMultiplier<G> for BGMWScalarMultiplier<G, S, WIDTH, HEIGHT, SCALAR_SIZE>
{
    fn new(base_element: G) -> Self {
        // Verify parameters
        let lower_limit = div_ceil(SCALAR_SIZE * 8, Self::WINDOW_WIDTH);
        if HEIGHT < lower_limit {
            panic!("Invalid parameters. HEIGHT needs to be at least {} with the given WIDTH and SCALAR_SIZE.", lower_limit);
        }

        // Store cache[i][j] = 2^{i w} * j * base_element
        let mut cache = [[G::zero(); WIDTH]; HEIGHT];

        // Compute cache[0][j] = j * base_element.
        for j in 1..WIDTH {
            cache[0][j] = cache[0][j - 1] + base_element;
        }

        // Compute cache[i][j] = 2^w * cache[i-1][j] for i > 0.
        for i in 1..HEIGHT {
            for j in 0..WIDTH {
                cache[i][j] = cache[i - 1][j];
                for _ in 0..Self::WINDOW_WIDTH {
                    cache[i][j] = cache[i][j].double();
                }
            }
        }
        Self { cache }
    }

    fn mul(&self, scalar: &S) -> G {
        // Scalar as bytes in little-endian representation.
        let scalar_bytes = scalar.to_byte_array();

        let base_2w_expansion =
            compute_base_2w_expansion::<SCALAR_SIZE>(&scalar_bytes, Self::WINDOW_WIDTH);

        let mut result = self.get_precomputed_multiple(0, base_2w_expansion[0]);
        for (i, digit) in base_2w_expansion.iter().enumerate().skip(1) {
            result += self.get_precomputed_multiple(i, *digit);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use crate::groups::secp256r1::{ProjectivePoint, Scalar};
    use ark_ff::{BigInteger, PrimeField};
    use ark_secp256r1::Fr;

    #[test]
    fn test_scalar_multiplication_ristretto() {
        let multiplier = BGMWScalarMultiplier::<RistrettoPoint, RistrettoScalar, 16, 64, 32>::new(
            RistrettoPoint::generator(),
        );

        let scalars = [
            RistrettoScalar::from(0),
            RistrettoScalar::from(1),
            RistrettoScalar::from(2),
            RistrettoScalar::from(1234),
            RistrettoScalar::from(123456),
            RistrettoScalar::from(123456789),
            RistrettoScalar::from(0xffffffffffffffff),
            RistrettoScalar::group_order(),
            RistrettoScalar::group_order() - RistrettoScalar::from(1),
            RistrettoScalar::group_order() + RistrettoScalar::from(1),
        ];

        for scalar in scalars {
            let expected = RistrettoPoint::generator() * scalar;
            let actual = multiplier.mul(&scalar);
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_scalar_multiplication_secp256r1() {
        let mut modulus_minus_one = Fr::MODULUS_MINUS_ONE_DIV_TWO;
        modulus_minus_one.mul2();
        let scalars = [
            Scalar::from(0),
            Scalar::from(1),
            Scalar::from(2),
            Scalar::from(1234),
            Scalar::from(123456),
            Scalar::from(123456789),
            Scalar::from(0xffffffffffffffff),
            Scalar(Fr::from(modulus_minus_one)),
        ];

        for scalar in scalars {
            let expected = ProjectivePoint::generator() * scalar;

            let multiplier = BGMWScalarMultiplier::<ProjectivePoint, Scalar, 16, 64, 32>::new(
                ProjectivePoint::generator(),
            );
            let actual = multiplier.mul(&scalar);
            assert_eq!(expected, actual);

            let multiplier = BGMWScalarMultiplier::<ProjectivePoint, Scalar, 32, 52, 32>::new(
                ProjectivePoint::generator(),
            );
            let actual = multiplier.mul(&scalar);
            assert_eq!(expected, actual);

            let multiplier = BGMWScalarMultiplier::<ProjectivePoint, Scalar, 64, 43, 32>::new(
                ProjectivePoint::generator(),
            );
            let actual = multiplier.mul(&scalar);
            assert_eq!(expected, actual);
        }

        // Assert a panic due to setting the HEIGHT too small
        assert!(std::panic::catch_unwind(|| {
            BGMWScalarMultiplier::<ProjectivePoint, Scalar, 16, 63, 32>::new(
                ProjectivePoint::generator(),
            )
        })
        .is_err());
    }
}
