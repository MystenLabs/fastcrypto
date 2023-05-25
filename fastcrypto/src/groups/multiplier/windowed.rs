// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::multiplier::integer_utils::{get_bits_from_bytes, test_bit};
use crate::groups::multiplier::{integer_utils, ScalarMultiplier};
use crate::groups::GroupElement;
use crate::serde_helpers::ToFromByteArray;
use std::iter::successors;

/// This multiplier uses pre-computation with the windowed method. This multiplier is particularly
/// fast for double multiplications, where a sliding window method is used, but this implies that the
/// `double_mul`, is NOT constant time. However, the single multiplication method, `mul`, is constant time.
///
/// The `CACHE_SIZE` should be a power of two. The `SCALAR_SIZE` is the number of bytes in the byte
/// representation of the scalar type `S`, and we assume that the `S::to_byte_array` method returns the
/// scalar in little-endian format.
///
/// The SLIDING_WINDOW_WIDTH is the number of bits in the sliding window. This should be approximately
/// log2(sqrt(SCALAR_SIZE_IN_BITS)) + 1 for optimal performance.
pub struct WindowedScalarMultiplier<
    G: GroupElement<ScalarType = S>,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const CACHE_SIZE: usize,
    const SCALAR_SIZE: usize,
    const SLIDING_WINDOW_WIDTH: usize,
> {
    /// Precomputed multiples of the base element from 0 up to CACHE_SIZE - 1 = 2^WINDOW_WIDTH - 1.
    cache: [G; CACHE_SIZE],
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
        const SLIDING_WINDOW_WIDTH: usize,
    > WindowedScalarMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE, SLIDING_WINDOW_WIDTH>
{
    /// The number of bits in the window. This is equal to the floor of the log2 of the cache size.
    const WINDOW_WIDTH: usize = (usize::BITS - CACHE_SIZE.leading_zeros() - 1) as usize;
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
        const SLIDING_WINDOW_WIDTH: usize,
    > ScalarMultiplier<G>
    for WindowedScalarMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE, SLIDING_WINDOW_WIDTH>
{
    fn new(base_element: G) -> Self {
        let mut cache = [G::zero(); CACHE_SIZE];
        cache[1] = base_element;
        for i in 2..CACHE_SIZE {
            cache[i] = cache[i - 1] + base_element;
        }
        Self { cache }
    }

    fn mul(&self, scalar: &S) -> G {
        // Scalar as bytes in little-endian representation.
        let scalar_bytes = scalar.to_byte_array();

        let base_2w_expansion = integer_utils::compute_base_2w_expansion::<SCALAR_SIZE>(
            &scalar_bytes,
            Self::WINDOW_WIDTH,
        );

        // Computer multiplication using the fixed window method to ensure that it's constant time.
        let mut result: G = self.cache[base_2w_expansion[base_2w_expansion.len() - 1]];
        for digit in base_2w_expansion.iter().rev().skip(1) {
            for _ in 1..=Self::WINDOW_WIDTH {
                result = result.double();
            }
            result += self.cache[*digit];
        }
        result
    }

    fn mul_double(
        &self,
        base_scalar: &G::ScalarType,
        other_element: &G,
        other_scalar: &G::ScalarType,
    ) -> G {
        // Compute the sum of the two multiples using Straus' algorithm combined with a sliding window algorithm.

        // Scalar as bytes in little-endian representation.
        let base_scalar_bytes = base_scalar.to_byte_array();
        let other_scalar_bytes = other_scalar.to_byte_array();

        // Compute multiples of the other element. We only need precomputed values for the upper half since a window always begins with a one bit.
        let mut smallest_other_element_multiple = other_element.double();
        for _ in 2..SLIDING_WINDOW_WIDTH {
            smallest_other_element_multiple = smallest_other_element_multiple.double();
        }
        let other_element_cache = successors(Some(smallest_other_element_multiple), |element| {
            Some(*element + other_element)
        })
        .take(1 << (SLIDING_WINDOW_WIDTH - 1))
        .collect::<Vec<_>>();

        let mut base_scalar_window_index = 0;
        let mut base_scalar_is_in_window = false;
        let mut base_scalar_latest_one_bit = 0;

        let mut other_scalar_window_index = 0;
        let mut other_scalar_is_in_window = false;
        let mut other_scalar_latest_one_bit = 0;

        let mut result = G::zero();

        let mut current_bit = SCALAR_SIZE * 8;

        // We may skip the first doubling and also until we get to the first one bit in either of the scalars.
        let mut skip_doubling = true;

        while current_bit > 0 {
            if !skip_doubling {
                result = result.double();
            }

            // TODO: Put in loop
            current_bit -= 1;
            if base_scalar_is_in_window {
                base_scalar_window_index += 1;
                if base_scalar_window_index == Self::WINDOW_WIDTH {
                    result += self.cache[base_scalar_latest_one_bit];
                    skip_doubling = false;
                    base_scalar_is_in_window = false;
                }
            } else if test_bit(&base_scalar_bytes, current_bit) {
                if current_bit >= Self::WINDOW_WIDTH - 1 {
                    base_scalar_window_index = 1;
                    base_scalar_is_in_window = true;
                    base_scalar_latest_one_bit = get_bits_from_bytes(
                        &base_scalar_bytes,
                        current_bit + 1 - Self::WINDOW_WIDTH,
                        current_bit + 1,
                    );
                } else {
                    result += self.cache[1];
                    skip_doubling = false;
                }
            }

            if other_scalar_is_in_window {
                other_scalar_window_index += 1;
                if other_scalar_window_index == SLIDING_WINDOW_WIDTH {
                    other_scalar_is_in_window = false;
                    skip_doubling = false;
                    result += other_element_cache[other_scalar_latest_one_bit];
                }
            } else if test_bit(&other_scalar_bytes, current_bit) {
                if current_bit >= SLIDING_WINDOW_WIDTH - 1 {
                    other_scalar_window_index = 1;
                    other_scalar_is_in_window = true;
                    other_scalar_latest_one_bit = get_bits_from_bytes(
                        &other_scalar_bytes,
                        current_bit + 1 - SLIDING_WINDOW_WIDTH,
                        current_bit, // We only store the upper half of the multiples since a window always begins with a one bit, so we ignore the last bit.
                    );
                } else {
                    result += *other_element;
                    skip_doubling = false;
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use crate::groups::secp256r1::{ProjectivePoint, Scalar};
    use crate::groups::Scalar as ScalarTrait;
    use rand::thread_rng;

    #[test]
    fn test_scalar_multiplication_ristretto() {
        let multiplier =
            WindowedScalarMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32, 4>::new(
                RistrettoPoint::generator(),
            );
        let scalar = RistrettoScalar::from(123456789);
        let expected = RistrettoPoint::generator() * scalar;
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_scalar_multiplication_secp256r1() {
        let scalar = Scalar::from(123456789);
        let expected = ProjectivePoint::generator() * scalar;

        let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 15, 32, 4>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 16, 32, 4>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 17, 32, 4>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 32, 32, 4>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 64, 32, 4>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 512, 32, 4>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_double_mul_ristretto() {
        let multiplier =
            WindowedScalarMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32, 5>::new(
                RistrettoPoint::generator(),
            );

        let other_point = RistrettoPoint::generator() * RistrettoScalar::from(3);

        let a = RistrettoScalar::rand(&mut thread_rng());
        let b = RistrettoScalar::rand(&mut thread_rng());
        let expected = RistrettoPoint::generator() * a + other_point * b;
        let actual = multiplier.mul_double(&a, &other_point, &b);
        assert_eq!(expected, actual);
    }
}
