// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::multiplier::integer_utils::{get_bits_from_bytes, test_bit};
use crate::groups::multiplier::{integer_utils, ScalarMultiplier};
use crate::groups::GroupElement;
use crate::serde_helpers::ToFromByteArray;
use std::iter::successors;

/// This multiplier uses pre-computation with the fixed window method. This multiplier is particularly
/// fast for double multiplications, but the double multiplication function, `double_mul`, is not constant
/// time. However, the single multiplication method, `mul`, is constant time.
///
/// The `CACHE_SIZE` should be a power of two. The `SCALAR_SIZE` is the number of bytes in the byte
/// representation of the scalar type `S`, and we assume that the `S::to_byte_array` method returns the
/// scalar in little-endian format.
pub struct FixedWindowMultiplier<
    G: GroupElement<ScalarType = S>,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const CACHE_SIZE: usize,
    const SCALAR_SIZE: usize,
> {
    /// Precomputed multiples of the base element from 0 up to CACHE_SIZE - 1 = 2^WINDOW_WIDTH - 1.
    cache: [G; CACHE_SIZE],
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > FixedWindowMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
{
    /// The number of bits in the window. This is equal to the floor of the log2 of the cache size.
    const WINDOW_WIDTH: usize = (usize::BITS - CACHE_SIZE.leading_zeros() - 1) as usize;
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > ScalarMultiplier<G> for FixedWindowMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
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

        let mut result: G = self.cache[base_2w_expansion[base_2w_expansion.len() - 1]];

        for i in (0..=(base_2w_expansion.len() - 2)).rev() {
            for _ in 1..=Self::WINDOW_WIDTH {
                result = result.double();
            }
            result += self.cache[base_2w_expansion[i]];
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

        let base_scalar_bytes = base_scalar.to_byte_array();
        let other_scalar_bytes = other_scalar.to_byte_array();

        // TODO: Allow other cache sizes here
        let other_element_cache =
            successors(Some(G::zero()), |element| Some(*element + other_element))
                .take(CACHE_SIZE)
                .collect::<Vec<_>>();

        let mut base_scalar_window_index = 0;
        let mut base_scalar_is_in_window = false;
        let mut base_scalar_latest_one_bit = 0;

        let mut other_scalar_window_index = 0;
        let mut other_scalar_is_in_window = false;
        let mut other_scalar_latest_one_bit = 0;

        let mut result = G::zero();

        let mut bit = SCALAR_SIZE * 8;
        let mut skip_doubling = true;

        while bit > 0 {
            if !skip_doubling {
                result = result.double();
            }

            bit -= 1;
            if base_scalar_is_in_window {
                base_scalar_window_index += 1;
                if base_scalar_window_index == Self::WINDOW_WIDTH {
                    result += self.cache[base_scalar_latest_one_bit];
                    base_scalar_is_in_window = false;
                }
            } else if test_bit(&base_scalar_bytes, bit) {
                if bit >= Self::WINDOW_WIDTH - 1 {
                    base_scalar_window_index = 1;
                    base_scalar_is_in_window = true;
                    base_scalar_latest_one_bit = get_bits_from_bytes(
                        &base_scalar_bytes,
                        bit + 1 - Self::WINDOW_WIDTH,
                        bit + 1,
                    );
                } else {
                    result += self.cache[1];
                }
                skip_doubling = false;
            }

            if other_scalar_is_in_window {
                other_scalar_window_index += 1;
                if other_scalar_window_index == Self::WINDOW_WIDTH {
                    other_scalar_is_in_window = false;
                    result += other_element_cache[other_scalar_latest_one_bit];
                }
            } else if test_bit(&other_scalar_bytes, bit) {
                if bit >= Self::WINDOW_WIDTH - 1 {
                    other_scalar_window_index = 1;
                    other_scalar_is_in_window = true;
                    other_scalar_latest_one_bit = get_bits_from_bytes(
                        &other_scalar_bytes,
                        bit + 1 - Self::WINDOW_WIDTH,
                        bit + 1,
                    );
                } else {
                    result += *other_element;
                }
                skip_doubling = false;
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
        let multiplier = FixedWindowMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32>::new(
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

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 15, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 16, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 17, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 32, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 64, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = FixedWindowMultiplier::<ProjectivePoint, Scalar, 512, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_double_mul_ristretto() {
        let multiplier = FixedWindowMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32>::new(
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
