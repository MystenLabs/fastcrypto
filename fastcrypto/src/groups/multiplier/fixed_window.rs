// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::multiplier::{integer_utils, ScalarMultiplier};
use crate::groups::{Doubling, GroupElement};
use crate::serde_helpers::ToFromByteArray;
use std::mem::size_of;

/// This multiplier uses pre-computation with the fixed window method. If the addition and doubling
/// operations for `G` are constant time, the `mul` and `double_mul` methods are also constant time.
/// The `CACHE_SIZE` should be a power of two. The `SCALAR_SIZE` is the number of bytes in the byte
/// representation of the scalar type `S`, and we assume that the `S::from_bytes` method returns the
/// scalar in little-endian format.
///
/// This multiplier is particularly fast for double multiplications.
pub struct FixedWindowMultiplier<
    G: GroupElement<ScalarType = S>,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const CACHE_SIZE: usize,
    const SCALAR_SIZE: usize,
> {
    /// Precomputed multiples of the base element from 0 up to (2^WINDOW_WIDTH - 1).
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
    const WINDOW_WIDTH: usize = 8 * size_of::<usize>() - CACHE_SIZE.leading_zeros() as usize - 1;

    /// Get the multiple `s * base_element` for a scalar `s` with `0 <= s < 2^Self::WINDOW_WIDTH`.
    /// If `s` is not in this range the method will panic.
    fn get_precomputed_multiple(&self, s: usize) -> G {
        self.cache[s]
    }
}

impl<
        G: GroupElement<ScalarType = S> + Doubling,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > ScalarMultiplier<G> for FixedWindowMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
{
    fn new(base_element: G) -> Self {
        // Compute cache [0, base_element, 2 * base_element, ..., (2^WINDOW_WIDTH - 1) * base_element].
        // Note that CACHE_SIZE = 2^WINDOW_WIDTH.
        let mut cache = [G::zero(); CACHE_SIZE];
        for i in 1..CACHE_SIZE {
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

        let mut result: G =
            self.get_precomputed_multiple(base_2w_expansion[base_2w_expansion.len() - 1]);

        for i in (0..=(base_2w_expansion.len() - 2)).rev() {
            for _ in 1..=Self::WINDOW_WIDTH {
                result = result.double();
            }
            result += self.get_precomputed_multiple(base_2w_expansion[i]);
        }
        result
    }

    fn mul_double(
        &self,
        base_scalar: &G::ScalarType,
        other_element: &G,
        other_scalar: &G::ScalarType,
    ) -> G {
        // Compute the sum of the two multiples using Straus' algorithm.

        // Scalars as bytes in little-endian representations.
        let base_scalar_bytes = base_scalar.to_byte_array();
        let base_scalar_2w_expansion = integer_utils::compute_base_2w_expansion::<SCALAR_SIZE>(
            &base_scalar_bytes,
            Self::WINDOW_WIDTH,
        );
        let other_scalar_bytes = other_scalar.to_byte_array();
        let other_scalar_2w_expansion = integer_utils::compute_base_2w_expansion::<SCALAR_SIZE>(
            &other_scalar_bytes,
            Self::WINDOW_WIDTH,
        );

        let mut multiplier = PrecomputedSmallMultiplier::<G, CACHE_SIZE>::new(*other_element);

        let mut result: G = self
            .get_precomputed_multiple(base_scalar_2w_expansion[base_scalar_2w_expansion.len() - 1])
            + multiplier.mul(other_scalar_2w_expansion[other_scalar_2w_expansion.len() - 1]);

        for i in (0..=(base_scalar_2w_expansion.len() - 2)).rev() {
            for _ in 1..=Self::WINDOW_WIDTH {
                result = result.double();
            }
            result += self.get_precomputed_multiple(base_scalar_2w_expansion[i]);
            result += multiplier.mul(other_scalar_2w_expansion[i]);
        }
        result
    }
}

/// Compute scalar multiplication with a small scalar (usize type)
trait SmallScalarMultiplier<G: GroupElement> {
    /// Create a new multiplier with the given base element
    fn new(base_element: G) -> Self;

    /// Compute scalar * base_element.
    fn mul(&mut self, scalar: usize) -> G;
}

/// Scalar multiplier which precomputes i * base_element for i = 1,...,N-1. If larger multiples are
/// requested, the `mul` method will panic.
struct PrecomputedSmallMultiplier<G: GroupElement + Doubling, const N: usize> {
    cache: [G; N],
}

impl<G: GroupElement + Doubling, const N: usize> SmallScalarMultiplier<G>
    for PrecomputedSmallMultiplier<G, N>
{
    fn new(base_element: G) -> Self {
        let mut cache = [G::zero(); N];
        cache[1] = base_element;
        for i in 2..N {
            cache[i] = cache[i - 1] + base_element;
        }
        Self { cache }
    }

    fn mul(&mut self, scalar: usize) -> G {
        self.cache[scalar]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use crate::groups::secp256r1::{ProjectivePoint, Scalar};

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
    fn test_double_mul_secp256r1() {
        let multiplier = FixedWindowMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32>::new(
            RistrettoPoint::generator(),
        );

        let other_point = RistrettoPoint::generator() * RistrettoScalar::from(3);

        let a = RistrettoScalar::from(1234);
        let b = RistrettoScalar::from(5678);
        let expected = RistrettoPoint::generator() * a + other_point * b;
        let actual = multiplier.mul_double(&a, &other_point, &b);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_small_multiplier() {
        let mut multiplier =
            PrecomputedSmallMultiplier::<RistrettoPoint, 8>::new(RistrettoPoint::generator());
        let expected = RistrettoPoint::generator() * RistrettoScalar::from(7);
        let actual = multiplier.mul(7);
        assert_eq!(expected, actual);
    }
}
