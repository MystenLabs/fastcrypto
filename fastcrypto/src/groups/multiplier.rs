// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::{Doubling, GroupElement};
use crate::serde_helpers::ToFromByteArray;
use std::mem::size_of;

/// Trait for scalar multiplication for a fixed group element, e.g. by using precomputed values.
pub trait ScalarMultiplier<G: GroupElement> {
    /// Create a new scalar multiplier for the given base element.
    fn new(base_element: G) -> Self;

    /// Multiply the base element by the given scalar.
    fn mul(&self, scalar: &G::ScalarType) -> G;
}

/// Performs scalar multiplication using a fixed window method. If the addition and doubling operations for
/// `G` are constant time, the `mul`  is also constant time. The `CACHE_SIZE` should ideally be a power of
/// two. The `SCALAR_SIZE` is the number of bytes in the byte representation of the scalar type `S`, and we
/// assume that the `S::from_bytes` method returns the scalar in little-endian format.
pub struct ConstantTimeMultiplier<
    G: GroupElement<ScalarType = S>,
    S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
    const CACHE_SIZE: usize,
    const SCALAR_SIZE: usize,
> {
    /// Precomputed multiples of the base element, B, up to (2^WINDOW_WIDTH - 1) * B.
    cache: [G; CACHE_SIZE],
}

impl<
        G: GroupElement<ScalarType = S>,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > ConstantTimeMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
{
    /// The number of bits in the window. This is equal to the floor of the log2 of the cache size.
    const WINDOW_WIDTH: usize = 8 * size_of::<usize>() - CACHE_SIZE.leading_zeros() as usize - 1;

    /// Get the multiple s*G for a scalar 0 <= s < 2^WINDOW_WIDTH. If s is not in this range the method will panic.
    fn get_precomputed_multiple(&self, s: usize) -> G {
        // We do not store zero in the cache, so we need to handle it separately.
        if s == 0 {
            return G::zero();
        }
        self.cache[s - 1]
    }
}

/// Given a binary representation of a number in little-endian format, return the digits of its base 2^W expansion.
/// We use usize as digits because we will eventually use these as indices into a table of precomputed multiples.
fn compute_base_2w_expansion<const N: usize>(bytes: &[u8; N], window_size: usize) -> Vec<usize> {
    if window_size > 8 * size_of::<usize>() {
        panic!("Window size must be less than or equal to the number of bits in a usize");
    }

    // TODO: The output size is constant when used in ConstantTimeMultiplier, so we should be able to use an array with fixed size here
    // The base 2^w expansions digits in little-endian.
    let mut expansion = Vec::new();

    // Compute the number of digits needed to represent the numbed in base 2^w. This is equal to
    // ceil(8*N / window_size), and we compute like this because div_ceil is unstable as of rustc 1.69.0.
    let digits = (8 * N + window_size - 1) / window_size;

    // The current byte and bit index
    let mut current_byte = 0;
    let mut i = 0;

    for _ in 0..digits {
        let mut current_digit_value: usize = 0;
        let mut bits_added_to_current_digit = 0;
        while bits_added_to_current_digit < window_size && current_byte < N {
            let next_byte_index = (current_byte + 1) * 8;

            let (bits_to_read, next_byte) =
                if window_size - bits_added_to_current_digit < next_byte_index - i {
                    // There are enough bits in the current byte to fill the current digit
                    (window_size - bits_added_to_current_digit, current_byte)
                } else {
                    // There are not enough bits in the current byte to fill the current digit. Take the
                    // remaining bits and increment the byte index
                    (next_byte_index - i, current_byte + 1)
                };

            // Add the bits to the current digit
            current_digit_value +=
                (get_lendian_from_substring(&bytes[current_byte], i % 8, i % 8 + bits_to_read)
                    as usize)
                    << bits_added_to_current_digit;

            // Increment the counters
            bits_added_to_current_digit += bits_to_read;
            i += bits_to_read;
            current_byte = next_byte;
        }
        expansion.push(current_digit_value);
    }

    expansion
}

/// Get the integer represented by a given range of bits of a byte from start to end (exclusive).
#[inline]
fn get_lendian_from_substring(byte: &u8, start: usize, end: usize) -> u8 {
    byte >> start & ((1 << (end - start)) - 1) as u8
}

impl<
        G: GroupElement<ScalarType = S> + Doubling,
        S: GroupElement + ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > ScalarMultiplier<G> for ConstantTimeMultiplier<G, S, CACHE_SIZE, SCALAR_SIZE>
{
    fn new(base_element: G) -> Self {
        // Compute cache [G, 2G, 3G, ..., (2^WINDOW_WIDTH - 1)G]
        let mut cache = [base_element; CACHE_SIZE];
        //cache[0] = base_element;
        for i in 1..CACHE_SIZE {
            cache[i] = cache[i - 1] + cache[0];
        }
        Self { cache }
    }

    fn mul(&self, scalar: &S) -> G {
        let scalar_bytes = scalar.to_byte_array();

        let limbs = compute_base_2w_expansion::<SCALAR_SIZE>(&scalar_bytes, Self::WINDOW_WIDTH);

        // Number of digits in the base 2^window_size representation of the scalar
        let mut r: G = self.get_precomputed_multiple(limbs[limbs.len() - 1]);

        // Compute the scalar multiplication using Algorithm 9.49 (Fixed-base comb exponentiation)
        // from Christophe Doche: Handbook of Elliptic and Hyperelliptic Curve Cryptography
        for i in (0..=(limbs.len() - 2)).rev() {
            for _ in 1..=Self::WINDOW_WIDTH {
                r = r.double();
            }
            r += self.get_precomputed_multiple(limbs[i]);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
    use crate::groups::secp256r1::{ProjectivePoint, Scalar};

    #[test]
    fn test_get_bits() {
        let byte = 0b00000001;
        assert_eq!(0, get_lendian_from_substring(&byte, 0, 0));
        assert_eq!(1, get_lendian_from_substring(&byte, 0, 1));
        assert_eq!(1, get_lendian_from_substring(&byte, 0, 3));
        assert_eq!(1, get_lendian_from_substring(&byte, 0, 8));
        assert_eq!(0, get_lendian_from_substring(&byte, 1, 8));

        let byte = 0b00000011;
        assert_eq!(1, get_lendian_from_substring(&byte, 0, 1));
        assert_eq!(3, get_lendian_from_substring(&byte, 0, 2));
        assert_eq!(3, get_lendian_from_substring(&byte, 0, 3));
        assert_eq!(1, get_lendian_from_substring(&byte, 1, 8));
        assert_eq!(0, get_lendian_from_substring(&byte, 2, 8));

        let byte = 0b10000001;
        assert_eq!(1, get_lendian_from_substring(&byte, 0, 1));
        assert_eq!(1, get_lendian_from_substring(&byte, 0, 7));
        assert_eq!(129, get_lendian_from_substring(&byte, 0, 8));
        assert_eq!(64, get_lendian_from_substring(&byte, 1, 8));
        assert_eq!(16, get_lendian_from_substring(&byte, 3, 8));
    }

    #[test]
    fn test_base_2w_expansion() {
        let value: u128 = 123812341234567;
        let bytes = value.to_le_bytes();
        let expansion = compute_base_2w_expansion::<16>(&bytes, 8);
        assert_eq!(
            bytes.to_vec(),
            expansion.iter().map(|x| *x as u8).collect::<Vec<u8>>()
        );

        let mut sum = 0u128;
        for (i, value) in expansion.iter().enumerate() {
            sum += (1 << 8 * i) * *value as u128;
        }
        assert_eq!(value, sum);

        for window_size in 1..=64 {
            let expansion = compute_base_2w_expansion::<16>(&bytes, window_size);
            let mut sum = 0u128;
            for (i, value) in expansion.iter().enumerate() {
                sum += (1 << (window_size * i)) * *value as u128;
            }
            assert_eq!(value, sum);
        }
    }

    #[test]
    fn test_scalar_multiplication_ristretto() {
        let multiplier = ConstantTimeMultiplier::<RistrettoPoint, RistrettoScalar, 16, 32>::new(
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

        let multiplier = ConstantTimeMultiplier::<ProjectivePoint, Scalar, 15, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = ConstantTimeMultiplier::<ProjectivePoint, Scalar, 16, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = ConstantTimeMultiplier::<ProjectivePoint, Scalar, 17, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = ConstantTimeMultiplier::<ProjectivePoint, Scalar, 32, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = ConstantTimeMultiplier::<ProjectivePoint, Scalar, 64, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);

        let multiplier = ConstantTimeMultiplier::<ProjectivePoint, Scalar, 512, 32>::new(
            ProjectivePoint::generator(),
        );
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }
}
