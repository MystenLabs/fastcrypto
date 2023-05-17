// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
#[cfg(test)]
use crate::groups::secp256r1::{ProjectivePoint, Scalar};
use crate::groups::{Doubling, GroupElement};
use crate::serde_helpers::ToFromByteArray;

/// Trait for scalar multiplication of a fixed group element, eg. using precomputed values.
pub trait ScalarMultiplier<G: GroupElement> {
    fn new(base_element: G) -> Self;

    /// Multiply the base element by the given scalar.
    fn mul(&self, scalar: &G::ScalarType) -> G;

    /// Return the base element used for multiplication.
    fn get_base_element(&self) -> G;
}

pub struct FixedWindowScalarMultiplier<
    G: GroupElement,
    const CACHE_SIZE: usize,
    const SCALAR_SIZE: usize,
> {
    /// Precomputed multiples of the base element, G, up to (2^WINDOW_WIDTH - 1) * G.
    cache: [G; CACHE_SIZE],
}

impl<G: GroupElement, const CACHE_SIZE: usize, const SCALAR_SIZE: usize>
    FixedWindowScalarMultiplier<G, CACHE_SIZE, SCALAR_SIZE>
{
    /// Get the multiple of the base element G for a scalar smaller than `2^WINDOW_WIDTH`.
    fn get_multiple(&self, s: usize) -> G {
        if s == 0 {
            return G::zero();
        }
        self.cache[s - 1]
    }

    /// Assuming the scalar is written in base 2^window_size as k_0,...,k_{m-1}, return the the k_i'th
    /// element from the cache, eg. k_i * B.
    fn get_from_cache(
        &self,
        scalar_bytes: &[u8; SCALAR_SIZE],
        window_size: usize,
        index: usize,
    ) -> G {
        self.get_multiple(read_window(scalar_bytes, index, window_size))
    }
}

fn get_bits(byte: &u8, start: usize, end: usize) -> u8 {
    let mut result = *byte;
    result >>= start;
    let mask = ((1 << (end - start + 1)) - 1) as u8;
    result &= mask;
    result
}

#[test]
fn test_get_bits() {
    let byte = 0b00000001;

    assert_eq!(1, get_bits(&byte, 0, 1));
    assert_eq!(1, get_bits(&byte, 0, 2));
    assert_eq!(1, get_bits(&byte, 0, 7));
    assert_eq!(0, get_bits(&byte, 7, 7));

    let byte = 0b00000011;
    assert_eq!(3, get_bits(&byte, 0, 2));
    assert_eq!(3, get_bits(&byte, 0, 3));
    assert_eq!(1, get_bits(&byte, 1, 3));
    assert_eq!(0, get_bits(&byte, 6, 7));
    assert_eq!(0, get_bits(&byte, 7, 7));
}

// TODO: Do this in one loop instead
/// Get the i'th window of WINDOW_WIDTH bits from the given byte array
fn read_window<const N: usize>(
    scalar_bytes: &[u8; N],
    window_number: usize,
    window_width: usize,
) -> usize {
    let start_byte_index = (window_number * window_width) / 8;
    let start_bit_index = (window_number * window_width) % 8;
    let end_byte_index = ((window_number + 1) * window_width - 1) / 8;
    let end_bit_index = ((window_number + 1) * window_width - 1) % 8;

    if start_byte_index >= N {
        return 0;
    }

    if start_byte_index == end_byte_index {
        return get_bits(
            &scalar_bytes[start_byte_index],
            start_bit_index,
            end_bit_index,
        ) as usize;
    }

    let mut result = get_bits(&scalar_bytes[start_byte_index], start_bit_index, 7) as usize;

    //for (i, byte) in scalar_bytes.iter().enumerate().take(end_byte_index + 1).skip(start_byte_index + 1) {
    for i in start_byte_index + 1..=end_byte_index {
        if i != end_byte_index {
            result <<= 8;
            result += if i < N { scalar_bytes[i] as usize } else { 0 };
        } else {
            result <<= end_bit_index + 1;
            result += if i < N {
                get_bits(&scalar_bytes[i], 0, end_bit_index) as usize
            } else {
                0
            };
        }
    }

    result
}

#[test]
fn test_window() {
    let bytes = [0b00000001, 0b00000010, 0b00000011, 0b00000100];
    assert_eq!(bytes[0] as usize, read_window(&bytes, 0, 8));
    assert_eq!(bytes[2] as usize, read_window(&bytes, 2, 8));

    assert_eq!(1, read_window(&bytes, 0, 4));
    assert_eq!(0, read_window(&bytes, 1, 4));

    assert_eq!(1, read_window(&bytes, 0, 6));
    assert_eq!(2, read_window(&bytes, 1, 6));
    assert_eq!(3, read_window(&bytes, 2, 6));
    assert_eq!(0, read_window(&bytes, 3, 6));
    assert_eq!(4, read_window(&bytes, 4, 6));
    assert_eq!(0, read_window(&bytes, 5, 6));
}

impl<
        G: GroupElement<ScalarType = S> + Doubling,
        S: ToFromByteArray<SCALAR_SIZE>,
        const CACHE_SIZE: usize,
        const SCALAR_SIZE: usize,
    > ScalarMultiplier<G> for FixedWindowScalarMultiplier<G, CACHE_SIZE, SCALAR_SIZE>
{
    fn new(base_element: G) -> Self {
        let mut cache = [G::zero(); CACHE_SIZE];
        cache[0] = base_element;
        for i in 1..CACHE_SIZE {
            cache[i] = cache[i - 1] + cache[0];
        }
        Self { cache }
    }

    fn mul(&self, scalar: &S) -> G {
        let scalar_bytes = scalar.to_byte_array();

        // TODO: Compute this somewhere nice
        let window_size = 4;

        // Number of digits in the base 2^window_size representation of the scalar
        let m = CACHE_SIZE;
        let mut r: G = self.get_from_cache(&scalar_bytes, window_size, m - 1);

        for i in (0..m - 1).rev() {
            for _ in 1..=window_size {
                r = r.double();
            }
            r += self.get_from_cache(&scalar_bytes, window_size, i);
        }
        r
    }

    fn get_base_element(&self) -> G {
        self.cache[0]
    }
}

#[test]
fn test_scalar_multiplication_ristretto() {
    let multiplier =
        FixedWindowScalarMultiplier::<RistrettoPoint, 16, 32>::new(RistrettoPoint::generator());
    let scalar = RistrettoScalar::from(123456789);
    let expected = RistrettoPoint::generator() * scalar;
    let actual = multiplier.mul(&scalar);
    assert_eq!(expected, actual);
}

#[test]
fn test_scalar_multiplication_secp256r1() {
    let multiplier =
        FixedWindowScalarMultiplier::<ProjectivePoint, 16, 32>::new(ProjectivePoint::generator());
    let scalar = Scalar::from(123456789);
    let expected = ProjectivePoint::generator() * scalar;
    let actual = multiplier.mul(&scalar);
    assert_eq!(expected, actual);
}
