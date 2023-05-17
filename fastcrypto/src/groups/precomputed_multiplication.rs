// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
#[cfg(test)]
use crate::groups::secp256r1::{ProjectivePoint, Scalar};
use crate::groups::{Doubling, GroupElement};
use crate::serde_helpers::ToFromByteArray;
use std::cmp::min;

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
}

/// Given a binary representation of a number in little-endian format, return the digits of its base 2^W expansion.
fn get_base_2w_expansion<const N: usize, const W: usize>(bytes: &[u8; N]) -> Vec<usize> {
    let mut result = Vec::new();

    let mut next_byte = 8;
    let mut current_byte = 0;
    let mut i = 0;
    // TODO: What if W does not divide 8*N?
    while i < 8 * N {
        let mut limb = 0;
        let mut limb_index = 0;
        while limb_index < W {
            let step = min(next_byte - i, W - limb_index);
            limb = (limb << step) + get_bits(&bytes[current_byte], i % 8, i % 8 + step - 1);
            limb_index += step;
            i += step;
            if i >= next_byte {
                current_byte += 1;
                next_byte += 8;
            }
        }
        result.push(limb as usize);
    }
    result
}

// End is inclusive
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

        let limbs = get_base_2w_expansion::<SCALAR_SIZE, 4>(&scalar_bytes);

        // TODO: Compute this somewhere nice
        let window_size = 4;

        // Number of digits in the base 2^window_size representation of the scalar
        let m = CACHE_SIZE;
        let mut r: G = self.get_multiple(limbs[m - 1]); //self.get_from_cache(&scalar_bytes, window_size, m - 1);

        for i in (0..m - 1).rev() {
            for _ in 1..=window_size {
                r = r.double();
            }
            r += self.get_multiple(limbs[i]); //self.get_from_cache(&scalar_bytes, window_size, i);
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
