// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Given a binary representation of a number in little-endian format, return the digits of its base
/// `2^bits_per_digit` expansion.
pub fn compute_base_2w_expansion<const N: usize>(
    bytes: &[u8; N],
    bits_per_digit: usize,
) -> Vec<usize> {
    assert!(0 < bits_per_digit && bits_per_digit <= usize::BITS as usize);

    // The base 2^window_size expansions digits in little-endian representation.
    let mut digits = Vec::new();

    // Compute the number of digits needed to represent the numbed in base 2^w. This is equal to
    // ceil(8*N / window_size), and we compute like this because div_ceil is unstable as of rustc 1.69.0.
    let digits_count = div_ceil(8 * N, bits_per_digit);

    for i in 0..digits_count {
        digits.push(get_bits_from_bytes(
            bytes,
            bits_per_digit * i,
            bits_per_digit * (i + 1),
        ));
    }
    digits
}

/// Get the integer represented by a given range of bits of a byte from start to end (exclusive).
#[inline]
fn get_lendian_from_substring(byte: &u8, start: usize, end: usize) -> u8 {
    assert!(start <= end);
    byte >> start & ((1 << (end - start)) - 1) as u8
}

/// Compute ceil(numerator / denominator).
pub(crate) fn div_ceil(numerator: usize, denominator: usize) -> usize {
    (numerator + denominator - 1) / denominator
}

/// Get the integer represented by a given range of bits of a an integer represented by a little-endian
/// byte array from start to end (exclusive). The `end` argument may be arbitrarily large, but if it
/// is larger than 8*N, the remaining bits of the byte array will be assumed to be zero.
#[inline]
pub fn get_bits_from_bytes<const N: usize>(bytes: &[u8; N], start: usize, end: usize) -> usize {
    assert!(start <= end && start < 8 * N);

    let mut result: usize = 0;
    let mut bits_added = 0;

    let mut current_bit = start % 8;
    let mut current_byte = start / 8;

    while bits_added < end - start && current_byte < N {
        let remaining_bits = end - start - bits_added;
        let (bits_to_read, next_byte, next_bit) = if remaining_bits < 8 - current_bit {
            // There are enough bits left in the current byte
            (remaining_bits, current_byte, current_bit + remaining_bits)
        } else {
            // There are not enough bits in the current byte. Take the remaining bits and increment the byte index
            (8 - current_bit, current_byte + 1, 0)
        };

        // Add the bits to the result
        result += (get_lendian_from_substring(
            &bytes[current_byte],
            current_bit,
            current_bit + bits_to_read,
        ) as usize)
            << bits_added;

        // Increment the counters
        bits_added += bits_to_read;
        current_bit = next_bit;
        current_byte = next_byte;
    }
    result
}

/// Return true iff the bit at the given index is set.
#[inline]
pub fn test_bit<const N: usize>(bytes: &[u8; N], index: usize) -> bool {
    assert!(index < 8 * N);
    let byte = index >> 3;
    let shifted = bytes[byte] >> (index & 7);
    shifted & 1 != 0
}

/// Compute the floor of the base-2 logarithm of <i>x</i>.
pub const fn log2(x: usize) -> usize {
    (usize::BITS - x.leading_zeros() - 1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_eq;

    #[test]
    fn test_lendian_from_substring() {
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

        // Is w = 8, the base 2^w expansion should be equal to the le bytes.
        let expansion = compute_base_2w_expansion::<16>(&bytes, 8);
        assert_eq!(
            bytes.to_vec(),
            expansion.iter().map(|x| *x as u8).collect::<Vec<u8>>()
        );

        // Verify that the expansion is correct for w = 1, ..., 64
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
    fn test_bits_form_bytes() {
        let bytes = [0b00000001, 0b00000011, 0b10000001];
        assert_eq!(0, get_bits_from_bytes(&bytes, 0, 0));
        assert_eq!(1, get_bits_from_bytes(&bytes, 0, 1));
        assert_eq!(3, get_bits_from_bytes(&bytes, 8, 10));
        assert_eq!(1, get_bits_from_bytes(&bytes, 16, 17));
        assert_eq!(0, get_bits_from_bytes(&bytes, 17, 23));
        assert_eq!(1, get_bits_from_bytes(&bytes, 23, 100));
    }
}
