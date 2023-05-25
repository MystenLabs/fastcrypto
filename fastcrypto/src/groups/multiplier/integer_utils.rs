// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Given a binary representation of a number in little-endian format, return the digits of its base
/// `2^bits_per_digit` expansion. We use usize as digits because we will eventually use these as indices
/// in an array.
pub fn compute_base_2w_expansion<const N: usize>(
    bytes: &[u8; N],
    bits_per_digit: usize,
) -> Vec<usize> {
    if bits_per_digit > usize::BITS as usize {
        panic!("Window size must be less than or equal to the number of bits in a usize");
    }

    // The base 2^window_size expansions digits in little-endian representation.
    let mut digits = Vec::new();

    // Compute the number of digits needed to represent the numbed in base 2^w. This is equal to
    // ceil(8*N / window_size), and we compute like this because div_ceil is unstable as of rustc 1.69.0.
    let digits_count = div_ceil(8 * N, bits_per_digit);

    // The current byte and bit index
    let mut current_byte = 0;
    let mut current_bit = 0;

    for _ in 0..digits_count {
        let mut current_digit: usize = 0;
        let mut bits_added_to_current_digit = 0;
        while bits_added_to_current_digit < bits_per_digit && current_byte < N {
            let remaining_bits_for_current_digit = bits_per_digit - bits_added_to_current_digit;
            let (bits_to_read, next_byte, next_bit) =
                if remaining_bits_for_current_digit < 8 - current_bit {
                    // There are enough bits in the current byte to fill the current digit
                    (
                        remaining_bits_for_current_digit,
                        current_byte,
                        current_bit + remaining_bits_for_current_digit,
                    )
                } else {
                    // There are not enough bits in the current byte to fill the current digit. Take the
                    // remaining bits and increment the byte index
                    (8 - current_bit, current_byte + 1, 0)
                };

            // Add the bits to the current digit
            current_digit += (get_lendian_from_substring(
                &bytes[current_byte],
                current_bit,
                current_bit + bits_to_read,
            ) as usize)
                << bits_added_to_current_digit;

            // Increment the counters
            bits_added_to_current_digit += bits_to_read;
            current_bit = next_bit;
            current_byte = next_byte;
        }
        digits.push(current_digit);
    }

    digits
}

/// Get the integer represented by a given range of bits of a byte from start to end (exclusive).
#[inline]
fn get_lendian_from_substring(byte: &u8, start: usize, end: usize) -> u8 {
    byte >> start & ((1 << (end - start)) - 1) as u8
}

/// Compute ceil(numerator / denominator).
pub(crate) fn div_ceil(numerator: usize, denominator: usize) -> usize {
    (numerator + denominator - 1) / denominator
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_eq;

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
}
