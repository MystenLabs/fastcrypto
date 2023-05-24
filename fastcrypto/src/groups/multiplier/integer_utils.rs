use std::mem::size_of;

/// Given a binary representation of a number in little-endian format, return the digits of its base 2^W expansion.
/// We use usize as digits because we will eventually use these as indices into a table of precomputed multiples.
pub fn compute_base_2w_expansion<const N: usize>(
    bytes: &[u8; N],
    window_size: usize,
) -> Vec<usize> {
    if window_size > 8 * size_of::<usize>() {
        panic!("Window size must be less than or equal to the number of bits in a usize");
    }

    // TODO: The output size is constant when used in the multipliers, so we should be able to use an array with fixed size here
    // The base 2^w expansions digits in little-endian.
    let mut expansion = Vec::new();

    // Compute the number of digits needed to represent the numbed in base 2^w. This is equal to
    // ceil(8*N / window_size), and we compute like this because div_ceil is unstable as of rustc 1.69.0.
    let digits = div_ceil(8 * N, window_size);

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

/// Compute ceil(numerator / denominator).
pub fn div_ceil(numerator: usize, denominator: usize) -> usize {
    (numerator + denominator - 1) / denominator
}

#[cfg(test)]
mod tests {
    use super::*;

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
