// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Unpack each byte of `bytes` into individual bits (MSB first), each stored as 0 or 1.
pub(super) fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for shift in (0..8).rev() {
            bits.push((b >> shift) & 1);
        }
    }
    bits
}

/// Pack `bits` into `chunk_size`-bit values (MSB first within each chunk).
pub(super) fn bits_to_base(bits: &[u8], chunk_size: u16) -> Vec<u32> {
    assert!(chunk_size <= 32, "chunk_size must fit in u32");
    let n = chunk_size as usize;
    assert_eq!(
        bits.len() % n,
        0,
        "bits.len() must be a multiple of chunk_size"
    );
    let mut result = Vec::with_capacity(bits.len() / n);
    for chunk in bits.chunks(n) {
        let mut acc: u32 = 0;
        for &b in chunk {
            acc = (acc << 1) | u32::from(b);
        }
        result.push(acc);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_to_base_nibbles() {
        assert_eq!(bits_to_base(&bytes_to_bits(&[0xA3]), 4), vec![0xA, 0x3]);
        assert_eq!(
            bits_to_base(&bytes_to_bits(&[0xA3, 0xF0]), 4),
            vec![0xA, 0x3, 0xF, 0x0]
        );
    }

    #[test]
    fn test_bits_to_base_pairs() {
        // chunk_size = 2 → 0xA3 = 10 10 00 11 → [2, 2, 0, 3]
        assert_eq!(bits_to_base(&bytes_to_bits(&[0xA3]), 2), vec![2, 2, 0, 3]);
    }

    #[test]
    fn test_bits_to_base_single_bits() {
        assert_eq!(
            bits_to_base(&bytes_to_bits(&[0xA3]), 1),
            vec![1, 0, 1, 0, 0, 0, 1, 1]
        );
    }
}
