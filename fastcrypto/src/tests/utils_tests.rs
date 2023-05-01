// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::utils::log2_byte;

// log2 using shift operations.
fn log2_byte_shift(b: u8) -> usize {
    let mut r = u8::from(b > 0xF) << 2;
    let mut b = b >> r;
    let shift = u8::from(b > 0x3) << 1;
    b >>= shift + 1;
    r |= shift | b;
    r.into()
}

#[test]
fn test_log2_byte() {
    for b in 0..=u8::MAX {
        let result_shift = log2_byte_shift(b);
        let result_lz = log2_byte(b);
        assert_eq!(result_shift, result_lz, "Mismatch for input {}", b);
    }
}
