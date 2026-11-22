// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Constants and helpers shared by the secp256k1 group and BIP-340 targets.

/// The field modulus p, big-endian.
pub const FIELD_MODULUS: [u8; 32] =
    hex_literal::hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// The group order n, big-endian.
pub const GROUP_ORDER: [u8; 32] =
    hex_literal::hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// A 32-byte big-endian integer plus a small signed integer, for integers far from 0 and 2^256
/// such as p + d and n + d.
pub fn add_small(bytes: &[u8; 32], delta: i8) -> [u8; 32] {
    let mut sum = *bytes;
    let mut carry = delta as i16;
    for byte in sum.iter_mut().rev() {
        let digit = *byte as i16 + carry;
        *byte = digit.rem_euclid(256) as u8;
        carry = digit.div_euclid(256);
        if carry == 0 {
            break;
        }
    }
    sum
}
