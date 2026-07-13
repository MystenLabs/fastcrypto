// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from PQClean crypto_sign/falcon-512/clean/codec.c,
// Copyright (c) 2017-2019 Falcon Project, MIT license; full notice in mod.rs.

//! Byte decoders for the Falcon-512 wire formats. All of them reject
//! non-canonical input: a byte string either decodes one way or not at all.

use super::{N, PUBKEY_LEN, Q};

/// Decode a public key: header 0x09, then 512 coefficients at 14 bits each,
/// MSB-first, every coefficient < q.
pub fn decode_pubkey(pubkey: &[u8], h: &mut [u16; N]) -> bool {
    if pubkey.len() != PUBKEY_LEN {
        return false;
    }
    if pubkey[0] != 9 {
        return false;
    }

    let data = &pubkey[1..];
    let mut acc: u32 = 0;
    let mut acc_len: i32 = 0;
    let mut u: usize = 0;
    let mut buf_idx: usize = 0;

    while u < N {
        acc = (acc << 8) | (data[buf_idx] as u32);
        buf_idx += 1;
        acc_len += 8;

        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= Q {
                return false;
            }
            h[u] = w as u16;
            u += 1;
        }
    }

    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return false;
    }

    true
}

/// Encode h as a public key: header 0x09, then 512 coefficients at 14 bits
/// each, MSB-first. Coefficients must already be reduced mod q; 512 * 14 bits
/// is byte-aligned, so the encoding is unique.
pub fn encode_pubkey(h: &[u16; N]) -> [u8; PUBKEY_LEN] {
    let mut out = [0u8; PUBKEY_LEN];
    out[0] = 9;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut idx = 1;
    for &c in h.iter() {
        debug_assert!((c as u32) < Q);
        acc = (acc << 14) | c as u32;
        acc_len += 14;
        while acc_len >= 8 {
            acc_len -= 8;
            out[idx] = (acc >> acc_len) as u8;
            idx += 1;
        }
    }
    debug_assert_eq!(idx, PUBKEY_LEN);
    out
}

/// Decode a compressed signature body into s2. Returns bytes consumed, or 0
/// on error. Per coefficient: 1 sign bit, low 7 magnitude bits, high bits in
/// unary. Rejects negative zero, magnitude > 2047, and non-zero padding bits.
pub fn decode_sig_compressed(data: &[u8], s2: &mut [i16; N]) -> usize {
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v = 0;

    for u in 0..N {
        if v >= data.len() {
            return 0;
        }
        acc = (acc << 8) | (data[v] as u32);
        v += 1;

        let b = acc >> acc_len;
        let sign = b & 128;
        let mut m = b & 127;

        loop {
            if acc_len == 0 {
                if v >= data.len() {
                    return 0;
                }
                acc = (acc << 8) | (data[v] as u32);
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;

            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return 0;
            }
        }

        if sign != 0 && m == 0 {
            return 0;
        }

        s2[u] = if sign != 0 { -(m as i16) } else { m as i16 };
    }

    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return 0;
    }

    v
}

/// Decode `N` trimmed two's-complement values of `bits` width (the reference
/// `trim_i8_decode`). Rejects the forbidden -2^(bits-1) value and non-zero
/// padding bits.
pub fn trim_i8_decode(data: &[u8], bits: u32, out: &mut [i8; N]) -> bool {
    debug_assert_eq!(data.len() * 8, N * bits as usize);
    let mask1: u32 = (1 << bits) - 1;
    let mask2: u32 = 1 << (bits - 1);
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut v = 0;
    let mut u = 0;
    while u < N {
        acc = (acc << 8) | (data[v] as u32);
        v += 1;
        acc_len += 8;
        while acc_len >= bits && u < N {
            acc_len -= bits;
            let w = (acc >> acc_len) & mask1;
            if w == mask2 {
                return false;
            }
            let val = if w & mask2 != 0 {
                w as i32 - (1i32 << bits)
            } else {
                w as i32
            };
            out[u] = val as i8;
            u += 1;
        }
    }
    (acc & ((1 << acc_len) - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_decode_header() {
        let mut h = [0u16; N];
        let bad_pk = [8u8; PUBKEY_LEN];
        assert!(!decode_pubkey(&bad_pk, &mut h));
        let short_pk = [9u8; 100];
        assert!(!decode_pubkey(&short_pk, &mut h));
    }
}
