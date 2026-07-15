// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from PQClean crypto_sign/falcon-512/clean/codec.c,
// Copyright (c) 2017-2019 Falcon Project, MIT license; full notice in mod.rs.

//! Byte codecs for the Falcon-512 wire formats. All decoders reject
//! non-canonical input: a byte string either decodes one way or not at all.
//! The encoders exist for key generation (`falcon512::sign`) and emit the
//! same unique form the decoders accept.

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

/// Encode `N` values in trimmed two's-complement at `bits` width, MSB-first
/// (the reference `trim_i8_encode`). `out` must be exactly N*bits/8 bytes;
/// N = 512 keeps both key widths (6 and 8 bits) byte-aligned, so there is no
/// padding tail. Returns false if any value falls outside
/// ±(2^(bits-1) - 1) — the reference range check, which also excludes the
/// -2^(bits-1) pattern that [`trim_i8_decode`] rejects.
pub fn trim_i8_encode(x: &[i8; N], bits: u32, out: &mut [u8]) -> bool {
    debug_assert_eq!(out.len() * 8, N * bits as usize);
    let maxv: i32 = (1 << (bits - 1)) - 1;
    let mask: u32 = (1 << bits) - 1;
    let mut acc: u32 = 0;
    let mut acc_len: u32 = 0;
    let mut idx = 0;
    for &v in x.iter() {
        if (v as i32) < -maxv || (v as i32) > maxv {
            return false;
        }
        acc = (acc << bits) | ((v as u8) as u32 & mask);
        acc_len += bits;
        while acc_len >= 8 {
            acc_len -= 8;
            out[idx] = (acc >> acc_len) as u8;
            idx += 1;
        }
    }
    debug_assert_eq!(idx, out.len());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_i8_roundtrip() {
        // Ramp over the full 6-bit legal range; decode must invert encode.
        let mut x = [0i8; N];
        for (i, v) in x.iter_mut().enumerate() {
            *v = ((i % 63) as i8) - 31;
        }
        let mut data = [0u8; N * 6 / 8];
        assert!(trim_i8_encode(&x, 6, &mut data));
        let mut back = [0i8; N];
        assert!(trim_i8_decode(&data, 6, &mut back));
        assert_eq!(x, back);

        // -2^(bits-1) and beyond are outside the reference range check.
        x[0] = -32;
        assert!(!trim_i8_encode(&x, 6, &mut data));
    }

    #[test]
    fn pubkey_decode_header() {
        let mut h = [0u16; N];
        let bad_pk = [8u8; PUBKEY_LEN];
        assert!(!decode_pubkey(&bad_pk, &mut h));
        let short_pk = [9u8; 100];
        assert!(!decode_pubkey(&short_pk, &mut h));
    }
}
