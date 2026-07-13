// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from the Falcon reference implementation via PQClean
// (crypto_sign/falcon-512/clean: vrfy.c, common.c),
// Copyright (c) 2017-2019 Falcon Project, MIT license; the full
// notice is in this module's mod.rs.

//! Top-level Falcon-512 verification: the two entry points the scheme uses.
//!
//! # Verification algorithm (Falcon spec §3.7, §3.11) #
//!
//! Given public key h, message m, and signature (nonce r, s2):
//! 1. challenge c = HashToPoint(r || m) over Z_q via SHAKE-256 rejection sampling;
//! 2. recover s1 = c − s2.h in R_q = Z_q[x]/(x^n + 1);
//! 3. accept iff ||(s1, s2)||^2 ≤ [`L2_BOUND`].

use super::codec::{decode_pubkey, decode_sig_compressed, encode_pubkey, trim_i8_decode};
use super::ntt::{
    field_sub, ntt_forward, ntt_inverse, poly_div_pointwise, poly_pointwise_mul,
    poly_prepare_for_mul, poly_sub,
};
use super::{L2_BOUND, N, PUBKEY_LEN, Q, SECKEY_LEN, SIG_MAX_LEN, SIG_MIN_LEN, SIG_PADDED_LEN};

/// Verify a Falcon-512 signature (permissive / interop mode).
///
/// Accepts both header families, `0x29` (variable-length compressed, what the
/// KATs and falcon.py emit) and `0x39` (padded, what PQClean emits), so two
/// encodings of one signature can verify. Callers needing a unique encoding
/// must use [`verify_strict`].
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_512(public_key, message, signature)
}

/// Verify a Falcon-512 signature in **strict canonical form** (authenticator /
/// consensus mode). Exactly one byte encoding per signature: 666 bytes, header
/// `0x39`, zero tail — the PQClean `falcon-padded-512` wire format.
///
/// # Why?
/// A transaction authenticator must not let two distinct byte-strings be valid
/// encodings of the same signature: anyone could then re-encode a signed
/// transaction in flight and change its digest (tx-malleability). One
/// fixed-length encoding keeps the signature bytes safe to hash.
pub fn verify_strict(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != SIG_PADDED_LEN || signature[0] != 0x39 {
        return false;
    }
    verify_512(public_key, message, signature)
}

/// Structural public-key validation
pub fn validate_public_key(pk: &[u8]) -> bool {
    decode_pubkey(pk, &mut [0u16; N])
}

/// Derive the public key from a PQClean-format secret key
/// (`0x59 || f || g || F`, trimmed two's-complement): h = g / f in R_q,
/// encoded canonically. None if the key is structurally invalid or f is not invertible.
///
/// F is only checked structurally (G is not stored, and fG − gF = q cannot
/// be confirmed in Z_q alone); a bad F cannot make a wrong signature verify,
/// it fails at signing time. Do not probe-sign to compensate: Falcon signers
/// need not terminate on a degenerate basis.
pub fn derive_public_key(sk: &[u8]) -> Option<[u8; PUBKEY_LEN]> {
    // f and g pack to 512 . 6 / 8 bytes each, F to 512 . 8 / 8.
    const FG_BYTES: usize = N * 6 / 8;
    const F_START: usize = 1 + 2 * FG_BYTES;

    if sk.len() != SECKEY_LEN || sk[0] != 0x50 + 9 {
        return None;
    }
    let mut f = [0i8; N];
    let mut g = [0i8; N];
    let mut big_f = [0i8; N];
    if !trim_i8_decode(&sk[1..1 + FG_BYTES], 6, &mut f)
        || !trim_i8_decode(&sk[1 + FG_BYTES..F_START], 6, &mut g)
        || !trim_i8_decode(&sk[F_START..], 8, &mut big_f)
    {
        return None;
    }

    // Lift f and g from signed coefficients into Z_q, then h = g/f pointwise
    // in the NTT domain.
    let mut fq = [0u16; N];
    let mut gq = [0u16; N];
    for i in 0..N {
        fq[i] = (f[i] as i32).rem_euclid(Q as i32) as u16;
        gq[i] = (g[i] as i32).rem_euclid(Q as i32) as u16;
    }
    ntt_forward(&mut fq);
    ntt_forward(&mut gq);
    let mut h = poly_div_pointwise(&gq, &fq)?;
    ntt_inverse(&mut h);
    Some(encode_pubkey(&h))
}

/// A secret key is consistent with `pk` iff it derives exactly those bytes.
pub fn validate_secret_key(sk: &[u8], pk: &[u8]) -> bool {
    derive_public_key(sk).is_some_and(|derived| derived[..] == *pk)
}

/// Full verification of a (compressed or padded) signature. Total on all
/// inputs: malformed anything is `false`, never a panic.
fn verify_512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // Public key: length and header (logn = 9 for Falcon-512).
    if pubkey.len() != PUBKEY_LEN {
        return false;
    }
    const FALCON_512_LOGN: u8 = 9;
    if pubkey[0] != FALCON_512_LOGN {
        return false;
    }

    // Signature header. The high nibble selects the encoding family; both
    // 0x2X (compressed, KAT/falcon.py) and 0x3X (padded, PQClean) are
    // accepted, and canonicity is enforced on the decoded body below.
    // 0x5X (CT, 809 bytes) has no decoder here and also fails the size gate.
    let sig_len = signature.len();
    if sig_len < SIG_MIN_LEN || sig_len > SIG_MAX_LEN {
        return false;
    }
    let sig_header = signature[0];
    if (sig_header & 0x0F) != FALCON_512_LOGN {
        return false;
    }
    let fmt = sig_header & 0xF0;
    if fmt != 0x20 && fmt != 0x30 {
        return false;
    }

    let mut h = [0u16; N];
    if !decode_pubkey(pubkey, &mut h) {
        return false;
    }

    let nonce = &signature[1..41];

    let mut s2 = [0i16; N];
    let sig_data = &signature[41..];
    let decoded_len = decode_sig_compressed(sig_data, &mut s2);
    if decoded_len == 0 {
        return false;
    }

    // Canonicity: the body either decodes exactly (natural length) or the
    // total signature is exactly 666 bytes with an all-zero tail. Any other
    // padded length is rejected, so one s2 has at most two encodings
    // (natural and 666-padded), never an arbitrary inflation.
    let is_natural = decoded_len == sig_data.len();
    let is_padded = signature.len() == SIG_PADDED_LEN;
    if !is_natural && !is_padded {
        return false;
    }
    for i in decoded_len..sig_data.len() {
        if sig_data[i] != 0 {
            return false;
        }
    }

    let mut c0 = [0u16; N];
    hash_to_point(nonce, message, &mut c0);

    poly_prepare_for_mul(&mut h);
    verify_raw(&c0, &s2, &h)
}

/// s1 = c0 - s2.h, then the norm check. `h` must already be in NTT+Montgomery
/// form.
fn verify_raw(c0: &[u16; N], s2: &[i16; N], h: &[u16; N]) -> bool {
    let mut tt = [0u16; N];

    // s2 to unsigned representation mod q.
    for i in 0..N {
        let w = s2[i] as i32;
        let w = if w < 0 {
            (w + Q as i32) as u32
        } else {
            w as u32
        };
        tt[i] = w as u16;
    }

    // s2.h in Z_q[X]/(X^n + 1).
    ntt_forward(&mut tt);
    poly_pointwise_mul(&mut tt, h);
    ntt_inverse(&mut tt);

    // -s1 = s2.h - c0; the sign flip does not affect the norm.
    poly_sub(&mut tt, c0);

    let mut s1 = [0i16; N];
    for i in 0..N {
        let w = tt[i] as i32;
        let w = if w > (Q as i32 / 2) { w - Q as i32 } else { w };
        s1[i] = w as i16;
    }

    is_short(&s1, s2)
}

/// Verifies that ||(s1, s2)||^2 ≤ [`L2_BOUND`].
fn is_short(s1: &[i16; N], s2: &[i16; N]) -> bool {
    let mut s: u32 = 0;
    let mut ng: u32 = 0;

    for i in 0..N {
        let z1 = s1[i] as i32;
        s = s.wrapping_add((z1 * z1) as u32);
        ng |= s;

        let z2 = s2[i] as i32;
        s = s.wrapping_add((z2 * z2) as u32);
        ng |= s;
    }

    // Saturate to u32::MAX if any intermediate sum had bit 31 set.
    s |= 0u32.wrapping_sub(ng >> 31);

    s <= L2_BOUND
}

/// Hash nonce || message to a challenge polynomial: squeeze SHAKE-256 two
/// bytes at a time as big-endian u16 and accept when below 5q = 61445, the
/// variant the Round-3 KAT vectors use (not `hash_to_point_ct`).
fn hash_to_point(nonce: &[u8], message: &[u8], c0: &mut [u16; N]) {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    let mut hasher = Shake256::default();
    hasher.update(nonce);
    hasher.update(message);
    let mut xof = hasher.finalize_xof();

    let mut remaining = N;
    let mut idx = 0;

    while remaining > 0 {
        let mut buf = [0u8; 2];
        xof.read(&mut buf);

        let w = ((buf[0] as u32) << 8) | (buf[1] as u32);

        const ACCEPT_THRESHOLD: u32 = 5 * Q;
        if w < ACCEPT_THRESHOLD {
            // w < 5q, so four conditional subtractions reduce mod q. (A naive
            // `while w >= Q` loop gets compiled into a hardware division.)
            let mut v = w;
            v = field_sub(v, Q);
            v = field_sub(v, Q);
            v = field_sub(v, Q);
            v = field_sub(v, Q);
            debug_assert!(v < Q);
            c0[idx] = v as u16;
            idx += 1;
            remaining -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_short_zero() {
        let s1 = [0i16; N];
        let s2 = [0i16; N];
        assert!(is_short(&s1, &s2));
    }

    #[test]
    fn is_short_small() {
        let mut s1 = [0i16; N];
        let mut s2 = [0i16; N];
        for i in 0..N {
            s1[i] = ((i % 10) as i16) - 5;
            s2[i] = ((i % 10) as i16) - 5;
        }
        assert!(is_short(&s1, &s2));
    }

    #[test]
    fn is_short_rejects_overflow() {
        // True squared norm here is ~9x u32::MAX; the saturation must reject.
        let mut s1 = [0i16; N];
        let mut s2 = [0i16; N];
        for i in 0..N {
            s1[i] = 6144;
            s2[i] = -6144;
        }
        assert!(!is_short(&s1, &s2));
    }

    #[test]
    fn ct_format_rejected_by_size_gate() {
        // 809-byte CT-format input must fail the size gate, not reach a
        // decoder that does not exist.
        let pk = [9u8; PUBKEY_LEN];
        let mut sig = [0u8; 809];
        sig[0] = 0x59;
        assert!(!verify_512(&pk, b"", &sig));
    }
}
