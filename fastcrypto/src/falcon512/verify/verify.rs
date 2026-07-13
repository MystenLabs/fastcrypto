// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Ported from the Falcon reference implementation via PQClean
// (crypto_sign/falcon-512/clean: vrfy.c, codec.c, common.c),
// Copyright (c) 2017-2019 Falcon Project, MIT license; the full
// notice is in this module's mod.rs.

//! Top-level Falcon-512 verification: the ported Montgomery core
//! ([`FalconVerifier`]) plus the two entry points the scheme uses.
//!
//! # Verification algorithm (Falcon spec §3.7, §3.11) #
//!
//! Given public key h, message m, and signature (nonce r, s2):
//! 1. challenge c = HashToPoint(r || m) over Z_q via SHAKE-256 rejection sampling;
//! 2. recover s1 = c − s2.h in R_q = Z_q[x]/(x^n + 1);
//! 3. accept iff ||(s1, s2)||^2 ≤ [`L2_BOUND`].

use super::ntt::{
    field_sub, ntt_forward, ntt_inverse, poly_pointwise_mul, poly_prepare_for_mul, poly_sub,
};
use super::{L2_BOUND, N, PUBKEY_LEN, Q, SECKEY_LEN, SIG_MAX_LEN, SIG_MIN_LEN, SIG_PADDED_LEN};

/// Verify a Falcon-512 signature (permissive / interop mode).
///
/// The header's low nibble must be `logn = 9`. The high nibble selects the
/// encoding family and **both `0x2X` and `0x3X` are accepted**, because real
/// signers disagree: the Round-3 KAT vectors and falcon.py emit `0x29` with a
/// variable-length compressed body, while PQClean emits `0x39` for the
/// 666-byte padded form. Canonicity is enforced on the decoded body, not the
/// nibble (see [`FalconVerifier::verify_512`]). Because both the compressed
/// and the padded encodings of the same underlying signature verify, the
/// scheme is EUF-CMA but not strongly non-malleable at the byte level: callers
/// needing a unique signature identifier must use [`verify_strict`].
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    FalconVerifier::verify_512(public_key, message, signature)
}

/// Verify a Falcon-512 signature in **strict canonical form** (authenticator /
/// consensus mode).
///
/// Accepts exactly one byte encoding per signature: the fixed
/// [`SIG_PADDED_LEN`]-byte (666) padded form — header byte exactly `0x39`
/// (padded family, logn = 9; the PQClean `falcon-padded-512` wire format),
/// 40-byte nonce, compressed s2 body, and an all-zero tail after the
/// compressed data ends. Everything [`verify`] rejects is also rejected here;
/// additionally the variable-length form and the `0x2X` header family fail.
///
/// # Why?
/// A transaction authenticator must not let two distinct byte-strings be valid
/// encodings of the same signature: anyone could then re-encode a signed
/// transaction in flight, changing its digest without the signer's consent
/// (tx-malleability). Restricting to one fixed-length encoding makes the map
/// signature-bytes -> accepted-signature injective, so the signature bytes can
/// safely be part of the transaction digest.
pub fn verify_strict(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != SIG_PADDED_LEN || signature[0] != 0x39 {
        return false;
    }
    FalconVerifier::verify_512(public_key, message, signature)
}

/// Structural public-key validation
pub fn validate_public_key(pk: &[u8]) -> bool {
    FalconVerifier::decode_pubkey(pk, &mut [0u16; N])
}

/// Validate a PQClean-format secret key against the public key stored
/// alongside it, without invoking the signer.
///
/// Layout (PQClean `crypto_sign/falcon-512/clean`): header `0x59`
/// (`0x50 + logn`), then f and g at 6 bits per coefficient and F at 8 bits
/// per coefficient, in the reference's trimmed two's-complement encoding.
///
/// Checks, in order:
/// 1. length, header byte, and per-polynomial structural decode (the
///    forbidden −2^(bits−1) value and non-zero trailing bits are rejected,
///    matching the reference `trim_i8_decode`);
/// 2. `pk` decodes canonically
/// 3. f is invertible in R_q (every NTT coefficient non-zero), and
///    h.f = g in R_q — the defining relation of a Falcon public key — so a
///    secret key spliced onto a different key's public half is rejected.
///
/// F is checked structurally only: G is not stored, and the integer NTRU
/// relation fG − gF = q cannot be confirmed in Z_q alone (any F satisfies it
/// mod q once G is derived from the congruence). A corrupted F that survives
/// the structural check cannot make a wrong signature verify; it surfaces at
/// signing time instead. Callers must not paper over that gap by
/// probe-signing: Falcon signers search for a short vector in a retry loop
/// and need not terminate when handed a degenerate basis.
pub fn validate_secret_key(sk: &[u8], pk: &[u8]) -> bool {
    // f and g pack to 512 . 6 / 8 bytes each, F to 512 . 8 / 8.
    const FG_BYTES: usize = N * 6 / 8;
    const F_START: usize = 1 + 2 * FG_BYTES;

    if sk.len() != SECKEY_LEN || sk[0] != 0x50 + 9 {
        return false;
    }
    let mut f = [0i8; N];
    let mut g = [0i8; N];
    let mut big_f = [0i8; N];
    if !trim_i8_decode(&sk[1..1 + FG_BYTES], 6, &mut f)
        || !trim_i8_decode(&sk[1 + FG_BYTES..F_START], 6, &mut g)
        || !trim_i8_decode(&sk[F_START..], 8, &mut big_f)
    {
        return false;
    }

    let mut h = [0u16; N];
    if !FalconVerifier::decode_pubkey(pk, &mut h) {
        return false;
    }

    // Lift f and g from signed coefficients into Z_q and transform.
    let mut fq = [0u16; N];
    let mut gq = [0u16; N];
    for i in 0..N {
        fq[i] = (f[i] as i32).rem_euclid(Q as i32) as u16;
        gq[i] = (g[i] as i32).rem_euclid(Q as i32) as u16;
    }
    ntt_forward(&mut fq);
    ntt_forward(&mut gq);
    if fq.contains(&0) {
        return false;
    }

    // h.f = g holds in R_q iff it holds pointwise in the NTT domain.
    // montgomery_mul(h.R, f) = h.f in natural form, directly comparable
    // against the natural-form NTT of g.
    poly_prepare_for_mul(&mut h);
    poly_pointwise_mul(&mut h, &fq);
    h == gq
}

/// Decode `N` trimmed two's-complement values of `bits` width (the reference
/// `trim_i8_decode`, MSB-first): rejects the forbidden −2^(bits−1) value and
/// non-zero padding bits in the final byte. `data` must hold exactly
/// `N . bits / 8` bytes (both widths used here are byte-aligned over N = 512).
fn trim_i8_decode(data: &[u8], bits: u32, out: &mut [i8; N]) -> bool {
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

/// Falcon-512 signature verifier (the vendored Montgomery-NTT core; see the
/// parent module docs for provenance).
///
/// This struct provides static methods for signature verification.
pub struct FalconVerifier;

impl FalconVerifier {
    /// Verifies a Falcon-512 signature.
    ///
    /// # Arguments
    /// * `pubkey` - 897-byte Falcon-512 public key
    /// * `message` - The message that was signed; must be ≤ `MAX_MESSAGE_LEN` bytes
    /// * `signature` - The signature bytes (compressed or padded format only)
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify_512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Step 1: Validate public key length and its header
        if pubkey.len() != PUBKEY_LEN {
            return false;
        }
        // Header byte encodes logn; for Falcon-512, logn = 9 (since n = 2^9 = 512)
        const FALCON_512_LOGN: u8 = 9;
        if pubkey[0] != FALCON_512_LOGN {
            return false;
        }

        // Step 2: Parse signature header and determine format
        let sig_len = signature.len();
        if sig_len < SIG_MIN_LEN || sig_len > SIG_MAX_LEN {
            return false;
        }
        let sig_header = signature[0];
        if (sig_header & 0x0F) != FALCON_512_LOGN {
            return false;
        }
        // The high nibble selects the encoding family. Real signers disagree
        // on which nibble means what: the NIST Round-3 KAT and falcon.py use
        // 0x2X for variable-length compressed signatures, while PQClean uses
        // 0x3X for the padded form. We therefore accept BOTH 0x2X and 0x3X
        // and do not bind the nibble to a particular body length; canonicity
        // is enforced on the decoded body instead (Step 5 below).
        //
        // 0x5X (CT, 809 bytes) is rejected here and, redundantly, by the size
        // gate above (809 > SIG_MAX_LEN = 666). Reference: Falcon NIST
        // Round-3 submission §3.11.1.
        let fmt = sig_header & 0xF0;
        if fmt != 0x20 && fmt != 0x30 {
            return false;
        }

        // Step 3: Decode public key polynomial h
        let mut h = [0u16; N];
        if !Self::decode_pubkey(pubkey, &mut h) {
            return false;
        }

        // Step 4: Extract nonce (bytes 1-40)
        let nonce = &signature[1..41];

        // Step 5: Decode signature polynomial s2
        let mut s2 = [0i16; N];
        let sig_data = &signature[41..];
        let decoded_len = Self::decode_sig_compressed(sig_data, &mut s2);
        if decoded_len == 0 {
            return false;
        }

        // Canonicity: the body must either decode exactly (natural
        // variable-length compressed) or be the fixed padded form whose TOTAL
        // signature length is SIG_PADDED_LEN (666 bytes) with an all-zero
        // tail. Any other zero-padded length is non-canonical and rejected,
        // so a signature cannot be silently inflated to an arbitrary size in
        // (natural, 666). This matches the reference's exact-consumption rule
        // and removes the unbounded-padding malleability while still
        // accepting every real signer (NIST KAT/falcon.py natural, PQClean
        // padded).
        let total_sig_len = signature.len(); // header(1) + nonce(40) + body
        let is_natural = decoded_len == sig_data.len();
        let is_padded = total_sig_len == SIG_PADDED_LEN;
        if !is_natural && !is_padded {
            return false;
        }
        // Trailing bytes (padded form only) must be zero.
        for i in decoded_len..sig_data.len() {
            if sig_data[i] != 0 {
                return false;
            }
        }

        // Step 6: Hash message to challenge polynomial c0
        let mut c0 = [0u16; N];
        Self::hash_to_point(nonce, message, &mut c0);

        // Step 7: Prepare public key and verify
        // Convert h to NTT domain and Montgomery form for efficient multiplication
        poly_prepare_for_mul(&mut h);

        Self::verify_raw_512(&c0, &s2, &h)
    }

    fn verify_raw_512(c0: &[u16; N], s2: &[i16; N], h: &[u16; N]) -> bool {
        let mut tt = [0u16; N];

        // Step 1: Convert s2 from signed to unsigned representation mod q
        for i in 0..N {
            let w = s2[i] as i32;
            let w = if w < 0 {
                (w + Q as i32) as u32
            } else {
                w as u32
            };
            tt[i] = w as u16;
        }

        // Step 2: Compute s2.h in the ring Z_q[X]/(X^n + 1)
        // Since h is already in NTT+Montgomery form, we only need to transform tt.
        ntt_forward(&mut tt);
        poly_pointwise_mul(&mut tt, h);
        ntt_inverse(&mut tt);

        // Step 3: Compute s1 = c0 - s2.h  (equivalently, -s1 = s2.h - c0).
        // ||s1|| = ||-s1||, so the sign flip does not affect the norm check below.
        poly_sub(&mut tt, c0);

        // Step 4: Convert -s1 back to signed representation for norm computation
        let mut s1 = [0i16; N];
        for i in 0..N {
            let w = tt[i] as i32;
            let w = if w > (Q as i32 / 2) { w - Q as i32 } else { w };
            s1[i] = w as i16;
        }

        // Step 5: Verify that the signature vector (s1, s2) is short enough
        Self::is_short(&s1, s2)
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

    /// Decodes a Falcon-512 public key from its packed binary format (14 bits per coefficient, MSB-first).
    pub fn decode_pubkey(pubkey: &[u8], h: &mut [u16; N]) -> bool {
        // Step1: check if the length and the flag match Falcon-512 parameters
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

    /// Decodes a signature from compressed format. Returns bytes consumed, or 0 on error.
    ///
    /// Per coefficient the bitstream carries: 1 sign bit, then the low 7 bits
    /// of the magnitude (MSB-first), then the high bits in unary. Rejections
    /// that matter for soundness: negative zero (non-canonical), an over-long
    /// unary run (magnitude > 2047), and non-zero padding bits in the final
    /// partial byte.
    fn decode_sig_compressed(data: &[u8], s2: &mut [i16; N]) -> usize {
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

    /// Hashes nonce || message to a challenge polynomial using SHAKE256 with
    /// rejection sampling: squeeze two bytes at a time as a big-endian 16-bit
    /// value and accept it (reduced mod q) when it is below 5q = 61445. This
    /// is the variant the Round-3 KAT vectors use (not `hash_to_point_ct`).
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
                // Reduce w mod q with bounded conditional subtractions: the
                // accept threshold guarantees w < 5q, so four suffice. (The
                // naive `while v >= Q { v -= Q; }` gets rewritten by LLVM
                // into a hardware division.)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_short_zero() {
        let s1 = [0i16; N];
        let s2 = [0i16; N];
        assert!(FalconVerifier::is_short(&s1, &s2));
    }

    #[test]
    fn is_short_small() {
        let mut s1 = [0i16; N];
        let mut s2 = [0i16; N];
        for i in 0..N {
            s1[i] = ((i % 10) as i16) - 5;
            s2[i] = ((i % 10) as i16) - 5;
        }
        assert!(FalconVerifier::is_short(&s1, &s2));
    }

    #[test]
    fn is_short_rejects_overflow() {
        // Fill with ±(q/2 - 1); true squared norm ≈ 1024 . 6144² ≈ 3.87.10¹⁰,
        // which is ~9× u32::MAX, and must be rejected.
        let mut s1 = [0i16; N];
        let mut s2 = [0i16; N];
        for i in 0..N {
            s1[i] = 6144;
            s2[i] = -6144;
        }
        assert!(
            !FalconVerifier::is_short(&s1, &s2),
            "must reject when true squared norm wraps u32"
        );
    }

    #[test]
    fn pubkey_decode_header() {
        let mut h = [0u16; N];
        let bad_pk = [8u8; PUBKEY_LEN];
        assert!(!FalconVerifier::decode_pubkey(&bad_pk, &mut h));
        let short_pk = [9u8; 100];
        assert!(!FalconVerifier::decode_pubkey(&short_pk, &mut h));
    }

    #[test]
    fn ct_format_rejected_by_size_gate() {
        // A 809-byte "signature" with the CT header nibble must be rejected
        // by the size gate, not silently accepted by a broken CT decoder.
        let pk = [9u8; PUBKEY_LEN];
        let mut sig = [0u8; 809];
        sig[0] = 0x59;
        assert!(!FalconVerifier::verify_512(&pk, b"", &sig));
    }
}
