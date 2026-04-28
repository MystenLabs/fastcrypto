// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// FIPS 205 Section 11.2.1 — SHA2-based tweakable hash functions for security category 1 (n=16).
///
/// F, H, T_l, and PRF all share the same core:
///   Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64-n) ‖ ADRSc ‖ M))
///
/// TODO: this only covers the n=16 SHA2 instantiation. Extend to cover:
///   - n ≥ 24 (SHA2-192/256): H and T_l switch to SHA-512 with 128-byte block
///     pad (toByte(0, 128-n)); F and PRF stay on SHA-256. See FIPS 205 §11.2.1.
///   - SLH-DSA-SHAKE-*: the SHAKE256-based construction from §11.2.2, which
///     replaces the whole family with a single XOF — no SHA-256/SHA-512 split,
///     no 64-n padding.
use digest::Digest;
use hkdf::hmac::{Hmac, Mac};
use sha2::Sha256;

use super::Adrs;

const SHA256_BLOCK: usize = 64;
const ZERO_PAD: [u8; SHA256_BLOCK] = [0u8; SHA256_BLOCK];

/// Core shared by F, H, T_l, and PRF:
///   Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64-n) ‖ ADRSc ‖ M))
pub fn tweakable_hash(pk_seed: &[u8], adrs: Adrs, m: &[u8]) -> Vec<u8> {
    let n = pk_seed.len();
    let adrs_c = adrs.compress();
    let mut hasher = Sha256::new();
    // TODO: the first block is fixed - so we can share its output across instantiations to optimize hash costs
    hasher.update(pk_seed);
    hasher.update(&ZERO_PAD[..SHA256_BLOCK - n]);
    hasher.update(adrs_c);
    hasher.update(m);
    hasher.finalize()[..n].to_vec()
}

/// FIPS 205 §11.2.1 — PRF_msg for SHA2, n≤24.
///   PRF_msg(sk_prf, opt_rand, M) = HMAC-SHA-256(sk_prf, opt_rand ‖ M)[0..n]
pub fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], msg: &[u8]) -> Vec<u8> {
    let n = sk_prf.len();
    let mut mac = <Hmac<Sha256>>::new_from_slice(sk_prf).expect("HMAC accepts any key length");
    mac.update(opt_rand);
    mac.update(msg);
    mac.finalize().into_bytes()[..n].to_vec()
}

/// FIPS 205 §11.2.1 — H_msg for SHA2, n≤24.
///   H_msg(R, pk_seed, pk_root, M) =
///     MGF1-SHA-256(R ‖ pk_seed ‖ SHA-256(R ‖ pk_seed ‖ pk_root ‖ M), out_len)
///
/// MGF1 (RFC 8017 B.2.1): iterated SHA-256 with a 4-byte big-endian counter appended to the seed.
pub fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], msg: &[u8], out_len: usize) -> Vec<u8> {
    let inner = {
        let mut h = Sha256::new();
        h.update(r);
        h.update(pk_seed);
        h.update(pk_root);
        h.update(msg);
        h.finalize()
    };

    let mgf_seed: Vec<u8> = [r, pk_seed, inner.as_slice()].concat();

    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 0;
    while out.len() < out_len {
        let mut h = Sha256::new();
        h.update(&mgf_seed);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(out_len);
    out
}
