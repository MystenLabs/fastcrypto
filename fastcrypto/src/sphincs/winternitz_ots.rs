// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WOTS+ implementation from FIPS-205.
//!
//! Most functions in this file take an Address as input. Callers must ensure it encodes:
//!     (i) the XMSS tree's address (layer & tree), and
//!     (ii) the WOTS+ keypair address within the XMSS tree.

use crate::sphincs::hash::tweakable_hash;
use crate::sphincs::{Adrs, AdrsType};

// ------------------------------------------------------------------
//                            Parameters
// ------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct WotsParams {
    pub n: u16,    // hash output length in bytes (spec: {16, 24, 32})
    pub lg_w: u16, // bits per winternitz digit (spec: 1..=8)
    w: u16,        // hash chain length = 2^lg_w
}

impl WotsParams {
    pub fn new(n: u16, lg_w: u16) -> Self {
        assert!((1..=8).contains(&lg_w), "lg_w must be in 1..=8");
        assert_eq!(
            (8 * n) % lg_w,
            0,
            "total #bits is a multiple of #bits per winternitz chain"
        );
        let w = 1u16 << lg_w;
        WotsParams { n, lg_w, w }
    }

    fn num_digits(msg_len_in_bits: u16, num_bits_per_digit: u16) -> u16 {
        msg_len_in_bits.div_ceil(num_bits_per_digit)
    }

    // len_1
    pub fn num_msg_digits(&self) -> u16 {
        Self::num_digits(self.n * 8, self.lg_w)
    }

    pub fn max_checksum(&self) -> u16 {
        (self.w - 1) * self.num_msg_digits()
    }

    // len_2
    pub fn num_checksum_digits(&self) -> u16 {
        self.max_checksum().ilog(self.w) as u16 + 1
    }

    pub fn num_elements(&self) -> u16 {
        self.num_msg_digits() + self.num_checksum_digits()
    }
}

// ------------------------------------------------------------------
//            Message encoding (base-w digits + checksum)
// ------------------------------------------------------------------

fn to_bits(msg: &[u8]) -> Vec<u8> {
    let mut msg_bits = Vec::with_capacity(msg.len() * 8);
    for &x in msg {
        for j in 0..8 {
            msg_bits.push((x >> (7 - j)) & 1);
        }
    }
    msg_bits
}

fn convert_base(msg: &[u8], lg_b: u16) -> Vec<u8> {
    let msg_bits = to_bits(msg);
    // chunking is guaranteed to be exact because WotsParams::new() enforces (8 * n) % lg_w = 0
    let mut result = Vec::with_capacity(msg_bits.len() / lg_b as usize);
    for chunk in msg_bits.chunks(lg_b as usize) {
        // acc < 2^lg_b by construction; WotsParams::new() enforces lg_b ≤ 8, so acc fits in u8.
        let mut acc: u8 = 0;
        for &bit in chunk {
            acc = (acc << 1) | bit;
        }
        result.push(acc);
    }
    result
}

fn encode_message(params: &WotsParams, msg: &[u8]) -> Vec<u8> {
    assert_eq!(
        msg.len(),
        params.n as usize,
        "msg length doesn't match params"
    );
    let mut msg_digits = convert_base(msg, params.lg_w);
    let sum: u16 = msg_digits.iter().map(|&d| d as u16).sum();
    let checksum = params.max_checksum() - sum;
    let mask = params.w - 1;
    let checksum_digits = (0..params.num_checksum_digits())
        .rev()
        .map(|i| ((checksum >> (i * params.lg_w)) & mask) as u8)
        .collect::<Vec<_>>();
    msg_digits.extend_from_slice(&checksum_digits);
    assert_eq!(msg_digits.len(), params.num_elements() as usize);
    msg_digits
}

// ------------------------------------------------------------------
//                          Address helper
// ------------------------------------------------------------------

/// Derive a WOTS+ sub-address from the caller's WOTS+ address by swapping the
/// type while preserving the key-pair address. FIPS 205's `setType` zeros
/// words 5-7, which wipes the key-pair address too — every WOTS+ sub-address
/// (PRF for sk derivation, PK for compression) wants it restored.
fn wots_sub_adrs(adrs: Adrs, t: AdrsType) -> Adrs {
    adrs.with_type(t)
        .with_key_pair_address(adrs.get_key_pair_address())
}

// ------------------------------------------------------------------
//             Chain primitives (FIPS 205 Algorithm 5)
// ------------------------------------------------------------------

fn chain(input: &[u8], i: u16, s: u16, pk_seed: &[u8], adrs: Adrs) -> Vec<u8> {
    let mut tmp = input.to_vec();
    for j in i..(i + s) {
        tmp = tweakable_hash(pk_seed, adrs.with_hash_address(j), &tmp);
    }
    tmp
}

/// Advance each per-element input along its WOTS+ chain from `start(i)` to
/// `end(i)` and collect the results. Used by `wots_pk_gen` (0 → w-1),
/// `wots_sign` (0 → msg_digit), and `wots_pk_from_sig` (msg_digit → w-1).
/// Coerces `adrs` to WOTS_HASH type internally, so callers may pass any type.
fn chain_all(
    params: &WotsParams,
    pk_seed: &[u8],
    adrs: Adrs,
    inputs: &[Vec<u8>],
    range: impl Fn(usize) -> (u16, u16),
) -> Vec<Vec<u8>> {
    let adrs = wots_sub_adrs(adrs, AdrsType::WotsHash);
    (0..params.num_elements() as usize)
        .map(|i| {
            let (start, end) = range(i);
            chain(
                &inputs[i],
                start,
                end - start,
                pk_seed,
                adrs.with_chain_address(i as u32),
            )
        })
        .collect()
}

// ------------------------------------------------------------------
//           Secret-key derivation & chain-PK compression
// ------------------------------------------------------------------

/// Derive all `num_elements` WOTS+ secret keys for this key-pair.
/// Each sk[i] = PRF(pk_seed, WOTS_PRF_ADRS(kp, chain=i), sk_seed).
fn gen_sks(params: &WotsParams, sk_seed: &[u8], pk_seed: &[u8], adrs: Adrs) -> Vec<Vec<u8>> {
    let sk_adrs = wots_sub_adrs(adrs, AdrsType::WotsPrf);
    (0..params.num_elements())
        .map(|i| tweakable_hash(pk_seed, sk_adrs.with_chain_address(i), sk_seed))
        .collect()
}

fn compress_chain_pks(pks: Vec<Vec<u8>>, pk_seed: &[u8], adrs: Adrs) -> Vec<u8> {
    let wots_pk_adrs = wots_sub_adrs(adrs, AdrsType::WotsPk);
    tweakable_hash(pk_seed, wots_pk_adrs, &pks.concat())
}

// ------------------------------------------------------------------
//             Public API (FIPS 205 Algorithms 6, 7, 8)
// ------------------------------------------------------------------

pub fn wots_pk_gen(params: &WotsParams, sk_seed: &[u8], pk_seed: &[u8], adrs: Adrs) -> Vec<u8> {
    let sks = gen_sks(params, sk_seed, pk_seed, adrs);
    let chain_pks = chain_all(params, pk_seed, adrs, &sks, |_| (0, params.w - 1));
    compress_chain_pks(chain_pks, pk_seed, adrs)
}

pub fn wots_sign(
    params: &WotsParams,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: Adrs,
    msg: &[u8],
) -> Vec<Vec<u8>> {
    let msg_digits = encode_message(params, msg);
    let sks = gen_sks(params, sk_seed, pk_seed, adrs);
    chain_all(params, pk_seed, adrs, &sks, |i| (0, msg_digits[i] as u16))
}

pub fn wots_pk_from_sig(
    params: &WotsParams,
    sig: &[Vec<u8>],
    msg: &[u8],
    pk_seed: &[u8],
    adrs: Adrs,
) -> Vec<u8> {
    assert_eq!(
        sig.len(),
        params.num_elements() as usize,
        "sig length doesn't match params"
    );
    let msg_digits = encode_message(params, msg);
    let pks = chain_all(params, pk_seed, adrs, sig, |i| {
        (msg_digits[i] as u16, params.w - 1)
    });
    compress_chain_pks(pks, pk_seed, adrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params() {
        for n in [16u16, 24, 32] {
            let sphincs_params = WotsParams::new(n, 4);
            assert_eq!(sphincs_params.num_msg_digits(), 2 * n);
            assert_eq!(sphincs_params.num_checksum_digits(), 3);
            assert_eq!(sphincs_params.num_elements(), 2 * n + 3);
        }
    }

    #[test]
    fn test_convert_base_nibbles() {
        assert_eq!(convert_base(&[0xA3], 4), vec![0xA, 0x3]);
        assert_eq!(convert_base(&[0xA3, 0xF0], 4), vec![0xA, 0x3, 0xF, 0x0]);
    }

    #[test]
    fn test_convert_base_pairs() {
        // lg_b = 2 → 0xA3 = 10 10 00 11 → [2, 2, 0, 3]
        assert_eq!(convert_base(&[0xA3], 2), vec![2, 2, 0, 3]);
    }

    #[test]
    fn test_convert_base_single_bits() {
        assert_eq!(convert_base(&[0xA3], 1), vec![1, 0, 1, 0, 0, 0, 1, 1]);
    }

    /// Runs keygen → sign → verify and a wrong-message negative check for the given WOTS+ config.
    fn run_e2e(n: u16, lg_w: u16) {
        let params = WotsParams::new(n, lg_w);
        let n = n as usize;
        let pk_seed: Vec<u8> = (0..n).map(|i| 0xA0u8.wrapping_add(i as u8)).collect();
        let sk_seed: Vec<u8> = (0..n).map(|i| 0x50u8.wrapping_add(i as u8)).collect();
        let msg: Vec<u8> = (0..n).map(|i| 0x10u8.wrapping_add(i as u8)).collect();
        let adrs = Adrs::new();

        let pk = wots_pk_gen(&params, &sk_seed, &pk_seed, adrs);
        let sig = wots_sign(&params, &sk_seed, &pk_seed, adrs, &msg);
        let pk_recovered = wots_pk_from_sig(&params, &sig, &msg, &pk_seed, adrs);
        assert_eq!(pk, pk_recovered, "verify must recover same pk");

        let mut wrong_msg = msg.clone();
        wrong_msg[0] ^= 1;
        let pk_wrong = wots_pk_from_sig(&params, &sig, &wrong_msg, &pk_seed, adrs);
        assert_ne!(pk, pk_wrong, "wrong msg must not recover same pk");
    }

    // FIPS 205 (approved). All sets fix lg_w=4; n varies across security cats 1, 3, 5.

    #[test]
    fn test_wots_e2e_n16_lgw4() {
        run_e2e(16, 4);
    }

    #[test]
    fn test_wots_e2e_n24_lgw4() {
        run_e2e(24, 4);
    }

    #[test]
    fn test_wots_e2e_n32_lgw4() {
        run_e2e(32, 4);
    }

    // SP 800-230 IPD (draft, 2^24-sig-limit sets). lg_w varies: {2, 3}.

    #[test]
    fn test_wots_e2e_n16_lgw2() {
        run_e2e(16, 2);
    }

    #[test]
    fn test_wots_e2e_n24_lgw3() {
        run_e2e(24, 3);
    }

    #[test]
    fn test_wots_e2e_n32_lgw2() {
        run_e2e(32, 2);
    }
}
