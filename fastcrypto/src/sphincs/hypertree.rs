// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! SLH-DSA Hypertree implementation from FIPS-205
//!
//! A hypertree is `d` stacked XMSS trees. Layer 0's WOTS+ leaves sign the
//! message; each layer above signs the root of the layer below; the top
//! layer's root is the SLH-DSA public key root.

use crate::sphincs::xmss::{xmss_node, xmss_pk_from_sig, xmss_sign, XmssParams, XmssSignature};
use crate::sphincs::Adrs;

pub struct HypertreeParams {
    /// Number of layers of XMSS trees.
    pub d: u8,
    pub xmss: XmssParams,
    /// Total height of the hypertree (`h = d * h'`).
    pub h: u8,
}

impl HypertreeParams {
    pub fn new(d: u8, xmss: XmssParams) -> Self {
        // h' < 32 so that a leaf index fits in u32 (the type of idx_leaf in
        // the sign/verify API). FIPS 205 tops out at h' = 12 and SP 800-230
        // draft at h' = 22, so this is purely a sanity check.
        debug_assert!(xmss.h_prime < 32, "h_prime must be < 32");
        // h = d * h' ≤ 68 for every FIPS 205 / SP 800-230 param set, so fits in u8.
        let h = d
            .checked_mul(xmss.h_prime)
            .expect("h = d * h_prime overflowed u8");
        HypertreeParams { d, xmss, h }
    }
}

pub struct HypertreeSignature {
    /// One XMSS signature per layer; `xmss[0]` is the bottom layer.
    pub xmss: Vec<XmssSignature>,
}

impl HypertreeSignature {
    pub fn size_in_bytes(&self) -> usize {
        self.xmss.iter().map(|s| s.size_in_bytes()).sum()
    }
}

/// Consume the low `h_prime` bits of `idx_tree` as the next layer's `idx_leaf`,
/// and shift `idx_tree` down by `h_prime`.
fn advance_indices(idx_tree: &mut u64, idx_leaf: &mut u32, h_prime: u8) {
    *idx_leaf = (*idx_tree & ((1u64 << h_prime) - 1)) as u32;
    *idx_tree >>= h_prime;
}

/// Top-tree root (layer d-1, tree 0). This is the SLH-DSA public key root.
pub fn ht_pk_root(params: &HypertreeParams, sk_seed: &[u8], pk_seed: &[u8]) -> Vec<u8> {
    let adrs = Adrs::new().with_xmss_height(params.d - 1);
    xmss_node(&params.xmss, sk_seed, 0, params.xmss.h_prime, pk_seed, adrs)
}

/// Sign `msg` at the layer-0 leaf identified by `(idx_tree, idx_leaf)`:
/// - `idx_tree`: which XMSS tree at the current layer (upper `h - h'` bits of the global leaf index on entry to layer 0).
/// - `idx_leaf`: which WOTS+ leaf inside that XMSS tree (low `h'` bits).
pub fn ht_sign(
    params: &HypertreeParams,
    sk_seed: &[u8],
    pk_seed: &[u8],
    msg: &[u8],
    mut idx_tree: u64,
    mut idx_leaf: u32,
) -> HypertreeSignature {
    let h_prime = params.xmss.h_prime;
    let mut sigs = Vec::with_capacity(params.d as usize);
    let mut to_sign: Vec<u8> = msg.to_vec();

    for j in 0..params.d {
        let adrs = Adrs::new().with_xmss_height(j).with_xmss_index(idx_tree);
        let sig_j = xmss_sign(&params.xmss, sk_seed, &to_sign, idx_leaf, pk_seed, adrs);

        if j < params.d - 1 {
            // Next layer signs the root recovered from this layer's signature.
            to_sign = xmss_pk_from_sig(&params.xmss, idx_leaf, &sig_j, &to_sign, pk_seed, adrs);
            advance_indices(&mut idx_tree, &mut idx_leaf, h_prime);
        }
        sigs.push(sig_j);
    }
    HypertreeSignature { xmss: sigs }
}

/// Verify a hypertree signature. `(idx_tree, idx_leaf)` identifies the layer-0
/// leaf that was signed (same split as [`ht_sign`]).
pub fn ht_verify(
    params: &HypertreeParams,
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
    sig: &HypertreeSignature,
    mut idx_tree: u64,
    mut idx_leaf: u32,
) -> bool {
    if sig.xmss.len() != params.d as usize {
        return false;
    }
    let h_prime = params.xmss.h_prime;
    let mut node: Vec<u8> = msg.to_vec();

    for j in 0..params.d {
        let adrs = Adrs::new().with_xmss_height(j).with_xmss_index(idx_tree);
        node = xmss_pk_from_sig(
            &params.xmss,
            idx_leaf,
            &sig.xmss[j as usize],
            &node,
            pk_seed,
            adrs,
        );
        if j < params.d - 1 {
            advance_indices(&mut idx_tree, &mut idx_leaf, h_prime);
        }
    }
    node == pk_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphincs::params::{
        FipsParams, FIPS_128F, FIPS_128S, FIPS_192F, FIPS_192S, FIPS_256F, FIPS_256S,
    };
    use crate::sphincs::winternitz_ots::WotsParams;

    /// End-to-end roundtrip: keygen → sign → verify, plus negative checks and
    /// sig size formula `d · n · (len_wots + h')`.
    fn run_e2e(p: &FipsParams) {
        let params = HypertreeParams::new(
            p.d,
            XmssParams {
                h_prime: p.h_prime,
                wots: WotsParams::new(p.n, p.lg_w),
            },
        );
        let n = p.n as usize;
        let pk_seed: Vec<u8> = (0..n).map(|i| 0xA0u8.wrapping_add(i as u8)).collect();
        let sk_seed: Vec<u8> = (0..n).map(|i| 0x50u8.wrapping_add(i as u8)).collect();
        let msg: Vec<u8> = (0..n).map(|i| 0x10u8.wrapping_add(i as u8)).collect();

        let pk_root = ht_pk_root(&params, &sk_seed, &pk_seed);

        // Pick an idx somewhere below 2^h; split into (idx_tree, idx_leaf).
        let global_idx: u64 = if params.h >= 64 {
            u64::MAX / 3
        } else {
            ((1u64 << params.h) - 1) / 3
        };
        let idx_leaf = (global_idx & ((1u64 << p.h_prime) - 1)) as u32;
        let idx_tree = global_idx >> p.h_prime;

        let sig = ht_sign(&params, &sk_seed, &pk_seed, &msg, idx_tree, idx_leaf);
        assert!(
            ht_verify(&params, &pk_seed, &pk_root, &msg, &sig, idx_tree, idx_leaf),
            "[{}] verify must accept good signature",
            p.name,
        );

        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 1;
        assert!(
            !ht_verify(&params, &pk_seed, &pk_root, &bad_msg, &sig, idx_tree, idx_leaf),
            "[{}] verify must reject tampered msg",
            p.name,
        );

        let wrong_leaf = idx_leaf ^ 1;
        assert!(
            !ht_verify(&params, &pk_seed, &pk_root, &msg, &sig, idx_tree, wrong_leaf),
            "[{}] verify must reject wrong idx_leaf",
            p.name,
        );

        let num_elems = params.xmss.wots.num_elements() as usize;
        let per_xmss = n * (num_elems + p.h_prime as usize);
        assert_eq!(sig.size_in_bytes(), p.d as usize * per_xmss, "[{}]", p.name);
    }

    #[test]
    fn test_ht_128s() {
        run_e2e(&FIPS_128S);
    }
    #[test]
    fn test_ht_128f() {
        run_e2e(&FIPS_128F);
    }
    #[test]
    fn test_ht_192s() {
        run_e2e(&FIPS_192S);
    }
    #[test]
    fn test_ht_192f() {
        run_e2e(&FIPS_192F);
    }
    #[test]
    fn test_ht_256s() {
        run_e2e(&FIPS_256S);
    }
    #[test]
    fn test_ht_256f() {
        run_e2e(&FIPS_256F);
    }
}
