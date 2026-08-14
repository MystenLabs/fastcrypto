// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! XMSS implementation from FIPS-205
//!
//! Callers must ensure that the address input encodes XMSS tree address (layer & tree).

use crate::sphincs::merkle::{build_auth_path, compute_root_from_path, merkle_node};
use crate::sphincs::winternitz_ots::{
    wots_pk_from_sig, wots_pk_gen, wots_sign, WotsParams, WotsSignature,
};
use crate::sphincs::{Adrs, AdrsType};

// ------------------------------------------------------------------
//                            Parameters
// ------------------------------------------------------------------

pub struct XmssParams {
    /// Height of the XMSS tree (`h'`). An XMSS tree contains `2^h'` WOTS+
    /// instances and can therefore sign `2^h'` messages.
    pub h_prime: u8,
    pub wots: WotsParams,
}

pub type XmssNode = Vec<u8>;

pub struct XmssSignature {
    pub wots: WotsSignature,
    pub auth: Vec<XmssNode>,
}

impl XmssSignature {
    pub fn size_in_bytes(&self) -> usize {
        self.wots.size_in_bytes() + self.auth.iter().map(|n| n.len()).sum::<usize>()
    }
}

// ------------------------------------------------------------------
//                             Helpers
// ------------------------------------------------------------------

/// Build a Tree ADRS for a node at `height` and `index` inside an XMSS tree.
/// Sets `type = Tree` (which zeros kp, as Tree ADRS has no kp).
fn xmss_tree_adrs(adrs: Adrs, height: impl Into<u32>, index: u32) -> Adrs {
    adrs.with_type(AdrsType::Tree)
        .with_tree_height(height)
        .with_tree_index(index)
}

/// Compute the XMSS subtree node at height `z` and index `i` (within that height).
pub fn xmss_node(
    params: &XmssParams,
    sk_seed: &[u8],
    i: u32,
    z: u8,
    pk_seed: &[u8],
    adrs: Adrs,
) -> XmssNode {
    assert!(z <= params.h_prime);
    assert!(i < 2u32.pow(u32::from(params.h_prime - z)));

    let leaf_generator = |idx| {
        wots_pk_gen(
            &params.wots,
            sk_seed,
            pk_seed,
            adrs.with_key_pair_address(idx),
        )
    };
    let adrs_generator = |height, idx| xmss_tree_adrs(adrs, height, idx);
    merkle_node(&leaf_generator, &adrs_generator, i, u16::from(z), pk_seed)
}

// ------------------------------------------------------------------
//                          Public API
// ------------------------------------------------------------------

pub fn xmss_sign(
    params: &XmssParams,
    sk_seed: &[u8],
    msg: &[u8],
    wots_idx: u32,
    pk_seed: &[u8],
    adrs: Adrs,
) -> XmssSignature {
    let node_at = |height, sib| xmss_node(params, sk_seed, sib, height as u8, pk_seed, adrs);
    let auth = build_auth_path(u16::from(params.h_prime), wots_idx, node_at);

    XmssSignature {
        wots: wots_sign(
            &params.wots,
            sk_seed,
            pk_seed,
            adrs.with_key_pair_address(wots_idx),
            msg,
        ),
        auth,
    }
}

pub fn xmss_pk_from_sig(
    params: &XmssParams,
    idx: u32,
    sig: &XmssSignature,
    msg: &[u8],
    pk_seed: &[u8],
    adrs: Adrs,
) -> Vec<u8> {
    let leaf = wots_pk_from_sig(
        &params.wots,
        &sig.wots,
        msg,
        pk_seed,
        adrs.with_key_pair_address(idx),
    );
    let adrs_generator = |height, parent_idx| xmss_tree_adrs(adrs, height, parent_idx);
    compute_root_from_path(leaf, idx, &sig.auth, pk_seed, adrs_generator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphincs::params::{
        FipsParams, FIPS_128F, FIPS_128S, FIPS_192F, FIPS_192S, FIPS_256F, FIPS_256S,
    };

    /// Sign → verify → tampered-msg rejection; assert sig size formula `n · (len_wots + h')`.
    fn run_e2e(p: &FipsParams) {
        let params = XmssParams {
            h_prime: p.h_prime,
            wots: WotsParams::new(p.n, p.lg_w),
        };
        let n = p.n as usize;
        let pk_seed: Vec<u8> = (0..n).map(|i| 0xA0u8.wrapping_add(i as u8)).collect();
        let sk_seed: Vec<u8> = (0..n).map(|i| 0x50u8.wrapping_add(i as u8)).collect();
        let msg: Vec<u8> = (0..n).map(|i| 0x10u8.wrapping_add(i as u8)).collect();
        let leaf: u32 = 5 % (1u32 << p.h_prime);
        let adrs = Adrs::new();

        let root = xmss_node(&params, &sk_seed, 0, p.h_prime, &pk_seed, adrs);
        let sig = xmss_sign(&params, &sk_seed, &msg, leaf, &pk_seed, adrs);

        let recovered = xmss_pk_from_sig(&params, leaf, &sig, &msg, &pk_seed, adrs);
        assert_eq!(
            recovered, root,
            "[{}] recovered root must equal computed root",
            p.name
        );

        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 1;
        let bad_root = xmss_pk_from_sig(&params, leaf, &sig, &bad_msg, &pk_seed, adrs);
        assert_ne!(
            bad_root, root,
            "[{}] tampered msg must not recover root",
            p.name
        );

        let num_elems = params.wots.num_elements() as usize;
        assert_eq!(
            sig.size_in_bytes(),
            n * (num_elems + p.h_prime as usize),
            "[{}]",
            p.name
        );
    }

    #[test]
    fn test_xmss_128s() {
        run_e2e(&FIPS_128S);
    }
    #[test]
    fn test_xmss_128f() {
        run_e2e(&FIPS_128F);
    }
    #[test]
    fn test_xmss_192s() {
        run_e2e(&FIPS_192S);
    }
    #[test]
    fn test_xmss_192f() {
        run_e2e(&FIPS_192F);
    }
    #[test]
    fn test_xmss_256s() {
        run_e2e(&FIPS_256S);
    }
    #[test]
    fn test_xmss_256f() {
        run_e2e(&FIPS_256F);
    }
}
