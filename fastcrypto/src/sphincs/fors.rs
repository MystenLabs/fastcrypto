// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! FORS implementation from FIPS-205
//!
//! Every WOTS+ leaf at the bottom layer of the hypertree (layer=0) has a distinct FORS forest beneath it.
//! So callers must set:
//! - xmss height, xmss index & keypair address to that of the WOTS+ key
//! - type to FORS_TREE

use crate::sphincs::hash::tweakable_hash;
use crate::sphincs::merkle::{build_auth_path, compute_root_from_path, merkle_node};
use crate::sphincs::utils::{bits_to_base, bytes_to_bits};
use crate::sphincs::{Adrs, AdrsType};

pub struct ForsParams {
    pub k: u16, // number of trees in the FORS forest
    pub a: u16, // height of each tree; also equivalent to #bits a single FORS tree can sign
    pub t: u32, // t = 2^a
    pub n: u16,
}

pub type ForsNode = Vec<u8>;

pub type ForsSignature = Vec<ForsTreeSignature>; // k elements

pub struct ForsTreeSignature {
    pub sk: Vec<u8>,         // n bytes
    pub auth: Vec<ForsNode>, // a elements
}

impl ForsTreeSignature {
    pub fn size_in_bytes(&self) -> usize {
        self.sk.len() + self.auth.iter().map(|n| n.len()).sum::<usize>()
    }
}

impl ForsParams {
    pub fn new(k: u16, a: u16, n: u16) -> Self {
        let t = 2u32.pow(a as u32);
        ForsParams { k, a, t, n }
    }
}

fn fors_sk_gen(
    params: &ForsParams,
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: Adrs,
    idx: u32,
) -> Vec<u8> {
    assert!(idx < params.t * params.k as u32);

    tweakable_hash(
        pk_seed,
        adrs.with_type(AdrsType::ForsPrf)
            .with_key_pair_address(adrs.get_key_pair_address())
            .with_tree_index(idx),
        sk_seed,
    )
}

/// Build a FORS_TREE address at a given height/index. Assumes the caller's
/// `adrs` is already a FORS_TREE address with `kp` set — true at every entry
/// into this module (slh_dsa's `derive_fors_context` and the fors tests).
fn fors_tree_adrs(adrs: Adrs, height: impl Into<u32>, index: u32) -> Adrs {
    adrs.with_tree_height(height).with_tree_index(index)
}

/// F(sk) — the FORS leaf at forest-global index `idx`. Used by both the signer
/// (with sk derived from sk_seed) and the verifier (with sk from the signature).
fn fors_leaf(pk_seed: &[u8], adrs: Adrs, sk: &[u8], idx: u32) -> Vec<u8> {
    tweakable_hash(pk_seed, fors_tree_adrs(adrs, 0u32, idx), sk)
}

fn fors_node(
    params: &ForsParams,
    sk_seed: &[u8],
    i: u32,
    z: u16,
    pk_seed: &[u8],
    adrs: Adrs,
) -> ForsNode {
    assert!(z <= params.a);
    assert!(i < (params.k as u32) * 2u32.pow(u32::from(params.a - z)));

    let leaf_generator = |idx| {
        fors_leaf(
            pk_seed,
            adrs,
            &fors_sk_gen(params, sk_seed, pk_seed, adrs, idx),
            idx,
        )
    };
    let adrs_generator = |height, idx| fors_tree_adrs(adrs, height, idx);
    merkle_node(&leaf_generator, &adrs_generator, i, z, pk_seed)
}

/// Unpack `md` into `k` base-`a` digits per FIPS 205 Alg. 7. `md` is
/// `⌈k·a / 8⌉` bytes; any trailing padding bits are discarded.
fn md_to_indices(params: &ForsParams, md: &[u8]) -> Vec<u32> {
    let ka = (params.k as usize) * (params.a as usize);
    assert_eq!(md.len(), ka.div_ceil(8), "md must be ⌈k·a/8⌉ bytes");
    let bits = bytes_to_bits(md);
    let indices = bits_to_base(&bits[..ka], params.a);
    debug_assert_eq!(indices.len(), params.k as usize);
    indices
}

pub fn fors_sign(
    params: &ForsParams,
    md: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: Adrs,
) -> ForsSignature {
    assert_eq!(
        adrs.get_type(),
        AdrsType::ForsTree,
        "fors_sign expects a FORS_TREE ADRS"
    );
    let indices = md_to_indices(params, md);

    let mut fors_sign = Vec::with_capacity(params.k as usize);
    for i in 0..params.k as u32 {
        let fors_idx = i * params.t + indices[i as usize];
        let fors_tree_sk = fors_sk_gen(params, sk_seed, pk_seed, adrs, fors_idx);
        // Indices are contiguous across the forest, so shift tree i's local sibling
        // index into the global forest-wide index space at each height.
        let node_at = |height, sib| {
            let shift = i * 2u32.pow(u32::from(params.a - height));
            fors_node(params, sk_seed, shift + sib, height, pk_seed, adrs)
        };
        let auth = build_auth_path(params.a, indices[i as usize], node_at);
        fors_sign.push(ForsTreeSignature {
            sk: fors_tree_sk,
            auth,
        });
    }

    fors_sign
}

pub fn fors_pk_from_sig(
    params: &ForsParams,
    sig: &ForsSignature,
    md: &[u8],
    pk_seed: &[u8],
    adrs: Adrs,
) -> Vec<u8> {
    assert_eq!(
        adrs.get_type(),
        AdrsType::ForsTree,
        "fors_pk_from_sig expects a FORS_TREE ADRS"
    );
    assert_eq!(sig.len(), params.k as usize);
    let indices = md_to_indices(params, md);

    let mut roots = Vec::with_capacity(params.k as usize);
    let adrs_generator = |height, idx| fors_tree_adrs(adrs, height, idx);
    for i in 0..params.k as u32 {
        let tree_sig = &sig[i as usize];
        assert_eq!(tree_sig.auth.len(), params.a as usize);

        let leaf_idx = i * params.t + indices[i as usize];
        let leaf = fors_leaf(pk_seed, adrs, &tree_sig.sk, leaf_idx);
        let root = compute_root_from_path(leaf, leaf_idx, &tree_sig.auth, pk_seed, adrs_generator);
        roots.push(root);
    }

    compress_roots(&roots.concat(), pk_seed, adrs)
}

fn compress_roots(all_roots: &[u8], pk_seed: &[u8], adrs: Adrs) -> Vec<u8> {
    tweakable_hash(
        pk_seed,
        adrs.with_type(AdrsType::ForsRoots)
            .with_key_pair_address(adrs.get_key_pair_address()),
        all_roots,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compute the FORS public key from sk_seed by hashing the k tree roots — mirrors
    /// what a signer would publish, independent of fors_sign/fors_pk_from_sig.
    fn fors_pk_gen(params: &ForsParams, sk_seed: &[u8], pk_seed: &[u8], adrs: Adrs) -> Vec<u8> {
        let roots: Vec<u8> = (0..params.k as u32)
            .flat_map(|i| fors_node(params, sk_seed, i, params.a, pk_seed, adrs))
            .collect();
        compress_roots(&roots, pk_seed, adrs)
    }

    use crate::sphincs::params::{
        FipsParams, FIPS_128F, FIPS_128S, FIPS_192F, FIPS_192S, FIPS_256F, FIPS_256S,
    };

    /// End-to-end roundtrip: keygen → sign → verify, plus a tampered-md negative
    /// check and sig size formula `k · (1 + a) · n`.
    fn run_e2e(p: &FipsParams) {
        let params = ForsParams::new(p.k, p.a, p.n);
        let n = p.n as usize;
        let pk_seed: Vec<u8> = (0..n).map(|i| 0xA0u8.wrapping_add(i as u8)).collect();
        let sk_seed: Vec<u8> = (0..n).map(|i| 0x50u8.wrapping_add(i as u8)).collect();
        let adrs = Adrs::new()
            .with_type(AdrsType::ForsTree)
            .with_key_pair_address(7u32);

        // md: ⌈k·a/8⌉ bytes of arbitrary content.
        let md_len = ((p.k as usize) * (p.a as usize)).div_ceil(8);
        let md: Vec<u8> = (0..md_len).map(|i| 0x5Au8.wrapping_add(i as u8)).collect();

        let pk = fors_pk_gen(&params, &sk_seed, &pk_seed, adrs);
        let sig = fors_sign(&params, &md, &sk_seed, &pk_seed, adrs);
        let recovered = fors_pk_from_sig(&params, &sig, &md, &pk_seed, adrs);
        assert_eq!(pk, recovered, "[{}] recovered pk must match", p.name);

        let mut wrong = md;
        wrong[0] ^= 1;
        let wrong_pk = fors_pk_from_sig(&params, &sig, &wrong, &pk_seed, adrs);
        assert_ne!(pk, wrong_pk, "[{}] wrong md must not recover pk", p.name);

        let sig_size: usize = sig.iter().map(|t| t.size_in_bytes()).sum();
        assert_eq!(
            sig_size,
            (p.k as usize) * (1 + p.a as usize) * n,
            "[{}]",
            p.name
        );
    }

    #[test]
    fn test_fors_128s() {
        run_e2e(&FIPS_128S);
    }
    #[test]
    fn test_fors_128f() {
        run_e2e(&FIPS_128F);
    }
    #[test]
    fn test_fors_192s() {
        run_e2e(&FIPS_192S);
    }
    #[test]
    fn test_fors_192f() {
        run_e2e(&FIPS_192F);
    }
    #[test]
    fn test_fors_256s() {
        run_e2e(&FIPS_256S);
    }
    #[test]
    fn test_fors_256f() {
        run_e2e(&FIPS_256F);
    }
}
