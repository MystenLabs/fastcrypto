// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::sphincs::fors::{
    fors_pk_from_sig, fors_sign, ForsParams, ForsSignature, ForsTreeSignature,
};
use crate::sphincs::hash::{h_msg, prf_msg};
use crate::sphincs::hypertree::{
    ht_pk_root, ht_sign, ht_verify, HypertreeParams, HypertreeSignature,
};
use crate::sphincs::params::{
    FipsParams, FIPS_128F, FIPS_128S, FIPS_192F, FIPS_192S, FIPS_256F, FIPS_256S,
};
use crate::sphincs::winternitz_ots::{WotsParams, WotsSignature};
use crate::sphincs::xmss::{XmssParams, XmssSignature};
use crate::sphincs::{Adrs, AdrsType};

/// Combined parameter set for SLH-DSA
pub struct SlhDsaParams {
    pub fors: ForsParams,
    pub hypertree: HypertreeParams,
    /// Hash output length in bytes (n).
    pub n: usize,
}

impl SlhDsaParams {
    /// Build an SLH-DSA parameter set in FIPS 205 notation.
    ///
    /// - `n`     : hash output length in bytes
    /// - `h`     : total hypertree height (must be `d * h_prime`)
    /// - `d`     : number of hypertree layers
    /// - `h_prime`: per-XMSS height (h/d)
    /// - `a`     : FORS tree height (bits per FORS tree)
    /// - `k`     : number of FORS trees
    /// - `lg_w`  : bits per WOTS+ digit
    pub fn new(n: usize, h: u8, d: u8, h_prime: u8, a: u16, k: u16, lg_w: u16) -> Self {
        assert_eq!(
            h,
            d.checked_mul(h_prime).expect("h = d * h_prime overflowed")
        );
        let hypertree = HypertreeParams::new(
            d,
            XmssParams {
                h_prime,
                wots: WotsParams::new(n as u16, lg_w),
            },
        );
        let fors = ForsParams::new(k, a, n as u16);
        SlhDsaParams { fors, hypertree, n }
    }

    /// Build from a [`FipsParams`] table entry.
    fn from_fips(p: &FipsParams) -> Self {
        Self::new(p.n as usize, p.h, p.d, p.h_prime, p.a, p.k, p.lg_w)
    }

    pub fn sha2_128s() -> Self {
        Self::from_fips(&FIPS_128S)
    }
    pub fn sha2_128f() -> Self {
        Self::from_fips(&FIPS_128F)
    }
    pub fn sha2_192s() -> Self {
        Self::from_fips(&FIPS_192S)
    }
    pub fn sha2_192f() -> Self {
        Self::from_fips(&FIPS_192F)
    }
    pub fn sha2_256s() -> Self {
        Self::from_fips(&FIPS_256S)
    }
    pub fn sha2_256f() -> Self {
        Self::from_fips(&FIPS_256F)
    }

    /// SLH-DSA-SHA2-128-24 (SP 800-230 IPD, 2^24 sig limit):
    /// n=16, h=22, d=1, h'=22, a=24, k=6, lg_w=2.
    pub fn sha2_128_24() -> Self {
        Self::new(16, 22, 1, 22, 24, 6, 2)
    }
}

pub struct SlhDsaPublicKey {
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
}

pub struct SlhDsaSecretKey {
    pub sk_seed: Vec<u8>,
    pub sk_prf: Vec<u8>,
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
}

pub struct SlhDsaSignature {
    pub r: Vec<u8>,
    pub fors_sig: ForsSignature,
    pub ht_sig: HypertreeSignature,
}

// ---- byte serialization (FIPS 205 §9.1) ----

impl SlhDsaPublicKey {
    /// Concatenated encoding `pk_seed ‖ pk_root` (2n bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.pk_seed.as_slice(), self.pk_root.as_slice()].concat()
    }

    pub fn from_bytes(params: &SlhDsaParams, bytes: &[u8]) -> FastCryptoResult<Self> {
        if bytes.len() != 2 * params.n {
            return Err(FastCryptoError::InputLengthWrong(2 * params.n));
        }
        Ok(Self {
            pk_seed: bytes[..params.n].to_vec(),
            pk_root: bytes[params.n..].to_vec(),
        })
    }
}

impl SlhDsaSecretKey {
    /// Concatenated encoding `sk_seed ‖ sk_prf ‖ pk_seed ‖ pk_root` (4n bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.sk_seed.as_slice(),
            self.sk_prf.as_slice(),
            self.pk_seed.as_slice(),
            self.pk_root.as_slice(),
        ]
        .concat()
    }

    pub fn from_bytes(params: &SlhDsaParams, bytes: &[u8]) -> FastCryptoResult<Self> {
        let n = params.n;
        if bytes.len() != 4 * n {
            return Err(FastCryptoError::InputLengthWrong(4 * n));
        }
        Ok(Self {
            sk_seed: bytes[..n].to_vec(),
            sk_prf: bytes[n..2 * n].to_vec(),
            pk_seed: bytes[2 * n..3 * n].to_vec(),
            pk_root: bytes[3 * n..].to_vec(),
        })
    }
}

impl SlhDsaSignature {
    /// Expected signature length: `(1 + k·(1 + a) + h + d·len_wots) · n` bytes.
    pub fn expected_len(params: &SlhDsaParams) -> usize {
        let n = params.n;
        let k = params.fors.k as usize;
        let a = params.fors.a as usize;
        let h = params.hypertree.h as usize;
        let d = params.hypertree.d as usize;
        let len_wots = params.hypertree.xmss.wots.num_elements() as usize;
        (1 + k * (1 + a) + h + d * len_wots) * n
    }

    /// Serialize as `R ‖ SIG_FORS ‖ SIG_HT` per FIPS 205 §9.1.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.r);
        for tree in &self.fors_sig {
            out.extend_from_slice(&tree.sk);
            for node in &tree.auth {
                out.extend_from_slice(node);
            }
        }
        for xmss_sig in &self.ht_sig.xmss {
            for chain in xmss_sig.wots.as_slice() {
                out.extend_from_slice(chain);
            }
            for node in &xmss_sig.auth {
                out.extend_from_slice(node);
            }
        }
        out
    }

    pub fn from_bytes(params: &SlhDsaParams, bytes: &[u8]) -> FastCryptoResult<Self> {
        let expected = Self::expected_len(params);
        if bytes.len() != expected {
            return Err(FastCryptoError::InputLengthWrong(expected));
        }
        let n = params.n;
        let k = params.fors.k as usize;
        let a = params.fors.a as usize;
        let h_prime = params.hypertree.xmss.h_prime as usize;
        let d = params.hypertree.d as usize;
        let len_wots = params.hypertree.xmss.wots.num_elements() as usize;

        let mut off = 0;
        let take = |len: usize, off: &mut usize| {
            let v = bytes[*off..*off + len].to_vec();
            *off += len;
            v
        };

        let r = take(n, &mut off);

        let mut fors_sig = Vec::with_capacity(k);
        for _ in 0..k {
            let sk = take(n, &mut off);
            let auth = (0..a).map(|_| take(n, &mut off)).collect();
            fors_sig.push(ForsTreeSignature { sk, auth });
        }

        let mut xmss_sigs = Vec::with_capacity(d);
        for _ in 0..d {
            let chains: Vec<Vec<u8>> = (0..len_wots).map(|_| take(n, &mut off)).collect();
            let auth = (0..h_prime).map(|_| take(n, &mut off)).collect();
            xmss_sigs.push(XmssSignature {
                wots: WotsSignature::from_chains(chains),
                auth,
            });
        }
        let ht_sig = HypertreeSignature { xmss: xmss_sigs };

        debug_assert_eq!(off, bytes.len());
        Ok(Self {
            r,
            fors_sig,
            ht_sig,
        })
    }
}

/// FIPS 205 Alg. 18 — SLH-DSA key generation.
///
/// Deterministic: caller supplies all three n-byte seeds.
pub fn slh_keygen(
    params: &SlhDsaParams,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> (SlhDsaPublicKey, SlhDsaSecretKey) {
    let pk_root = ht_pk_root(&params.hypertree, sk_seed, pk_seed);
    let pk = SlhDsaPublicKey {
        pk_seed: pk_seed.to_vec(),
        pk_root: pk_root.clone(),
    };
    let sk = SlhDsaSecretKey {
        sk_seed: sk_seed.to_vec(),
        sk_prf: sk_prf.to_vec(),
        pk_seed: pk_seed.to_vec(),
        pk_root,
    };
    (pk, sk)
}

/// Message-dependent context shared by sign and verify: derive `digest = H_msg(R, pk_seed, pk_root, M)`,
/// split it into `(md, idx_tree, idx_leaf)`, and build the FORS_TREE ADRS for that leaf.
fn derive_fors_context(
    params: &SlhDsaParams,
    r: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    msg: &[u8],
) -> (Vec<u8>, u64, u32, Adrs) {
    let digest = h_msg(r, pk_seed, pk_root, msg, digest_len(params));
    let (md, idx_tree, idx_leaf) = parse_digest(params, &digest);
    let adrs = Adrs::new()
        .with_xmss_height(0u32)
        .with_xmss_index(idx_tree)
        .with_type(AdrsType::ForsTree)
        .with_key_pair_address(idx_leaf);
    (md, idx_tree, idx_leaf, adrs)
}

/// FIPS 205 Alg. 19 — SLH-DSA signing (internal).
///
/// `addrnd`: optional randomizer; if `None` the deterministic variant uses `pk_seed`.
pub fn slh_sign(
    params: &SlhDsaParams,
    sk: &SlhDsaSecretKey,
    msg: &[u8],
    addrnd: Option<&[u8]>,
) -> SlhDsaSignature {
    let opt_rand = addrnd.unwrap_or(&sk.pk_seed);
    let r = prf_msg(&sk.sk_prf, opt_rand, msg);

    let (md, idx_tree, idx_leaf, adrs) =
        derive_fors_context(params, &r, &sk.pk_seed, &sk.pk_root, msg);

    let sig_fors = fors_sign(&params.fors, &md, &sk.sk_seed, &sk.pk_seed, adrs);
    let pk_fors = fors_pk_from_sig(&params.fors, &sig_fors, &md, &sk.pk_seed, adrs);

    let sig_ht = ht_sign(
        &params.hypertree,
        &sk.sk_seed,
        &sk.pk_seed,
        &pk_fors,
        idx_tree,
        idx_leaf,
    );

    SlhDsaSignature {
        r,
        fors_sig: sig_fors,
        ht_sig: sig_ht,
    }
}

/// FIPS 205 Alg. 20 — SLH-DSA verification.
pub fn slh_verify(
    params: &SlhDsaParams,
    pk: &SlhDsaPublicKey,
    msg: &[u8],
    sig: &SlhDsaSignature,
) -> bool {
    let (md, idx_tree, idx_leaf, adrs) =
        derive_fors_context(params, &sig.r, &pk.pk_seed, &pk.pk_root, msg);

    let pk_fors = fors_pk_from_sig(&params.fors, &sig.fors_sig, &md, &pk.pk_seed, adrs);

    ht_verify(
        &params.hypertree,
        &pk.pk_seed,
        &pk.pk_root,
        &pk_fors,
        &sig.ht_sig,
        idx_tree,
        idx_leaf,
    )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Total digest length m in bytes:
///   ⌈(k·a)/8⌉  +  ⌈(h − h/d) / 8⌉  +  ⌈(h/d) / 8⌉
fn digest_len(params: &SlhDsaParams) -> usize {
    let k = params.fors.k as usize;
    let a = params.fors.a as usize;
    let h = params.hypertree.h as usize;
    let d = params.hypertree.d as usize;
    let h_prime = h / d;
    (k * a).div_ceil(8) + (h - h_prime).div_ceil(8) + h_prime.div_ceil(8)
}

/// Parse the H_msg digest into (md, idx_tree, idx_leaf) per FIPS 205 §9.
///
/// - `md`       = first ⌈k·a/8⌉ bytes
/// - `idx_tree` = next  ⌈(h−h/d)/8⌉ bytes as big-endian int, masked to (h−h/d) bits
/// - `idx_leaf` = last  ⌈h/d/8⌉ bytes as big-endian int, masked to h/d bits
fn parse_digest(params: &SlhDsaParams, digest: &[u8]) -> (Vec<u8>, u64, u32) {
    let k = params.fors.k as usize;
    let a = params.fors.a as usize;
    let h = params.hypertree.h as usize;
    let d = params.hypertree.d as usize;
    let h_prime = h / d;

    let md_bytes = (k * a).div_ceil(8);
    let tree_bytes = (h - h_prime).div_ceil(8);
    let leaf_bytes = h_prime.div_ceil(8);

    let md = digest[..md_bytes].to_vec();

    let tree_slice = &digest[md_bytes..md_bytes + tree_bytes];
    let mut tree_buf = [0u8; 8];
    tree_buf[8 - tree_bytes..].copy_from_slice(tree_slice);
    let idx_tree_raw = u64::from_be_bytes(tree_buf);
    let tree_mask: u64 = if h - h_prime >= 64 {
        u64::MAX
    } else {
        (1u64 << (h - h_prime)) - 1
    };
    let idx_tree = idx_tree_raw & tree_mask;

    let leaf_slice = &digest[md_bytes + tree_bytes..md_bytes + tree_bytes + leaf_bytes];
    let mut leaf_buf = [0u8; 4];
    leaf_buf[4 - leaf_bytes..].copy_from_slice(leaf_slice);
    let idx_leaf_raw = u32::from_be_bytes(leaf_buf);
    let leaf_mask: u32 = if h_prime >= 32 {
        u32::MAX
    } else {
        (1u32 << h_prime) - 1
    };
    let idx_leaf = idx_leaf_raw & leaf_mask;

    (md, idx_tree, idx_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slh_dsa_sha2_128s_roundtrip() {
        let params = SlhDsaParams::sha2_128s();

        let sk_seed: Vec<u8> = (0u8..16).map(|i| 0x50u8.wrapping_add(i)).collect();
        let sk_prf: Vec<u8> = (0u8..16).map(|i| 0x60u8.wrapping_add(i)).collect();
        let pk_seed: Vec<u8> = (0u8..16).map(|i| 0xA0u8.wrapping_add(i)).collect();
        let msg: Vec<u8> = b"test message for slh-dsa".to_vec();

        let (pk, sk) = slh_keygen(&params, &sk_seed, &sk_prf, &pk_seed);

        // pk_root must match what ht_pk_root computes directly.
        let expected_root = ht_pk_root(&params.hypertree, &sk_seed, &pk_seed);
        assert_eq!(pk.pk_root, expected_root, "pk_root mismatch");

        let sig = slh_sign(&params, &sk, &msg, None);
        assert!(
            slh_verify(&params, &pk, &msg, &sig),
            "valid sig must verify"
        );

        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 1;
        assert!(
            !slh_verify(&params, &pk, &bad_msg, &sig),
            "tampered msg must not verify"
        );

        let mut bad_sig_r = sig.r.clone();
        bad_sig_r[0] ^= 1;
        let bad_sig = SlhDsaSignature {
            r: bad_sig_r,
            fors_sig: sig.fors_sig,
            ht_sig: sig.ht_sig,
        };
        assert!(
            !slh_verify(&params, &pk, &msg, &bad_sig),
            "tampered R must not verify"
        );
    }

    /// Cross-check our `m` and signature-length formulas against FIPS 205 Table 1
    /// for every approved parameter set.
    #[test]
    fn test_fips_205_formula_cross_check() {
        use crate::sphincs::params::{
            FIPS_128F, FIPS_128S, FIPS_192F, FIPS_192S, FIPS_256F, FIPS_256S,
        };
        for p in [
            &FIPS_128S, &FIPS_128F, &FIPS_192S, &FIPS_192F, &FIPS_256S, &FIPS_256F,
        ] {
            let params = SlhDsaParams::from_fips(p);
            assert_eq!(digest_len(&params), p.m as usize, "[{}] m mismatch", p.name);
            assert_eq!(
                SlhDsaSignature::expected_len(&params),
                p.sig_size,
                "[{}] sig_size mismatch",
                p.name,
            );
        }
    }

    #[test]
    fn test_expected_sig_len_sha2_128_24() {
        // SP 800-230 IPD: 3856 bytes hand-derived from params (not in the FIPS_205 table).
        let params = SlhDsaParams::sha2_128_24();
        assert_eq!(SlhDsaSignature::expected_len(&params), 3856);
    }
}
