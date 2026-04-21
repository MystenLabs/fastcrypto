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
    hasher.update(&adrs_c);
    hasher.update(m);
    hasher.finalize()[..n].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sphincs::AdrsType;

    #[test]
    fn test_deterministic() {
        let pk_seed = [0xA0u8; 16];
        let adrs = Adrs::new().with_type(AdrsType::WotsHash);
        let m = [0x42u8; 16];
        let out1 = tweakable_hash(&pk_seed, adrs, &m);
        let out2 = tweakable_hash(&pk_seed, adrs, &m);
        assert_eq!(out1.len(), 16);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_different_adrs_gives_different_output() {
        let pk_seed = [0xA0u8; 16];
        let m = [0x42u8; 16];

        let adrs1 = Adrs::new()
            .with_type(AdrsType::WotsHash)
            .with_chain_address(0u32);
        let adrs2 = Adrs::new()
            .with_type(AdrsType::WotsHash)
            .with_chain_address(1u32);

        assert_ne!(
            tweakable_hash(&pk_seed, adrs1, &m),
            tweakable_hash(&pk_seed, adrs2, &m)
        );
    }

    #[test]
    fn test_cross_check_prf_with_ref_c() {
        // Inputs: pub_seed = 0xA0..0xAF, sk_seed = 0x50..0x5F
        // Address: type=WOTS_PRF(5), everything else 0.
        // Expected from ref C: b668d77c6ef925c464757ab725b24be5
        let pk_seed: Vec<u8> = (0xA0u8..=0xAF).collect();
        let sk_seed: Vec<u8> = (0x50u8..=0x5F).collect();

        let adrs = Adrs::new().with_type(AdrsType::WotsPrf);

        let out = tweakable_hash(&pk_seed, adrs, &sk_seed);
        assert_eq!(hex::encode(&out), "b668d77c6ef925c464757ab725b24be5");
    }

    #[test]
    fn test_cross_check_f_with_ref_c() {
        // F(pk_seed, adrs, prf_out) where adrs is all-zero WOTS_HASH.
        // Expected from ref C: 60088aceb3ea7dbdcb47867c3b917416
        let pk_seed: Vec<u8> = (0xA0u8..=0xAF).collect();
        let adrs = Adrs::new();

        let prf_out = hex::decode("b668d77c6ef925c464757ab725b24be5").unwrap();
        let out = tweakable_hash(&pk_seed, adrs, &prf_out);
        assert_eq!(hex::encode(&out), "60088aceb3ea7dbdcb47867c3b917416");
    }
}
