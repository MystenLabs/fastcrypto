// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Common reference string and statement dimensioning for BP++.

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::pedersen;

/// Base of the digit decomposition; each digit covers log2(BASE) = 4 bits.
pub(crate) const BASE: u64 = 16;

/// Number of H-bases: 7 blinding slots + N_v = 1 linear-witness slot.
pub(crate) const H_LEN: usize = 8;

/// Domain separation tags for the hash-to-curve derived generators, one per
/// generator family: the RFC 9380 suite ID plus an application suffix, as in
/// `fastcrypto::vrf`. The hash (SHA-512) is fixed by fastcrypto's
/// `hash_to_ristretto255_with_dst` suite.
// TODO: discuss DST strings.
const DST_H: &[u8] = b"ristretto255_XMD:SHA-512_R255MAP_RO_fastcrypto-bppp-gen-h-01";
const DST_G: &[u8] = b"ristretto255_XMD:SHA-512_R255MAP_RO_fastcrypto-bppp-gen-g-01";

/// Check the statement dimensions: `n_bits` must be a positive multiple of 4
/// (at most 64) and `k >= 1`.
pub(crate) fn validate_dims(n_bits: usize, k: usize) -> FastCryptoResult<()> {
    if n_bits == 0 || n_bits > 64 || !n_bits.is_multiple_of(BASE.ilog2() as usize) || k == 0 {
        return Err(FastCryptoError::InvalidInput);
    }
    Ok(())
}

/// Digit-count dimensions for a batch of `k` values of `n_bits` bits each:
/// `d` digits per value, `n_d = k*d` digits overall, and the norm-vector
/// length `nm = max(n_d, BASE)` rounded up to a power of two (the BASE-1
/// multiplicity slots set the floor; slots beyond `n_d` are zero-padded).
pub(crate) fn dims(n_bits: usize, k: usize) -> (usize, usize, usize) {
    let d = n_bits / BASE.ilog2() as usize;
    let n_d = k * d;
    (d, n_d, n_d.max(BASE as usize).next_power_of_two())
}

/// Common reference string for BP++ over Ristretto255.
///
/// Layout per the spec (`G`, `H_0..H_7`, `G_0..G_{nm-1}`): `g` carries the
/// committed value, `h_vec` blinding and the linear witness, `g_vec` the norm
/// witness (digits, reciprocals, multiplicities).
///
/// Base mapping matches roles, not letters: BP++'s value base `g` is
/// [`pedersen::H`] and the blinding base `h_vec[0]` is [`pedersen::G`], so
/// commitments from [`fastcrypto::pedersen`] open directly under this CRS.
/// The remaining generators are derived by hash-to-curve and have no known
/// discrete-log relation to each other or to the Pedersen bases.
#[derive(Clone)]
pub(crate) struct Generators {
    pub(crate) g: RistrettoPoint,
    pub(crate) h_vec: Vec<RistrettoPoint>,
    pub(crate) g_vec: Vec<RistrettoPoint>,
}

impl Generators {
    /// Create the CRS for proofs over `k` values of `n_bits` bits each.
    /// `n_bits` must be a positive multiple of 4 (at most 64) and `k >= 1`.
    pub(crate) fn new(n_bits: usize, k: usize) -> FastCryptoResult<Self> {
        validate_dims(n_bits, k)?;
        let (_, _, nm) = dims(n_bits, k);

        let mut h_vec = Vec::with_capacity(H_LEN);
        h_vec.push(*pedersen::G);
        h_vec.extend((1..H_LEN).map(|i| hash_to_generator(DST_H, i)));

        Ok(Generators {
            g: *pedersen::H,
            h_vec,
            g_vec: (0..nm).map(|i| hash_to_generator(DST_G, i)).collect(),
        })
    }
}

fn hash_to_generator(dst: &[u8], index: usize) -> RistrettoPoint {
    RistrettoPoint::hash_to_ristretto255_with_dst(&[&(index as u64).to_le_bytes()], dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dims() {
        assert_eq!(dims(64, 1), (16, 16, 16));
        // Fewer digits than the multiplicity floor: nm stays at 16.
        assert_eq!(dims(16, 1), (4, 4, 16));
        assert_eq!(dims(32, 1), (8, 8, 16));
        assert_eq!(dims(8, 1), (2, 2, 16));
        // Batches, including non-power-of-two digit counts.
        assert_eq!(dims(16, 2), (4, 8, 16));
        assert_eq!(dims(16, 4), (4, 16, 16));
        assert_eq!(dims(16, 5), (4, 20, 32));
        assert_eq!(dims(16, 8), (4, 32, 32));
        assert_eq!(dims(32, 8), (8, 64, 64));
        assert_eq!(dims(64, 16), (16, 256, 256));
    }

    #[test]
    fn test_generators_sizes_and_validation() {
        let gens = Generators::new(64, 1).unwrap();
        assert_eq!(gens.h_vec.len(), H_LEN);
        assert_eq!(gens.g_vec.len(), 16);
        assert_eq!(Generators::new(16, 1).unwrap().g_vec.len(), 16);
        assert_eq!(Generators::new(32, 8).unwrap().g_vec.len(), 64);

        assert!(Generators::new(0, 1).is_err());
        assert!(Generators::new(10, 1).is_err());
        assert!(Generators::new(128, 1).is_err());
        assert!(Generators::new(64, 0).is_err());
    }

    #[test]
    fn test_generators_pedersen_interop_and_distinctness() {
        let gens = Generators::new(64, 2).unwrap();
        // Value base and blinding base are the fastcrypto Pedersen bases.
        assert_eq!(gens.g, *pedersen::H);
        assert_eq!(gens.h_vec[0], *pedersen::G);

        // Derivation is deterministic and a prefix of any larger CRS.
        let again = Generators::new(64, 1).unwrap();
        assert_eq!(gens.h_vec, again.h_vec);
        assert_eq!(&gens.g_vec[..16], &again.g_vec[..]);

        // All generators pairwise distinct.
        let mut all = vec![gens.g];
        all.extend(&gens.h_vec);
        all.extend(&gens.g_vec);
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j], "generators {i} and {j} collide");
            }
        }
    }
}
