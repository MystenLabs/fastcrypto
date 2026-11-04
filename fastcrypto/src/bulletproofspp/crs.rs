// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Common reference string and statement dimensioning for BP++.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::ristretto255::{RistrettoPoint, RistrettoPrecomputation, RistrettoScalar};
use crate::groups::{MixedMultiScalarMul, PrecomputableMultiScalarMul};
use crate::pedersen;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

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

/// Common reference string for BP++ over Ristretto255.
///
/// Layout per the spec (`G`, `H_0..H_7`, `G_0..G_{nm-1}`): `g` carries the
/// committed value, `h_vec` blinding and the linear witness, `g_vec` the norm
/// witness (digits, reciprocals, multiplicities).
///
/// Base mapping matches roles, not letters: BP++'s value base `g` is
/// [`pedersen::H`] and the blinding base `h_vec[0]` is [`pedersen::G`], so
/// commitments from [`crate::pedersen`] open directly under this CRS.
/// The remaining generators are derived by hash-to-curve and have no known
/// discrete-log relation to each other or to the Pedersen bases.
pub(crate) struct Generators {
    pub(crate) g: RistrettoPoint,
    pub(crate) h_vec: Vec<RistrettoPoint>,
    pub(crate) g_vec: Vec<RistrettoPoint>,
    /// Precomputed MSM tables over `[g, h_vec.., g_vec..]`.
    precomp: RistrettoPrecomputation,
}

/// Process-wide cache of derived CRSs, keyed by the norm length `nm` — the
/// only dimension a CRS depends on. The generator derivation (one
/// hash-to-curve per point) and the MSM table build are paid once per `nm`;
/// a hit shares the entry rather than copying it.
static CRS_CACHE: Lazy<RwLock<HashMap<usize, Arc<Generators>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

impl Generators {
    /// Create the CRS with `nm` norm generators, a power of two `>= BASE`.
    ///
    /// A cache miss is expensive (one hash-to-curve per generator plus the
    /// precomputed MSM table build, both linear in `nm`) and the entry is
    /// retained for the lifetime of the process, so the dimensions must not
    /// be taken from untrusted input.
    pub(crate) fn new(nm: usize) -> FastCryptoResult<Arc<Self>> {
        if !nm.is_power_of_two() || nm < BASE as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        if let Some(gens) = CRS_CACHE
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&nm)
        {
            return Ok(Arc::clone(gens));
        }

        let mut h_vec = Vec::with_capacity(H_LEN);
        h_vec.push(*pedersen::G);
        h_vec.extend((1..H_LEN).map(|i| hash_to_generator(DST_H, i)));

        let gens = Arc::new(Self::from_parts(
            *pedersen::H,
            h_vec,
            (0..nm).map(|i| hash_to_generator(DST_G, i)).collect(),
        )?);

        // Derivation is deterministic, so a concurrent double-build inserts
        // an identical entry.
        CRS_CACHE
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(nm, Arc::clone(&gens));
        Ok(gens)
    }

    /// Assemble a CRS from explicit generators, building the precomputed MSM
    /// tables over `[g, h_vec.., g_vec..]`.
    pub(crate) fn from_parts(
        g: RistrettoPoint,
        h_vec: Vec<RistrettoPoint>,
        g_vec: Vec<RistrettoPoint>,
    ) -> FastCryptoResult<Self> {
        let mut all = Vec::with_capacity(1 + h_vec.len() + g_vec.len());
        all.push(g);
        all.extend_from_slice(&h_vec);
        all.extend_from_slice(&g_vec);
        Ok(Generators {
            g,
            h_vec,
            g_vec,
            precomp: RistrettoPoint::precompute(&all)?,
        })
    }

    /// `sigma*G + <l, h_vec> + <n, g_vec> + <dynamic_scalars, dynamic_points>`
    /// over the precomputed tables; `l` and `n` must yield `h_vec.len()` and
    /// `g_vec.len()` scalars.
    pub(crate) fn msm(
        &self,
        sigma: RistrettoScalar,
        l: impl IntoIterator<Item = RistrettoScalar>,
        n: impl IntoIterator<Item = RistrettoScalar>,
        dynamic_scalars: &[RistrettoScalar],
        dynamic_points: &[RistrettoPoint],
    ) -> FastCryptoResult<RistrettoPoint> {
        let mut scalars = Vec::with_capacity(1 + self.h_vec.len() + self.g_vec.len());
        scalars.push(sigma);
        scalars.extend(l);
        scalars.extend(n);
        self.precomp
            .mixed_multi_scalar_mul(&scalars, dynamic_scalars, dynamic_points)
    }
}

/// Whether `gens` uses the Pedersen value and blinding bases, so that
/// commitments from [`crate::pedersen`] open under it.
pub(crate) fn compatible_with_pedersen_commitments(gens: &Generators) -> bool {
    gens.g == *pedersen::H && gens.h_vec[0] == *pedersen::G
}

fn hash_to_generator(dst: &[u8], index: usize) -> RistrettoPoint {
    RistrettoPoint::hash_to_ristretto255_with_dst(&[&(index as u64).to_le_bytes()], dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generators_sizes_and_validation() {
        let gens = Generators::new(16).unwrap();
        assert_eq!(gens.h_vec.len(), H_LEN);
        assert_eq!(gens.g_vec.len(), 16);
        assert_eq!(Generators::new(64).unwrap().g_vec.len(), 64);

        assert!(Generators::new(0).is_err());
        assert!(Generators::new(8).is_err());
        assert!(Generators::new(24).is_err());
    }

    #[test]
    fn test_generators_pedersen_interop_and_distinctness() {
        let gens = Generators::new(32).unwrap();
        // Value base and blinding base are the fastcrypto Pedersen bases.
        assert!(compatible_with_pedersen_commitments(&gens));

        // Derivation is deterministic and a prefix of any larger CRS.
        let again = Generators::new(16).unwrap();
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
