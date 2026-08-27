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

/// The provable ranges.
#[derive(Clone, Copy, Debug)]
pub enum Range {
    /// The range [0, 2^8).
    Bits8,
    /// The range [0, 2^16).
    Bits16,
    /// The range [0, 2^32).
    Bits32,
    /// The range [0, 2^64).
    Bits64,
}

impl Range {
    pub fn is_in_range(&self, value: u64) -> bool {
        match self {
            Range::Bits64 => true,
            _ => value >> self.bits() == 0,
        }
    }

    pub(crate) fn bits(&self) -> usize {
        match self {
            Range::Bits8 => 8,
            Range::Bits16 => 16,
            Range::Bits32 => 32,
            Range::Bits64 => 64,
        }
    }
}

/// Digit-count dimensions for a batch of `k` values in `range`: `d` digits
/// per value, `n_d = k*d` digits overall, and the norm-vector length
/// `nm = max(n_d, BASE)` rounded up to a power of two (the BASE-1
/// multiplicity slots set the floor; slots beyond `n_d` are zero-padded).
pub(crate) fn dims(range: Range, k: usize) -> (usize, usize, usize) {
    let d = range.bits() / BASE.ilog2() as usize;
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
    /// Create the CRS for proofs over `k >= 1` values in `range`.
    ///
    /// A cache miss is expensive (one hash-to-curve per generator plus the
    /// precomputed MSM table build, both linear in `nm`) and the entry is
    /// retained for the lifetime of the process, so the dimensions must not
    /// be taken from untrusted input.
    pub(crate) fn new(range: Range, k: usize) -> FastCryptoResult<Arc<Self>> {
        if k == 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        let (_, _, nm) = dims(range, k);

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

fn hash_to_generator(dst: &[u8], index: usize) -> RistrettoPoint {
    RistrettoPoint::hash_to_ristretto255_with_dst(&[&(index as u64).to_le_bytes()], dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dims() {
        assert_eq!(dims(Range::Bits64, 1), (16, 16, 16));
        // Fewer digits than the multiplicity floor: nm stays at 16.
        assert_eq!(dims(Range::Bits16, 1), (4, 4, 16));
        assert_eq!(dims(Range::Bits32, 1), (8, 8, 16));
        assert_eq!(dims(Range::Bits8, 1), (2, 2, 16));
        // Batches, including non-power-of-two digit counts.
        assert_eq!(dims(Range::Bits16, 2), (4, 8, 16));
        assert_eq!(dims(Range::Bits16, 4), (4, 16, 16));
        assert_eq!(dims(Range::Bits16, 5), (4, 20, 32));
        assert_eq!(dims(Range::Bits16, 8), (4, 32, 32));
        assert_eq!(dims(Range::Bits32, 8), (8, 64, 64));
        assert_eq!(dims(Range::Bits64, 16), (16, 256, 256));
    }

    #[test]
    fn test_generators_sizes_and_validation() {
        let gens = Generators::new(Range::Bits64, 1).unwrap();
        assert_eq!(gens.h_vec.len(), H_LEN);
        assert_eq!(gens.g_vec.len(), 16);
        assert_eq!(Generators::new(Range::Bits16, 1).unwrap().g_vec.len(), 16);
        assert_eq!(Generators::new(Range::Bits32, 8).unwrap().g_vec.len(), 64);

        assert!(Generators::new(Range::Bits64, 0).is_err());
    }

    #[test]
    fn test_generators_pedersen_interop_and_distinctness() {
        let gens = Generators::new(Range::Bits64, 2).unwrap();
        // Value base and blinding base are the fastcrypto Pedersen bases.
        assert_eq!(gens.g, *pedersen::H);
        assert_eq!(gens.h_vec[0], *pedersen::G);

        // Derivation is deterministic and a prefix of any larger CRS.
        let again = Generators::new(Range::Bits64, 1).unwrap();
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
