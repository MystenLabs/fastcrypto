// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul};
use fastcrypto::traits::AllowedRng;

/// Helper functions for checking relations between scalars and group elements.

/// Checks that a given set of evaluations is consistent with a given polynomial in the exp by
/// checking that (\sum r_i v_i)*G = \sum r_i p(i) for a random set of scalars r_i.
pub fn verify_poly_evals<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    evals: &[Eval<G::ScalarType>],
    poly: &Poly<G>,
    rng: &mut R,
) -> FastCryptoResult<()> {
    let rs = get_random_scalars::<G, R>(evals.len() as u32, rng);

    let lhs = G::generator()
        * rs.iter()
            .zip(evals.iter())
            .map(|(r, eval)| *r * eval.value)
            .fold(G::ScalarType::zero(), |acc, r| acc + r);

    let mut multiplies = rs;
    let mut coeffs = Vec::<G::ScalarType>::new();
    let evals_as_scalars = evals
        .iter()
        .map(|e| G::ScalarType::from(e.index.get().into()))
        .collect::<Vec<_>>();
    for _ in 0..poly.as_vec().len() {
        let sum = multiplies
            .iter()
            .fold(G::ScalarType::zero(), |acc, r| acc + *r);
        coeffs.push(sum);
        multiplies = multiplies
            .iter()
            .zip(evals_as_scalars.iter())
            .map(|(r, eval)| *r * eval)
            .collect::<Vec<_>>();
    }
    let rhs = G::multi_scalar_mul(&coeffs, poly.as_vec()).expect("sizes match");

    if lhs != rhs {
        return Err(FastCryptoError::InvalidProof);
    }
    Ok(())
}

pub fn get_random_scalars<G: GroupElement, R: AllowedRng>(
    n: u32,
    rng: &mut R,
) -> Vec<<G as GroupElement>::ScalarType> {
    // TODO: can use 40 bits instead of 64 ("& 0x000F_FFFF_FFFF_FFFF" below)
    (0..n)
        .into_iter()
        .map(|_| G::ScalarType::from(rng.next_u64()))
        .collect::<Vec<_>>()
}
