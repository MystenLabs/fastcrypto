// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;

/// Helper functions for checking relations between scalars and group elements.

fn dot<S: Scalar>(v1: &[S], v2: &[S]) -> S {
    assert_eq!(v1.len(), v2.len());
    v1.iter()
        .zip(v2.iter())
        .fold(S::zero(), |acc, (a, b)| acc + *a * *b)
}

/// Given a set of indexes <a1, a2, ..., an> and a vector of random scalars <r1, r2, ..., rn>,
/// returns the vector v such that <v, c> = \sum ri * p(ai) for a polynomial p with coefficients c.
pub fn batch_coefficients<S: Scalar>(r: &[S], indexes: &[S], degree: u32) -> Vec<S> {
    let mut multiplies = r.to_vec();
    let mut res = Vec::<S>::new();
    for i in 0..=degree {
        let sum = multiplies.iter().fold(S::zero(), |acc, r| acc + *r);
        res.push(sum);
        if i == degree {
            // Save some computation since we don't need multiplies anymore
            break;
        }
        multiplies = multiplies
            .iter()
            .zip(indexes.iter())
            .map(|(r, c)| *r * c)
            .collect::<Vec<_>>();
    }
    res
}

/// Checks that a given set of evaluations is consistent with a given polynomial in the exp by
/// checking that (\sum r_i v_i)*G = \sum r_i p(i) for a random set of scalars r_i.
pub fn verify_poly_evals<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    evals: &[Eval<G::ScalarType>],
    poly: &Poly<G>,
    rng: &mut R,
) -> FastCryptoResult<()> {
    let rs = get_random_scalars::<G::ScalarType, R>(evals.len() as u32, rng);

    let lhs = G::generator() * dot(&rs, &evals.iter().map(|e| e.value).collect::<Vec<_>>());

    let evals_as_scalars = evals
        .iter()
        .map(|e| G::ScalarType::from(e.index.get().into()))
        .collect::<Vec<_>>();
    let coeffs = batch_coefficients(&rs, &evals_as_scalars, poly.degree());
    let rhs = G::multi_scalar_mul(&coeffs, poly.as_vec()).expect("sizes match");

    if lhs != rhs {
        return Err(FastCryptoError::InvalidProof);
    }
    Ok(())
}

pub fn get_random_scalars<S: Scalar, R: AllowedRng>(n: u32, rng: &mut R) -> Vec<S> {
    // TODO: can use 40 bits instead of 64 ("& 0x000F_FFFF_FFFF_FFFF" below)
    (0..n).map(|_| S::from(rng.next_u64())).collect::<Vec<_>>()
}
