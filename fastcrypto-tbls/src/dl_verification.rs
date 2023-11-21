// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::polynomial::{Eval, Poly, PrivatePoly};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{bls12381, GroupElement, MultiScalarMul, Pairing, Scalar};
use fastcrypto::traits::AllowedRng;
use std::num::NonZeroU32;

/// Helper functions for checking relations between scalars and group elements.

fn dot<S: Scalar>(v1: &[S], v2: &[S]) -> S {
    assert_eq!(v1.len(), v2.len());
    v1.iter()
        .zip(v2.iter())
        .fold(S::zero(), |acc, (a, b)| acc + *a * *b)
}

/// Given a set of indexes <a1, a2, ..., an> and a vector of random scalars <r1, r2, ..., rn>,
/// returns the vector v such that <v, c> = \sum ri * p(ai) for a polynomial p with coefficients c.
pub(crate) fn batch_coefficients<S: Scalar>(r: &[S], indexes: &[S], degree: u32) -> Vec<S> {
    assert!(r.len() == indexes.len() && degree > 0); // Should never happen
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
    assert!(poly.degree() > 0);
    if evals.is_empty() {
        return Ok(());
    }
    let rs = get_random_scalars::<G::ScalarType, R>(evals.len() as u32, rng);

    let lhs = G::generator() * dot(&rs, &evals.iter().map(|e| e.value).collect::<Vec<_>>());

    let evals_as_scalars = evals
        .iter()
        .map(|e| G::ScalarType::from(e.index.get().into()))
        .collect::<Vec<_>>();
    let coeffs = batch_coefficients(&rs, &evals_as_scalars, poly.degree());
    let rhs = G::multi_scalar_mul(&coeffs, poly.as_vec()).expect("sizes match");

    if lhs != rhs {
        Err(FastCryptoError::InvalidProof)
    } else {
        Ok(())
    }
}

/// Check that a pair (k, H) satisfies H = k*G using a random combination of the pairs and
/// multi scalar multiplication.
pub fn verify_pairs<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    pairs: &[(G::ScalarType, G)],
    rng: &mut R,
) -> FastCryptoResult<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    // Denote the inputs by (k1, H1), (k2, H2), ..., (kn, Hn)
    // Generate random r1, r2, ..., rn
    let rs = get_random_scalars::<G::ScalarType, R>(pairs.len() as u32, rng);
    // Compute (r1*k1 + r2*k2 + ... + rn*kn)*G
    let lhs = G::generator()
        * rs.iter()
            .zip(pairs.iter())
            .map(|(r, (k, _))| *r * *k)
            .reduce(|a, b| a + b)
            .expect("Iterators are non-empty");
    // Compute r1*H1 + r2*H2 + ... + rn*Hn
    let rhs = G::multi_scalar_mul(
        &rs[..],
        &pairs.iter().map(|(_, g)| *g).collect::<Vec<_>>()[..],
    )
    .expect("valid sizes");

    if lhs == rhs {
        Ok(())
    } else {
        Err(FastCryptoError::InvalidProof)
    }
}

/// Check that a triplet (k, G, H) satisfies H = k*G using a random combination of the
/// triplets and multi scalar multiplication.
pub fn verify_triplets<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    triplets: &[(G::ScalarType, G, G)],
    rng: &mut R,
) -> FastCryptoResult<()> {
    if triplets.is_empty() {
        return Ok(());
    }
    // Denote the inputs by (k1, G1, H1), (k2, G2, H2), ..., (kn, Gn, Hn)
    // Generate random r1, r2, ..., rn
    let rs = get_random_scalars::<G::ScalarType, R>(triplets.len() as u32, rng);
    // Compute r1*k1, r2*k2, ..., rn*kn
    let lhs_coeffs = rs
        .iter()
        .zip(triplets.iter())
        .map(|(r, (k, _, _))| *r * *k)
        .collect::<Vec<_>>();
    // Compute r1*k1*G1 + r2*k2*G2 + ... + rn*kn*Gn
    let lhs = G::multi_scalar_mul(
        &lhs_coeffs[..],
        &triplets.iter().map(|(_, b, _)| *b).collect::<Vec<_>>()[..],
    )
    .expect("valid sizes");
    // Compute r1*H1 + r2*H2 + ... + rn*Hn
    let rhs = G::multi_scalar_mul(
        &rs[..],
        &triplets.iter().map(|(_, _, k_b)| *k_b).collect::<Vec<_>>()[..],
    )
    .expect("valid sizes");

    if lhs == rhs {
        Ok(())
    } else {
        Err(FastCryptoError::InvalidProof)
    }
}

/// Check that partial public keys form a polynomial of the right degree using the protocol of
/// https://eprint.iacr.org/2017/216.pdf. deg_f should be n-k-2 if the polynomial is of degree k.
pub fn verify_deg_t_poly<G: GroupElement + MultiScalarMul, R: AllowedRng>(
    deg_f: u32,
    values: &[G],
    precomputed_dual_code_coefficients: &[G::ScalarType],
    rng: &mut R,
) -> FastCryptoResult<()> {
    let poly_f = PrivatePoly::<G>::rand(deg_f, rng);
    let coefficients = precomputed_dual_code_coefficients
        .iter()
        .enumerate()
        .map(|(i, c)| *c * poly_f.eval(NonZeroU32::new((i + 1) as u32).unwrap()).value)
        .collect::<Vec<_>>();
    let lhs = G::multi_scalar_mul(&coefficients[..], values).expect("sizes match");
    if lhs != G::zero() {
        return Err(FastCryptoError::InvalidProof);
    }
    Ok(())
}

/// Checks if vectors v1=(a1*G1, ..., an*G1) and v2=(a1'*G2, ..., an'*G2) use ai = ai' for all i, by
/// computing <v1, e> and <v2, e> for a random e and checking if they are equal using pairing.
pub fn verify_equal_exponents<R: AllowedRng>(
    v1: &[bls12381::G1Element],
    v2: &[bls12381::G2Element],
    rng: &mut R,
) -> FastCryptoResult<()> {
    if v1.len() != v2.len() {
        return Err(FastCryptoError::InvalidProof);
    }
    let rs = get_random_scalars::<bls12381::Scalar, R>(v1.len() as u32, rng);
    let lhs = bls12381::G1Element::multi_scalar_mul(&rs[..], v1).expect("sizes match");
    let rhs = bls12381::G2Element::multi_scalar_mul(&rs[..], v2).expect("sizes match");

    if lhs.pairing(&bls12381::G2Element::generator())
        != bls12381::G1Element::generator().pairing(&rhs)
    {
        return Err(FastCryptoError::InvalidProof);
    }
    Ok(())
}

pub(crate) fn get_random_scalars<S: Scalar, R: AllowedRng>(n: u32, rng: &mut R) -> Vec<S> {
    (0..n).map(|_| S::from(rng.next_u64())).collect::<Vec<_>>()
}
