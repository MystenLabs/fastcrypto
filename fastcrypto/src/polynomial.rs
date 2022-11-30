// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// TODO: add license notice

use crate::error::FastCryptoError;
use crate::groups::{GroupElement, Scalar};
use crate::traits::AllowedRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

//// Types

pub type Idx = u32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedValue<A> {
    pub index: Idx,
    pub value: A,
}

pub type Eval<A> = IndexedValue<A>;

/// A polynomial that is using a scalar for the variable x and a generic
/// element for the coefficients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poly<C>(Vec<C>);

pub type PrivatePoly<C> = Poly<<C as GroupElement>::ScalarType>;
pub type PublicPoly<C> = Poly<C>;

//// Vector related operations.

impl<C> Poly<C> {
    /// Returns the degree of the polynomial
    pub fn degree(&self) -> usize {
        // e.g. c_0 + c_1 * x + c_2 * x^2 + c_3 * x^3
        // ^ 4 coefficients correspond to a 3rd degree poly
        self.0.len() - 1
    }
}

impl<C> From<Vec<C>> for Poly<C> {
    fn from(c: Vec<C>) -> Self {
        Self(c)
    }
}

impl<C> From<Poly<C>> for Vec<C> {
    fn from(poly: Poly<C>) -> Self {
        poly.0
    }
}

//// GroupElement operations.

impl<C: GroupElement> Poly<C> {
    /// Returns a polynomial with the zero element.
    pub fn zero() -> Self {
        Self::from(vec![C::zero()])
    }

    /// Performs polynomial addition in place.
    pub fn add(&mut self, other: &Self) {
        // if we have a smaller degree we should pad with zeros
        if self.0.len() < other.0.len() {
            self.0.resize(other.0.len(), C::zero())
        }
        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| *a += *b)
    }

    // TODO: Some of the functions/steps below may be executed many times in practice thus cache can be
    // used to improve efficiency (e.g., eval(i) may be called with the same index every time a partial
    // signature from party i is verified).

    /// Evaluates the polynomial at the specified value.
    pub fn eval(&self, i: Idx) -> Eval<C> {
        assert!(i > 0); // Never reveal the secret coefficient directly.
        let xi = C::ScalarType::from(i.into());
        let res = self.0.iter().rev().fold(C::zero(), |mut sum, coeff| {
            sum = sum * xi + coeff;
            sum
        });

        Eval {
            index: i,
            value: res,
        }
    }

    /// Given at least `t` polynomial evaluations, it will recover the polynomial's
    /// constant term
    pub fn recover_c0(t: u32, shares: Vec<Eval<C>>) -> Result<C, FastCryptoError> {
        let xs = Self::share_map(t, shares)?;

        // Iterate over all indices and for each multiply the lagrange basis
        // with the value of the share.
        let mut acc = C::zero();
        for (i, xi) in &xs {
            let mut yi = *xi;
            let mut num = C::ScalarType::generator();
            let mut den = C::ScalarType::generator();

            for j in xs.keys() {
                if i == j {
                    continue;
                };
                // xj - 0
                num = num * C::ScalarType::from(*j as u64);
                // 1 / (xj - xi)
                let tmp = C::ScalarType::from(*j as u64) - C::ScalarType::from(*i as u64);
                den = den * tmp;
            }
            // Next line is safe since i != j.
            let inv = C::ScalarType::generator() / den;
            num = num * inv;
            yi = yi * num;
            acc += yi;
        }

        Ok(acc)
    }

    fn share_map(t: u32, mut shares: Vec<Eval<C>>) -> Result<BTreeMap<Idx, C>, FastCryptoError> {
        if shares.len() < t.try_into().unwrap() {
            return Err(FastCryptoError::InvalidInput);
        }
        // TODO: check that each id appears exactly once.

        // first sort the shares as it can happens recovery happens for
        // non-correlated shares so the subset chosen becomes important
        shares.sort_by(|a, b| a.index.cmp(&b.index));
        // convert the indexes of the shares into scalars
        let xs =
            shares
                .into_iter()
                .take(t.try_into().unwrap())
                .fold(BTreeMap::new(), |mut m, sh| {
                    m.insert(sh.index, sh.value);
                    m
                });

        Ok(xs)
    }

    /// Checks if a given share is valid.
    pub fn is_valid_share(&self, idx: Idx, share: &C::ScalarType) -> bool {
        let e = C::generator() * share;
        let pub_eval = self.eval(idx);
        pub_eval.value == e
    }

    /// Return the constant term of the polynomial.
    pub fn c0(&self) -> &C {
        &self.0[0]
    }
}

//// Scalar operations.

impl<C: Scalar> Poly<C> {
    /// Returns a new polynomial of the given degree where each coefficients is
    /// sampled at random from the given RNG.
    /// In the context of secret sharing, the threshold is the degree + 1.
    pub fn rand<R: AllowedRng>(degree: u32, rng: &mut R) -> Self {
        let coeffs: Vec<C> = (0..=degree).map(|_| C::rand(rng)).collect();
        Self::from(coeffs)
    }

    /// Commits the scalar polynomial to the group and returns a polynomial over
    /// the group.
    pub fn commit<P: GroupElement<ScalarType = C>>(&self) -> Poly<P> {
        let commits = self
            .0
            .iter()
            .map(|c| {
                let mut commitment = P::generator();
                commitment = commitment * c;
                commitment
            })
            .collect::<Vec<P>>();

        Poly::<P>::from(commits)
    }
}
