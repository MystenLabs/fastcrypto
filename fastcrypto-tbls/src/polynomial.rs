// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Most of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::types::{IndexedValue, ShareIndex};
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

//// Types

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
    pub fn degree(&self) -> u32 {
        // e.g. c_0 + c_1 * x + c_2 * x^2 + c_3 * x^3
        // ^ 4 coefficients correspond to a 3rd degree poly
        (self.0.len() - 1) as u32
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
    pub fn eval(&self, i: ShareIndex) -> Eval<C> {
        let xi = C::ScalarType::from(i.get().into());
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
    pub fn recover_c0(t: u32, shares: &[Eval<C>]) -> Result<C, FastCryptoError> {
        if shares.len() < t.try_into().unwrap() {
            return Err(FastCryptoError::InvalidInput);
        }

        // Check for duplicates.
        let mut ids_set = HashSet::new();
        shares.iter().map(|s| &s.index).for_each(|id| {
            ids_set.insert(id);
        });
        if ids_set.len() != t as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        // Iterate over all indices and for each multiply the lagrange basis
        // with the value of the share.
        let mut acc = C::zero();
        for IndexedValue {
            index: i,
            value: share_i,
        } in shares
        {
            let mut num = C::ScalarType::generator();
            let mut den = C::ScalarType::generator();

            for IndexedValue { index: j, value: _ } in shares {
                if i == j {
                    continue;
                };
                // j - 0
                num = num * C::ScalarType::from(j.get() as u64);
                // 1 / (j - i)
                den = den
                    * (C::ScalarType::from(j.get() as u64) - C::ScalarType::from(i.get() as u64));
            }
            // Next line is safe since i != j.
            let inv = (C::ScalarType::generator() / den).unwrap();
            acc += *share_i * num * inv;
        }

        Ok(acc)
    }

    // TODO: Create a batch version of is_valid_share that checks a vector in O(n) instead of O(n^2).

    /// Checks if a given share is valid.
    pub fn is_valid_share(&self, idx: ShareIndex, share: &C::ScalarType) -> bool {
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
