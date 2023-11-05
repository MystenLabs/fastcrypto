// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Most of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::types::{IndexedValue, ShareIndex};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Types

pub type Eval<A> = IndexedValue<A>;

/// A polynomial that is using a scalar for the variable x and a generic
/// element for the coefficients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poly<C>(Vec<C>);

pub type PrivatePoly<C> = Poly<<C as GroupElement>::ScalarType>;
pub type PublicPoly<C> = Poly<C>;

/// Vector related operations.

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

/// GroupElement operations.

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
        let res = self
            .0
            .iter()
            .rev()
            .fold(C::zero(), |sum, coeff| sum * xi + coeff);

        Eval {
            index: i,
            value: res,
        }
    }

    fn get_lagrange_coefficients(
        t: u32,
        shares: &[Eval<C>],
    ) -> FastCryptoResult<Vec<C::ScalarType>> {
        if shares.len() < t as usize {
            return Err(FastCryptoError::NotEnoughInputs);
        }
        // Check for duplicates.
        let mut ids_set = HashSet::new();
        shares.iter().map(|s| &s.index).for_each(|id| {
            ids_set.insert(id);
        });
        if ids_set.len() != shares.len() {
            return Err(FastCryptoError::InvalidInput); // expected unique ids
        }

        let indices = shares
            .iter()
            .map(|s| C::ScalarType::from(s.index.get() as u64))
            .collect::<Vec<_>>();

        let full_numerator = indices
            .iter()
            .fold(C::ScalarType::generator(), |acc, i| acc * i);
        let mut coeffs = Vec::new();
        for i in &indices {
            let denominator = indices
                .iter()
                .filter(|j| *j != i)
                .fold(*i, |acc, j| acc * (*j - i));
            let coeff = full_numerator / denominator;
            coeffs.push(coeff.expect("safe since i != j"));
        }
        Ok(coeffs)
    }

    /// Given at least `t` polynomial evaluations, it will recover the polynomial's
    /// constant term
    pub fn recover_c0(t: u32, shares: &[Eval<C>]) -> Result<C, FastCryptoError> {
        let coeffs = Self::get_lagrange_coefficients(t, shares)?;
        let plain_shares = shares.iter().map(|s| s.value).collect::<Vec<_>>();
        let res = coeffs
            .iter()
            .zip(plain_shares.iter())
            .fold(C::zero(), |acc, (c, s)| acc + (*s * *c));
        Ok(res)
    }

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

    /// Returns the coefficients of the polynomial.
    pub fn as_vec(&self) -> &Vec<C> {
        &self.0
    }
}

/// Scalar operations.

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

impl<C: GroupElement + MultiScalarMul> Poly<C> {
    /// Given at least `t` polynomial evaluations, it will recover the polynomial's
    /// constant term
    pub fn recover_c0_msm(t: u32, shares: &[Eval<C>]) -> Result<C, FastCryptoError> {
        let coeffs = Self::get_lagrange_coefficients(t, shares)?;
        let plain_shares = shares.iter().map(|s| s.value).collect::<Vec<_>>();
        let res = C::multi_scalar_mul(&coeffs, &plain_shares).expect("sizes match");
        Ok(res)
    }
}
