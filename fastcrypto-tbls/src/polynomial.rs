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
use itertools::{Either, Itertools};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::HashSet;
use std::mem::swap;
use std::ops::{Add, AddAssign, Div, Mul, SubAssign};

/// Types

pub type Eval<A> = IndexedValue<A>;

/// A polynomial that is using a scalar for the variable x and a generic
/// element for the coefficients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poly<C>(Vec<C>);

pub type PrivatePoly<C> = Poly<<C as GroupElement>::ScalarType>;
pub type PublicPoly<C> = Poly<C>;

/// Vector related operations.

impl<C: GroupElement> Poly<C> {
    /// Returns the degree of the polynomial
    pub fn degree(&self) -> usize {
        // e.g. c_0 + c_1 * x + c_2 * x^2 + c_3 * x^3
        // ^ 4 coefficients correspond to a 3rd degree poly
        self.0.len() - 1
    }

    fn reduce(&mut self) {
        while self.0.len() > 1 && self.0.last() == Some(&C::zero()) {
            self.0.pop();
        }
    }
}

impl<C: GroupElement> From<Vec<C>> for Poly<C> {
    fn from(c: Vec<C>) -> Self {
        if c.is_empty() {
            return Self::zero();
        }
        let mut p = Self(c);
        p.reduce();
        p
    }
}

impl<C: GroupElement> AddAssign<&Self> for Poly<C> {
    fn add_assign(&mut self, other: &Self) {
        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| *a += *b);
        // if we have a smaller degree we can copy the rest
        if self.0.len() < other.0.len() {
            self.0.extend_from_slice(&other.0[self.0.len()..]);
        }
        self.reduce();
    }
}

impl<C: Scalar> Mul<&C> for Poly<C> {
    type Output = Poly<C>;

    fn mul(self, rhs: &C) -> Self::Output {
        Poly::from(self.0.into_iter().map(|c| c * rhs).collect_vec())
    }
}

impl<C: Scalar> Mul<&Poly<C>> for &Poly<C> {
    type Output = Poly<C>;

    fn mul(self, rhs: &Poly<C>) -> Poly<C> {
        if self.is_zero() || rhs.is_zero() {
            return Poly::zero();
        }
        let mut result = vec![C::zero(); self.degree() + rhs.degree() + 1];
        for (i, a) in self.0.iter().enumerate() {
            for (j, b) in rhs.0.iter().enumerate() {
                result[i + j] += *a * *b;
            }
        }
        Poly::from(result)
    }
}

impl<C: GroupElement> Add<&Poly<C>> for Poly<C> {
    type Output = Poly<C>;

    fn add(mut self, rhs: &Poly<C>) -> Poly<C> {
        self += rhs;
        self
    }
}

/// GroupElement operations.

impl<C: GroupElement> Poly<C> {
    /// Returns a polynomial with the zero element.
    pub fn zero() -> Self {
        Self::from(vec![C::zero()])
    }

    pub fn one() -> Self {
        Self::from(vec![C::generator()])
    }

    // TODO: Some of the functions/steps below may be executed many times in practice thus cache can be
    // used to improve efficiency (e.g., eval(i) may be called with the same index every time a partial
    // signature from party i is verified).

    /// Evaluates the polynomial at the specified value.
    pub fn eval(&self, i: ShareIndex) -> Eval<C> {
        // Use Horner's Method to evaluate the polynomial.
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

    // Multiply using u128 if possible, otherwise just convert one element to the group element and return the other.
    pub(crate) fn fast_mult(x: u128, y: u128) -> Either<(C::ScalarType, u128), u128> {
        if x.leading_zeros() >= (128 - y.leading_zeros()) {
            Either::Right(x * y)
        } else {
            Either::Left((C::ScalarType::from(x), y))
        }
    }

    // Expects exactly t unique shares.
    fn get_lagrange_coefficients_for_c0(
        t: u16,
        mut shares: impl Iterator<Item = impl Borrow<Eval<C>>>,
    ) -> FastCryptoResult<Vec<C::ScalarType>> {
        let mut ids_set = HashSet::new();
        let (shares_size_lower, shares_size_upper) = shares.size_hint();
        let indices = shares.try_fold(
            Vec::with_capacity(shares_size_upper.unwrap_or(shares_size_lower)),
            |mut vec, s| {
                // Check for duplicates.
                if !ids_set.insert(s.borrow().index) {
                    return Err(FastCryptoError::InvalidInput); // expected unique ids
                }
                vec.push(s.borrow().index.get() as u128);
                Ok(vec)
            },
        )?;
        if indices.len() != t as usize {
            return Err(FastCryptoError::InvalidInput);
        }

        let full_numerator = indices.iter().fold(C::ScalarType::generator(), |acc, i| {
            acc * C::ScalarType::from(*i)
        });

        let mut coeffs = Vec::new();
        for i in &indices {
            let mut negative = false;
            let (mut denominator, remaining) = indices.iter().filter(|j| *j != i).fold(
                (C::ScalarType::from(*i), 1u128),
                |(prev_acc, remaining), j| {
                    let diff = if i > j {
                        negative = !negative;
                        i - j
                    } else {
                        // i < j (but not equal)
                        j - i
                    };
                    debug_assert_ne!(diff, 0);
                    let either = Self::fast_mult(remaining, diff);
                    match either {
                        Either::Left((remaining_as_scalar, diff)) => {
                            (prev_acc * remaining_as_scalar, diff)
                        }
                        Either::Right(new_remaining) => (prev_acc, new_remaining),
                    }
                },
            );
            debug_assert_ne!(remaining, 0);
            denominator = denominator * C::ScalarType::from(remaining);
            if negative {
                denominator = -denominator;
            }
            // TODO: Consider returning full_numerator and dividing once outside instead of here per iteration.
            let coeff = full_numerator / denominator;
            coeffs.push(coeff.expect("safe since i != j"));
        }
        Ok(coeffs)
    }

    /// Given exactly `t` polynomial evaluations, it will recover the polynomial's constant term.
    /// For group elements better use recover_c0_msm.
    pub fn recover_c0(
        t: u16,
        shares: impl Iterator<Item = impl Borrow<Eval<C>>> + Clone,
    ) -> FastCryptoResult<C> {
        let coeffs = Self::get_lagrange_coefficients_for_c0(t, shares.clone())?;
        let plain_shares = shares.map(|s| s.borrow().value);
        let res = coeffs
            .iter()
            .zip(plain_shares)
            .fold(C::zero(), |acc, (c, s)| acc + (s * *c));
        Ok(res)
    }

    /// Checks if a given share is valid.
    pub fn verify_share(&self, idx: ShareIndex, share: &C::ScalarType) -> FastCryptoResult<()> {
        let e = C::generator() * share;
        let pub_eval = self.eval(idx);
        if pub_eval.value == e {
            Ok(())
        } else {
            Err(FastCryptoError::InvalidInput)
        }
    }

    /// Return the constant term of the polynomial.
    pub fn c0(&self) -> &C {
        &self.0[0]
    }

    pub fn coefficient(&self, i: usize) -> &C {
        if i >= self.0.len() {
            panic!(
                "Index out of bounds: requested {}, but polynomial has degree {}",
                i,
                self.degree()
            );
        }
        &self.0[i]
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
    pub fn rand<R: AllowedRng>(degree: u16, rng: &mut R) -> Self {
        let coeffs: Vec<C> = (0..=degree).map(|_| C::rand(rng)).collect();
        Self::from(coeffs)
    }

    /// Returns a new polynomial of the given degree where the constant term is
    /// fixed to `c0` and the rest of the coefficients are sampled at random.
    pub fn rand_fixed_c0<R: AllowedRng>(degree: u16, c0: C, rng: &mut R) -> Self {
        let mut coeffs = Self::rand(degree, rng).0;
        coeffs[0] = c0;
        Self::from(coeffs)
    }

    /// Commits the scalar polynomial to the group and returns a polynomial over
    /// the group.
    pub fn commit<P: GroupElement<ScalarType = C>>(&self) -> Poly<P> {
        let commits = self
            .0
            .iter()
            .map(|c| P::generator() * c)
            .collect::<Vec<P>>();

        Poly::<P>::from(commits)
    }

    /// Given a set of shares with unique indices, compute what the value of the interpolated polynomial is at the given index.
    /// Returns an error if the input is invalid (e.g., empty or duplicate indices).
    ///
    /// This is faster than first recovering the polynomial and then evaluating it at the given index.
    pub fn interpolate_at_index(
        index: ShareIndex,
        points: &[Eval<C>],
    ) -> FastCryptoResult<Eval<C>> {
        if points.is_empty() {
            return Err(FastCryptoError::InvalidInput);
        }
        if !points.iter().map(|p| p.index).all_unique() {
            return Err(FastCryptoError::InvalidInput);
        }
        let x = C::from(index.get() as u128);

        // Convert indices to scalars for interpolation.
        let indices = points
            .iter()
            .map(|p| C::from(p.index.get() as u128))
            .collect::<Vec<_>>();

        let value = C::sum(indices.iter().enumerate().map(|(j, x_j)| {
            points[j].value
                * C::product(
                    indices
                        .iter()
                        .filter(|x_i| *x_i != x_j)
                        .map(|x_i| ((x - x_i) / (*x_j - x_i)).expect("Divisor is never zero")),
                )
        }));

        Ok(Eval { index, value })
    }

    /// Given a set of shares with unique indices, compute the polynomial that
    /// goes through all the points. The degree of the resulting polynomial is
    /// at most `points.len() - 1`.
    /// Returns an error if the input is invalid (e.g., empty or duplicate indices).
    pub fn interpolate(points: &[Eval<C>]) -> FastCryptoResult<Poly<C>> {
        if points.is_empty() || !points.iter().map(|p| p.index).all_unique() {
            return Err(FastCryptoError::InvalidInput);
        }
        let result = points
            .iter()
            .map(|p_j| {
                let x_j = C::from(p_j.index.get() as u128);
                points
                    .iter()
                    .filter(|p_i| p_i.index != p_j.index)
                    .map(|p_i| {
                        let x_i = C::from(p_i.index.get() as u128);
                        Poly::from(vec![-x_i, C::generator()])
                            * &(x_j - x_i).inverse().expect("Divisor is never zero")
                    })
                    .fold(Poly::<C>::one(), |product, factor| &product * &factor)
                    * &p_j.value
            })
            .fold(Poly::zero(), |acc, p| acc + &p);
        Ok(result)
    }
}

impl<C: GroupElement + MultiScalarMul> Poly<C> {
    /// Given exactly `t` polynomial evaluations, it will recover the polynomial's
    /// constant term.
    pub(crate) fn recover_c0_msm(
        t: u16,
        shares: impl Iterator<Item = impl Borrow<Eval<C>>> + Clone,
    ) -> Result<C, FastCryptoError> {
        let coeffs = Self::get_lagrange_coefficients_for_c0(t, shares.clone())?;
        let plain_shares = shares.map(|s| s.borrow().value).collect::<Vec<_>>();
        let res = C::multi_scalar_mul(&coeffs, &plain_shares).expect("sizes match");
        Ok(res)
    }
}

struct Monomial<C> {
    coefficient: C,
    degree: usize,
}

impl<C: Scalar> Div<&Self> for Monomial<C> {
    type Output = FastCryptoResult<Monomial<C>>;

    fn div(self, rhs: &Self) -> Self::Output {
        if self.degree < rhs.degree {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(Monomial {
            coefficient: (self.coefficient / rhs.coefficient)?,
            degree: self.degree - rhs.degree,
        })
    }
}

impl<C: GroupElement> AddAssign<&Monomial<C>> for Poly<C> {
    fn add_assign(&mut self, rhs: &Monomial<C>) {
        if self.0.len() <= rhs.degree {
            self.0.resize(rhs.degree + 1, C::zero());
        }
        self.0[rhs.degree] += rhs.coefficient;
        self.reduce();
    }
}

impl<C: GroupElement> SubAssign<Poly<C>> for Poly<C> {
    fn sub_assign(&mut self, rhs: Poly<C>) {
        if self.0.len() < rhs.0.len() {
            self.0.resize(rhs.0.len(), C::zero());
        }
        for (a, b) in self.0.iter_mut().zip(&rhs.0) {
            *a -= *b;
        }
        self.reduce();
    }
}

impl<C: Scalar> Mul<&Monomial<C>> for &Poly<C> {
    type Output = Poly<C>;

    fn mul(self, rhs: &Monomial<C>) -> Poly<C> {
        if rhs.coefficient == C::zero() {
            return Poly::zero();
        }
        let mut result = vec![C::zero(); self.degree() + rhs.degree + 1];
        for (i, coefficient) in self.0.iter().enumerate() {
            result[i + rhs.degree] = *coefficient * rhs.coefficient;
        }
        Poly::from(result)
    }
}

impl<C: Scalar> Poly<C> {
    pub(crate) fn is_zero(&self) -> bool {
        self.0 == vec![C::zero()]
    }

    fn lead(&self) -> Monomial<C> {
        if self.is_zero() {
            return Monomial {
                coefficient: C::zero(),
                degree: 0,
            };
        }
        Monomial {
            coefficient: *self.0.last().unwrap(),
            degree: self.degree(),
        }
    }

    /// Divide self by divisor, returning the quotient and remainder.
    /// Returns an error if divisor is zero.
    pub fn div_rem(&self, divisor: &Poly<C>) -> FastCryptoResult<(Poly<C>, Poly<C>)> {
        if divisor.is_zero() {
            return Err(FastCryptoError::InvalidInput);
        }
        let mut remainder = self.clone();
        let mut quotient = Self::zero();
        while !remainder.is_zero() && remainder.degree() >= divisor.degree() {
            // TODO: The divisor lead is always the same, so we can precompute its inverse.
            let tmp = (remainder.lead() / &divisor.lead())?;
            quotient += &tmp;
            remainder -= divisor * &tmp;
        }
        Ok((quotient, remainder))
    }

    /// Compute the extended GCD of two polynomials.
    /// Returns (g, x, y, s, t) such that g = self * x + other * y.
    ///
    pub fn partial_extended_gcd(
        &self,
        other: &Poly<C>,
        degree_bound: usize,
    ) -> FastCryptoResult<(Poly<C>, Poly<C>, Poly<C>)> {
        let mut r = (self.clone(), other.clone());
        let mut s = (Poly::one(), Poly::zero());
        let mut t = (Poly::zero(), Poly::one());
        while r.0.degree() >= degree_bound && !r.1.is_zero() {
            let (q, r_new) = r.0.div_rem(&r.1)?;
            r = (r.1, r_new);

            s.0 -= &q * &s.1;
            t.0 -= &q * &t.1;

            swap(&mut s.0, &mut s.1);
            swap(&mut t.0, &mut t.1);
        }
        Ok((r.0, s.0, t.0))
    }

    pub fn extended_gcd(&self, other: &Poly<C>) -> FastCryptoResult<(Poly<C>, Poly<C>, Poly<C>)> {
        self.partial_extended_gcd(other, 0)
    }
}
