// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Most of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::types::{to_scalar, IndexedValue, ShareIndex};
use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::iter::{once, repeat_with};
use std::mem::swap;
use std::num::NonZeroU16;
use std::ops::{Add, AddAssign, Div, Index, Mul, MulAssign, SubAssign};

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
    /// Returns an upper bound for the degree of the polynomial.
    /// The returned number is equal to the size of the underlying coefficient vector - 1,
    /// and in case some of the leading elements are zero, the actual degree will be smaller.
    /// See also [Poly::degree].
    pub fn degree_bound(&self) -> usize {
        // e.g. c_0 + c_1 * x + c_2 * x^2 + c_3 * x^3
        // ^ 4 coefficients correspond to a 3rd degree poly
        self.0.len() - 1
    }

    /// Returns the degree of the polynomial.
    pub fn degree(&self) -> usize {
        self.0.iter().rposition(|&c| c != C::zero()).unwrap_or(0)
    }

    /// Removes leading zero coefficients.
    pub(crate) fn into_reduced(mut self) -> Self {
        self.0.truncate(self.degree() + 1);
        self
    }
}

impl<C> From<Vec<C>> for Poly<C> {
    fn from(c: Vec<C>) -> Self {
        Self(c)
    }
}

impl<C: GroupElement> AddAssign<&Self> for Poly<C> {
    fn add_assign(&mut self, other: &Self) {
        self.0.iter_mut().zip(&other.0).for_each(|(a, b)| *a += *b);
        // if we have a smaller degree we can copy the rest
        if self.0.len() < other.0.len() {
            self.0.extend_from_slice(&other.0[self.0.len()..]);
        }
    }
}

impl<C: Scalar> Mul<&C> for Poly<C> {
    type Output = Poly<C>;

    fn mul(self, rhs: &C) -> Self::Output {
        Poly(self.0.into_iter().map(|c| c * rhs).collect())
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

impl<C: GroupElement> SubAssign<Poly<C>> for Poly<C> {
    fn sub_assign(&mut self, rhs: Poly<C>) {
        if self.0.len() < rhs.0.len() {
            self.0.resize(rhs.0.len(), C::zero());
        }
        for (a, b) in self.0.iter_mut().zip(&rhs.0) {
            *a -= *b;
        }
    }
}

/// GroupElement operations.

impl<C: GroupElement> Poly<C> {
    /// Returns a polynomial with the zero element.
    pub fn zero() -> Self {
        Self::from(vec![C::zero()])
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.iter().all(|&c| c == C::zero())
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
        let xi: C::ScalarType = to_scalar(i);
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

    /// Evaluate the polynomial for all x in the range [1,...,m].
    /// If m is sufficiently larger than the degree, this is faster than just evaluating at each point.
    /// Returns an [InvalidInput] error if `self.degree() >= u16::MAX` or if `m` is `0` or `u16::MAX`.
    ///
    /// This is based on an algorithm in section 4.6.4 of Knuth's "The Art of Computer Programming".
    pub fn eval_range(&self, m: u16) -> FastCryptoResult<EvalRange<C>> {
        if m == 0 || m == u16::MAX || self.degree() >= u16::MAX as usize {
            return Err(FastCryptoError::InvalidInput);
        }
        Ok(EvalRange(
            PolynomialEvaluator::new(
                self,
                NonZeroU16::new(1).unwrap(),
                NonZeroU16::new(1).unwrap(),
            )?
            .take(m as usize)
            .map(|e| e.value)
            .collect_vec(),
        ))
    }

    /// Multiply x.1 with y using u128s if possible, otherwise convert x.1 to the group element and multiply.
    /// Invariant: If res = fast_mult(x1, x2, y) then x.0 * x.1 * y = res.0 * res.1.
    pub(crate) fn fast_mult(x: (C::ScalarType, u128), y: u128) -> (C::ScalarType, u128) {
        if x.1.leading_zeros() >= (128 - y.leading_zeros()) {
            (x.0, x.1 * y)
        } else {
            (x.0 * C::ScalarType::from(x.1), y)
        }
    }

    /// Compute initial * \prod factors.
    pub(crate) fn fast_product(
        initial: C::ScalarType,
        factors: impl Iterator<Item = u128>,
    ) -> C::ScalarType {
        let (result, remaining) = factors.fold((initial, 1), |acc, factor| {
            debug_assert_ne!(factor, 0);
            Self::fast_mult(acc, factor)
        });
        debug_assert_ne!(remaining, 0);
        result * C::ScalarType::from(remaining)
    }

    pub(crate) fn get_lagrange_coefficients_for_c0(
        t: u16,
        shares: impl Iterator<Item = impl Borrow<Eval<C>>>,
    ) -> FastCryptoResult<(C::ScalarType, Vec<C::ScalarType>)> {
        Self::get_lagrange_coefficients_for(0, t, shares)
    }

    /// Expects exactly t unique shares.
    /// Returns an error if x is one of the indices.
    fn get_lagrange_coefficients_for(
        x: u128,
        t: u16,
        shares: impl Iterator<Item = impl Borrow<Eval<C>>>,
    ) -> FastCryptoResult<(C::ScalarType, Vec<C::ScalarType>)> {
        let indices = shares.map(|s| s.borrow().index.get() as u128).collect_vec();
        if !indices.iter().all_unique() || indices.len() != t as usize || indices.contains(&x) {
            return Err(FastCryptoError::InvalidInput);
        }

        let x_as_scalar = C::ScalarType::from(x);
        let full_numerator = C::ScalarType::product(
            indices
                .iter()
                .map(|i| C::ScalarType::from(*i) - x_as_scalar),
        );

        Ok((
            full_numerator,
            indices
                .iter()
                .map(|i| {
                    let mut negative = false;
                    let mut denominator = Self::fast_product(
                        C::ScalarType::from(*i) - x_as_scalar,
                        indices.iter().filter(|j| *j != i).map(|j| {
                            if i > j {
                                negative = !negative;
                                i - j
                            } else {
                                // i < j (but not equal)
                                j - i
                            }
                        }),
                    );
                    if negative {
                        denominator = -denominator;
                    }
                    denominator.inverse().expect("safe since i != j")
                })
                .collect(),
        ))
    }

    /// Given exactly `t` polynomial evaluations, it will recover the polynomial's constant term.
    /// For group elements better use recover_c0_msm.
    pub fn recover_c0(
        t: u16,
        shares: impl Iterator<Item = impl Borrow<Eval<C>>> + Clone,
    ) -> FastCryptoResult<C> {
        let coeffs = Self::get_lagrange_coefficients_for_c0(t, shares.clone())?;
        Ok(C::sum(
            shares
                .map(|s| s.borrow().value)
                .zip(coeffs.1)
                .map(|(c, s)| c * s),
        ) * coeffs.0)
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

    /// Consume the polynomial and return the constant term.
    pub fn into_c0(self) -> C {
        self.0[0]
    }

    pub fn coefficient(&self, i: usize) -> &C {
        if i >= self.0.len() {
            panic!(
                "Index out of bounds: requested {}, but polynomial has degree {}",
                i,
                self.degree_bound()
            );
        }
        &self.0[i]
    }

    /// Returns the i'th coefficient for this polynomial.
    /// If i is larger than the degree, this just returns a zero.
    pub fn safe_coefficient(&self, i: usize) -> C {
        if i >= self.0.len() {
            return C::zero();
        }
        self.0[i]
    }

    /// Returns the coefficients of the polynomial.
    pub fn as_vec(&self) -> &Vec<C> {
        &self.0
    }

    pub fn to_vec(self) -> Vec<C> {
        self.0
    }

    fn sum(terms: impl Iterator<Item = Poly<C>>) -> Poly<C> {
        terms.fold(Poly::zero(), |sum, term| sum + &term)
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
        self.0
            .iter()
            .map(|c| P::generator() * c)
            .collect_vec()
            .into()
    }

    /// Given a set of shares with unique indices, compute what the value of the interpolated polynomial is at the given index.
    /// Returns an error if the input is invalid (e.g., empty or duplicate indices).
    ///
    /// This is faster than first recovering the polynomial and then evaluating it at the given index.
    pub fn recover_at(index: ShareIndex, points: &[Eval<C>]) -> FastCryptoResult<Eval<C>> {
        // If the index we're looking for is already given, we can return that
        if let Some(point) = points.iter().find(|p| p.index == index) {
            return Ok(point.clone());
        }
        let lagrange_coefficients = Self::get_lagrange_coefficients_for(
            index.get() as u128,
            points.len() as u16,
            points.iter(),
        )?;
        let value = C::sum(
            lagrange_coefficients
                .1
                .iter()
                .zip(points.iter().map(|p| p.value))
                .map(|(c, s)| s * c),
        ) * lagrange_coefficients.0;
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

        // Compute the full numerator polynomial: (x - x_1)(x - x_2)...(x - x_t)
        let mut full_numerator = Poly::one();
        for point in points {
            full_numerator *= MonicLinear(-to_scalar::<C>(point.index));
        }

        Ok(Poly::sum(points.iter().enumerate().map(|(i, p_i)| {
            let x_i = p_i.index.get() as u128;
            let mut negative = false;
            let mut denominator = Self::fast_product(
                C::ScalarType::generator(),
                points
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, p_j)| {
                        let x_j = p_j.index.get() as u128;
                        if x_i > x_j {
                            x_i - x_j
                        } else {
                            negative = !negative;
                            x_j - x_i
                        }
                    }),
            );
            if negative {
                denominator = -denominator;
            }
            (&full_numerator / MonicLinear(-to_scalar::<C>(p_i.index)))
                * &(p_i.value / denominator).unwrap()
        }))
        .into_reduced())
    }

    /// Returns the leading term of the polynomial.
    /// If the polynomial is zero, returns a monomial with coefficient zero and degree zero.
    fn lead(&self) -> Monomial<C> {
        if self.is_zero() {
            return Monomial::zero();
        }
        let degree = self.degree();
        Monomial {
            coefficient: self.0[degree],
            degree,
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

        // Function to divide a term by the leading term of the divisor.
        let divider = divisor.lead().divider();

        while !remainder.is_zero() && remainder.degree() >= divisor.degree() {
            let tmp = divider(&remainder.lead());
            quotient += &tmp;
            remainder -= divisor * &tmp;
            remainder = remainder.into_reduced();
        }
        Ok((quotient, remainder))
    }

    /// Compute the extended GCD of two polynomials.
    /// Returns (g, x, y, s, t) such that g = self * x + other * y.
    /// The loop stops when the degree of g is less than degree_bound.
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
            r.0 = r.0.into_reduced();

            t.0 -= &q * &t.1;
            s.0 -= &q * &s.1;

            swap(&mut t.0, &mut t.1);
            swap(&mut s.0, &mut s.1);
        }
        Ok((r.0, s.0, t.0))
    }

    pub fn extended_gcd(&self, other: &Poly<C>) -> FastCryptoResult<(Poly<C>, Poly<C>, Poly<C>)> {
        self.partial_extended_gcd(other, 1)
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
        let res = C::multi_scalar_mul(&coeffs.1, &plain_shares).expect("sizes match") * coeffs.0;
        Ok(res)
    }

    /// Scale each of the polynomials with the corresponding scalar and compute the sum.
    /// Returns an error if the two slices does not have the same length.
    pub fn multi_scalar_mul(
        polynomials: &[Poly<C>],
        scalars: &[C::ScalarType],
    ) -> FastCryptoResult<Poly<C>> {
        if polynomials.len() != scalars.len() {
            return Err(FastCryptoError::InvalidInput);
        }
        if polynomials.is_empty() {
            return Ok(Poly::zero());
        }
        let degree = polynomials
            .iter()
            .map(Poly::degree)
            .max()
            .expect("Is not empty");
        Ok(Poly(
            (0..=degree)
                .map(|i| {
                    C::multi_scalar_mul(
                        scalars,
                        &polynomials
                            .iter()
                            .map(|p| p.safe_coefficient(i))
                            .collect_vec(),
                    )
                    .unwrap()
                })
                .collect_vec(),
        ))
    }
}

/// This represents a monomial, e.g., 3x^2, where 3 is the coefficient and 2 is the degree.
struct Monomial<C> {
    coefficient: C,
    degree: usize,
}

impl<C: GroupElement> AddAssign<&Monomial<C>> for Poly<C> {
    fn add_assign(&mut self, rhs: &Monomial<C>) {
        if self.0.len() <= rhs.degree {
            self.0.resize(rhs.degree + 1, C::zero());
        }
        self.0[rhs.degree] += rhs.coefficient;
    }
}

impl<C: Scalar> Mul<&Monomial<C>> for &Poly<C> {
    type Output = Poly<C>;

    fn mul(self, rhs: &Monomial<C>) -> Poly<C> {
        if rhs.coefficient == C::zero() {
            return Poly::zero();
        }
        let mut result = vec![C::zero(); self.degree_bound() + rhs.degree + 1];
        for (i, coefficient) in self.0.iter().enumerate() {
            result[i + rhs.degree] = *coefficient * rhs.coefficient;
        }
        Poly::from(result)
    }
}

impl<C: Scalar> Monomial<C> {
    /// Returns a closure which on input `x` computes the division `x / self`.
    /// Panics if the degree of `x` is smaller than `self` or if `self` is zero.
    fn divider(self) -> impl Fn(&Monomial<C>) -> Monomial<C> {
        let inverse = self.coefficient.inverse().unwrap();
        move |p: &Monomial<C>| Monomial {
            coefficient: p.coefficient * inverse,
            degree: p.degree - self.degree,
        }
    }

    fn zero() -> Self {
        Monomial {
            coefficient: C::zero(),
            degree: 0,
        }
    }
}

/// Represents a monic linear polynomial of the form x + c.
pub(crate) struct MonicLinear<C>(pub C);

impl<C: Scalar> MulAssign<MonicLinear<C>> for Poly<C> {
    fn mul_assign(&mut self, rhs: MonicLinear<C>) {
        if rhs.0 == C::zero() || self.is_zero() {
            *self = Poly::zero();
            return;
        }
        self.0.push(*self.0.last().unwrap());
        for i in (1..self.0.len() - 1).rev() {
            self.0[i] = self.0[i] * rhs.0 + self.0[i - 1];
        }
        self.0[0] = self.0[0] * rhs.0;
    }
}

impl<C: Scalar> Div<MonicLinear<C>> for &Poly<C> {
    type Output = Poly<C>;

    fn div(self, rhs: MonicLinear<C>) -> Self::Output {
        let mut result = self.0[1..].to_vec();
        for i in (0..result.len() - 1).rev() {
            result[i] = result[i] - result[i + 1] * rhs.0;
        }
        Poly::from(result)
    }
}

#[cfg(test)]
pub(crate) fn poly_eq<C: GroupElement>(a: &Poly<C>, b: &Poly<C>) -> bool {
    a.0[..(a.degree() + 1)] == b.0[..(b.degree() + 1)]
}

/// This can evaluate a polynomial at points in an arithmetic progression, e.g., x0, x0+h, x0+2h, ...
/// This is generally faster when evaluating more points than the degree of the polynomial.
/// The algorithm used is from section 4.6.4 in Knuth's "Art of Computer Programming".
pub(crate) struct PolynomialEvaluator<C> {
    state: Vec<C>,
    first: bool,
    index: NonZeroU16,
    step: NonZeroU16,
}

impl<C: GroupElement> PolynomialEvaluator<C> {
    /// Create a new evaluator.
    /// Returns an [InvalidInput] error if `initial + step * polynomial.degree()` cannot be represented as an u16.
    /// Once created, calling [Self::next] will return the evaluation for the next element in the arithmetic progression until the input cannot be represented as an u16.
    fn new(polynomial: &Poly<C>, initial: NonZeroU16, step: NonZeroU16) -> FastCryptoResult<Self> {
        // Compute initial values (see exercise 7 in 4.6.4 of TAOCP)
        let points = (0..=polynomial.degree())
            .map(|i| {
                u16::try_from(i)
                    .ok()
                    .and_then(|i| i.checked_mul(step.get()))
                    .and_then(|istep| istep.checked_add(initial.get()))
                    .and_then(NonZeroU16::new)
                    .map(|x| polynomial.eval(x).value)
                    .ok_or(FastCryptoError::InvalidInput)
            })
            .collect::<FastCryptoResult<Vec<_>>>()?;

        Ok(Self {
            state: Self::compute_state(points),
            first: true,
            index: initial,
            step,
        })
    }

    /// Given evaluations on 0, 1, ..., degree, this returns an evaluator on points 1, 2, ...
    pub(crate) fn simple_from_evaluations(points: Vec<C>) -> PolynomialEvaluator<C> {
        let mut state = Self::compute_state(points);

        // One iteration to skip zero
        Self::iterate_state(&mut state);

        Self {
            state,
            first: true,
            index: NonZeroU16::new(1).unwrap(),
            step: NonZeroU16::new(1).unwrap(),
        }
    }

    fn compute_state(points: Vec<C>) -> Vec<C> {
        let mut state = points;
        for k in 1..state.len() {
            for j in (k..state.len()).rev() {
                state[j] = state[j] - state[j - 1];
            }
        }
        state
    }

    fn iterate_state(state: &mut [C]) {
        for j in 0..state.len() - 1 {
            state[j] += state[j + 1]
        }
    }
}

impl<C: GroupElement> Iterator for PolynomialEvaluator<C> {
    type Item = Eval<C>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first {
            self.first = false;
        } else {
            self.index = match self.index.checked_add(self.step.get()) {
                Some(new_index) => new_index,
                None => return None,
            };
            Self::iterate_state(&mut self.state);
        }
        Some(Eval {
            index: self.index,
            value: self.state[0],
        })
    }
}

/// This holds the output of [Poly::eval_range].
#[derive(Clone, Debug)]
pub struct EvalRange<C>(Vec<C>);

impl<C: Clone> EvalRange<C> {
    /// Return all evaluations in this range as a vector, ordered by the indices.
    pub fn to_vec(self) -> Vec<Eval<C>> {
        self.into_iter().collect_vec()
    }

    pub fn take(self, n: u16) -> EvalRange<C> {
        EvalRange(self.0.into_iter().take(n as usize).collect_vec())
    }

    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get the evaluation point for the given index. Panics if it is out of range.
    pub fn get_eval(&self, index: ShareIndex) -> Eval<C>
    where
        C: Clone,
    {
        Eval {
            index,
            value: self[index].clone(),
        }
    }
}

impl<C> Index<ShareIndex> for EvalRange<C> {
    type Output = C;

    fn index(&self, index: ShareIndex) -> &Self::Output {
        &self.0[index.get() as usize - 1]
    }
}

impl<C> IntoIterator for EvalRange<C> {
    type Item = Eval<C>;
    type IntoIter = std::iter::Map<
        core::iter::Enumerate<std::vec::IntoIter<C>>,
        fn((usize, C)) -> IndexedValue<C>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter().enumerate().map(|(i, value)| Eval {
            index: NonZeroU16::new(i as u16 + 1).unwrap(),
            value,
        })
    }
}

impl<C: GroupElement> Add for EvalRange<C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        EvalRange(
            self.0
                .iter()
                .zip_eq(rhs.0)
                .map(|(a, b)| b + a)
                .collect_vec(),
        )
    }
}

impl<C: GroupElement> Mul<&C::ScalarType> for EvalRange<C> {
    type Output = Self;

    fn mul(self, rhs: &C::ScalarType) -> Self::Output {
        Self(self.0.iter().map(|a| *a * rhs).collect_vec())
    }
}

/// Create `n` shares for a given secret such that `t` shares can reconstruct the secret.
/// Panics if t == 0 or t > n.
pub(crate) fn create_secret_sharing<C: Scalar>(
    rng: &mut impl AllowedRng,
    secret: C,
    t: u16,
    n: u16,
) -> EvalRange<C> {
    assert!(t > 0 && t <= n);

    // The first evaluation point (one zero) is given by the secret, and the remaining are random.
    let evaluations_points = once(secret)
        .chain(repeat_with(|| C::rand(rng)))
        .take(t as usize)
        .collect_vec();

    // Compute evaluations of the polynomial for 1, 2, ..., n using a simple Evaluator
    let evaluator = PolynomialEvaluator::simple_from_evaluations(evaluations_points);
    EvalRange(evaluator.take(n as usize).map(|e| e.value).collect())
}
