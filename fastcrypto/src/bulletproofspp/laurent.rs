// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Laurent polynomials `sum_i a_i*T^i` in a formal variable `T`, with scalar
//! or vector coefficients.

use crate::bulletproofspp::util::{hadamard, inner_product, one, vec_add, vec_scalar_mul};
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::RistrettoScalar;
use crate::groups::{GroupElement, Scalar};
use std::ops::{Add, Sub};

type S = RistrettoScalar;

/// The Laurent polynomial `sum_i coeffs[i]*T^{low+i}`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Laurent<C> {
    low: i32,
    coeffs: Vec<C>,
}

impl<C: Coefficient> Laurent<C> {
    /// `sum_i coeffs[i]*T^{low+i}`.
    pub(crate) fn new(low: i32, coeffs: Vec<C>) -> Self {
        assert!(!coeffs.is_empty());
        Self { low, coeffs }
    }

    /// `c*T^power`.
    pub(crate) fn monomial(power: i32, c: C) -> Self {
        Self::new(power, vec![c])
    }

    /// The sum `sum_i c_i*T^{p_i}` of the `terms` `(p_i, c_i)`. Panics if
    /// there are none.
    pub(crate) fn from_terms(terms: impl IntoIterator<Item = (i32, C)>) -> Self {
        terms
            .into_iter()
            .map(|(power, c)| Self::monomial(power, c))
            .reduce(Add::add)
            .expect("at least one term")
    }

    /// The coefficient of `T^power`, zero if out of range.
    pub(crate) fn coeff(&self, power: i32) -> C {
        usize::try_from(power - self.low)
            .ok()
            .and_then(|i| self.coeffs.get(i))
            .cloned()
            .unwrap_or_else(|| self.coeffs[0].scale(S::zero()))
    }

    /// The highest power.
    fn degree(&self) -> i32 {
        self.low + self.coeffs.len() as i32 - 1
    }

    /// `s` times this polynomial.
    pub(crate) fn scale(&self, s: S) -> Self {
        Self::new(self.low, self.coeffs.iter().map(|c| c.scale(s)).collect())
    }

    /// The value at `T = x`. Fails if `x` is zero and there are negative powers.
    pub(crate) fn eval(&self, x: S) -> FastCryptoResult<C> {
        let base = if self.low < 0 { x.inverse()? } else { x };
        let mut x_pow = (0..self.low.unsigned_abs()).fold(one(), |acc, _| acc * base);
        let mut result = self.coeffs[0].scale(x_pow);
        for c in &self.coeffs[1..] {
            x_pow *= x;
            result = result.add(&c.scale(x_pow));
        }
        Ok(result)
    }
}

#[cfg(test)]
impl<C: Coefficient + PartialEq> Laurent<C> {
    /// Whether every coefficient is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|c| *c == c.scale(S::zero()))
    }
}

impl<C: Coefficient> Add for Laurent<C> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let low = self.low.min(other.low);
        let coeffs = (low..=self.degree().max(other.degree()))
            .map(|p| self.coeff(p).add(&other.coeff(p)))
            .collect();
        Self::new(low, coeffs)
    }
}

impl<C: Coefficient> Sub for Laurent<C> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self + other.scale(-one())
    }
}

impl Laurent<Vec<S>> {
    /// The scalar polynomial `<self(T), other(T)>`.
    pub(crate) fn inner_product(&self, other: &Self) -> Laurent<S> {
        let mut coeffs = vec![S::zero(); self.coeffs.len() + other.coeffs.len() - 1];
        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in other.coeffs.iter().enumerate() {
                coeffs[i + j] += inner_product(a, b);
            }
        }
        Laurent::new(self.low + other.low, coeffs)
    }

    /// The scalar polynomial `<self(T) ∘ weights, other(T)>`.
    pub(crate) fn weighted_inner_product(&self, other: &Self, weights: &[S]) -> Laurent<S> {
        let weighted = Laurent::new(
            self.low,
            self.coeffs.iter().map(|a| hadamard(a, weights)).collect(),
        );
        weighted.inner_product(other)
    }
}

/// A coefficient of a [Laurent] polynomial: a scalar or a vector of scalars.
pub(crate) trait Coefficient: Clone {
    fn add(&self, other: &Self) -> Self;
    fn scale(&self, s: S) -> Self;
}

impl Coefficient for S {
    fn add(&self, other: &Self) -> Self {
        *self + other
    }

    fn scale(&self, s: S) -> Self {
        *self * s
    }
}

impl Coefficient for Vec<S> {
    fn add(&self, other: &Self) -> Self {
        vec_add(self, other)
    }

    fn scale(&self, s: S) -> Self {
        vec_scalar_mul(s, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: u64) -> S {
        S::from(x)
    }

    #[test]
    fn test_eval() {
        // 2*T^{-1} + 3 + 5*T^2 at T = 2: 1 + 3 + 20.
        let p = Laurent::new(-1, vec![s(2), s(3), s(0), s(5)]);
        assert_eq!(p.eval(s(2)).unwrap(), s(24));
        assert!(p.eval(s(0)).is_err());
        // No negative powers: T = 0 is fine.
        assert_eq!(Laurent::monomial(0, s(7)).eval(s(0)).unwrap(), s(7));
    }

    #[test]
    fn test_from_terms() {
        // Repeated powers add up; gaps are zero.
        let p = Laurent::from_terms([(2, s(1)), (-1, s(2)), (2, s(3))]);
        assert_eq!(p, Laurent::new(-1, vec![s(2), s(0), s(0), s(4)]));
    }

    #[test]
    fn test_add_sub() {
        let p = Laurent::new(-2, vec![s(1), s(2)]);
        let q = Laurent::monomial(1, s(4));
        assert_eq!(
            p.clone() + q.clone(),
            Laurent::new(-2, vec![s(1), s(2), s(0), s(4)])
        );
        assert_eq!((p.clone() + q.clone() - q).coeff(1), s(0));
        assert!((p.clone() - p.clone()).is_zero());
        assert!(!p.is_zero());
        assert_eq!(p.coeff(-3), s(0));
        assert_eq!(p.coeff(-1), s(2));
    }

    #[test]
    fn test_inner_products_match_evaluation() {
        let a = Laurent::new(
            -1,
            vec![vec![s(1), s(2)], vec![s(3), s(4)], vec![s(5), s(6)]],
        );
        let b = Laurent::new(2, vec![vec![s(7), s(8)], vec![s(9), s(10)]]);
        let weights = vec![s(11), s(12)];
        let x = s(13);
        let (a_x, b_x) = (a.eval(x).unwrap(), b.eval(x).unwrap());
        assert_eq!(
            a.inner_product(&b).eval(x).unwrap(),
            inner_product(&a_x, &b_x)
        );
        assert_eq!(
            a.weighted_inner_product(&b, &weights).eval(x).unwrap(),
            inner_product(&hadamard(&a_x, &weights), &b_x)
        );
    }
}
