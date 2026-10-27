// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Laurent polynomials in the evaluation variable `T`, with scalar or
//! scalar-vector coefficients. The range circuit states every quantity of
//! the combined commitment `C(T)` as one of these, so powers of `T` are
//! addressed by their exponent rather than by an offset array index.

use crate::groups::ristretto255::RistrettoScalar;
use crate::groups::GroupElement;

use crate::bulletproofspp::util::one;

type S = RistrettoScalar;

/// `tau^p` for any integer `p`, given `tau_inv = tau^{-1}`.
pub(crate) fn pow(tau: S, tau_inv: S, p: i32) -> S {
    let (base, e) = if p < 0 { (tau_inv, -p) } else { (tau, p) };
    (0..e).fold(one(), |acc, _| acc * base)
}

/// A coefficient type: scalars, or scalar vectors of a common length.
pub(crate) trait Coefficient: Clone {
    /// The zero of the same shape as `self`.
    fn zero_like(&self) -> Self;

    /// `self += s * other`.
    fn add_scaled(&mut self, other: &Self, s: S);

    /// `s * self`.
    fn scaled(&self, s: S) -> Self;
}

// Scalar operations dominate the circuit's non-MSM work, and most weights
// are 1, so both impls skip the multiplication for `s = 1`.

impl Coefficient for S {
    fn zero_like(&self) -> Self {
        S::zero()
    }

    fn add_scaled(&mut self, other: &Self, s: S) {
        *self += other.scaled(s);
    }

    fn scaled(&self, s: S) -> Self {
        if s == one() {
            *self
        } else {
            s * self
        }
    }
}

impl Coefficient for Vec<S> {
    fn zero_like(&self) -> Self {
        vec![S::zero(); self.len()]
    }

    fn add_scaled(&mut self, other: &Self, s: S) {
        debug_assert_eq!(self.len(), other.len());
        if s == one() {
            for (x, y) in self.iter_mut().zip(other) {
                *x += y;
            }
        } else {
            // Skip zero entries: the constraint vector c(T) is sparse.
            for (x, y) in self.iter_mut().zip(other) {
                if *y != S::zero() {
                    *x += s * y;
                }
            }
        }
    }

    fn scaled(&self, s: S) -> Self {
        if s == one() {
            self.clone()
        } else {
            self.iter().map(|x| s * x).collect()
        }
    }
}

/// `sum_p coeffs[p - low] * T^p` over the powers `low..low + coeffs.len()`.
/// Never empty; the range grows as terms are added.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Laurent<C> {
    low: i32,
    coeffs: Vec<C>,
}

impl<C: Coefficient> Laurent<C> {
    /// The monomial `c * T^p`.
    pub(crate) fn monomial(p: i32, c: C) -> Self {
        Laurent {
            low: p,
            coeffs: vec![c],
        }
    }

    /// The sum of the monomials `c * T^p` over `terms`, which must not be
    /// empty.
    pub(crate) fn from_terms(terms: impl IntoIterator<Item = (i32, C)>) -> Self {
        let mut terms = terms.into_iter();
        let (p, c) = terms.next().expect("at least one term");
        let mut poly = Self::monomial(p, c);
        for (p, c) in terms {
            poly.add_term(p, &c, one());
        }
        poly
    }

    fn high(&self) -> i32 {
        self.low + self.coeffs.len() as i32 - 1
    }

    /// The coefficient of `T^p`, or `None` outside the stored range.
    pub(crate) fn coeff(&self, p: i32) -> Option<&C> {
        usize::try_from(p - self.low)
            .ok()
            .and_then(|i| self.coeffs.get(i))
    }

    /// `(p, coefficient of T^p)` over the stored range.
    pub(crate) fn terms(&self) -> impl Iterator<Item = (i32, &C)> {
        (self.low..).zip(&self.coeffs)
    }

    /// `self += s * c * T^p`. A term outside the stored range is placed
    /// directly, zero-filling any gap.
    pub(crate) fn add_term(&mut self, p: i32, c: &C, s: S) {
        let zeros = |n: i32| (0..n).map(|_| c.zero_like());
        if p < self.low {
            let mut coeffs = vec![c.scaled(s)];
            coeffs.extend(zeros(self.low - p - 1));
            coeffs.append(&mut self.coeffs);
            self.coeffs = coeffs;
            self.low = p;
        } else if p > self.high() {
            self.coeffs.extend(zeros(p - self.high() - 1));
            self.coeffs.push(c.scaled(s));
        } else {
            self.coeffs[(p - self.low) as usize].add_scaled(c, s);
        }
    }

    /// `self += s * other`.
    pub(crate) fn add_poly(&mut self, other: &Self, s: S) {
        for (p, c) in other.terms() {
            self.add_term(p, c, s);
        }
    }

    /// The coefficient-wise image under `f`.
    pub(crate) fn map<D>(&self, f: impl Fn(&C) -> D) -> Laurent<D> {
        Laurent {
            low: self.low,
            coeffs: self.coeffs.iter().map(f).collect(),
        }
    }

    /// The evaluation at `T = tau`, given `tau_inv = tau^{-1}`.
    pub(crate) fn eval(&self, tau: S, tau_inv: S) -> C {
        let mut tau_pow = pow(tau, tau_inv, self.low);
        let mut acc = self.coeffs[0].scaled(tau_pow);
        for c in &self.coeffs[1..] {
            tau_pow *= tau;
            acc.add_scaled(c, tau_pow);
        }
        acc
    }
}

impl Laurent<S> {
    /// The coefficient of `T^p`, zero outside the stored range.
    pub(crate) fn at(&self, p: i32) -> S {
        self.coeff(p).copied().unwrap_or_else(S::zero)
    }
}

impl Laurent<Vec<S>> {
    /// The scalar polynomial `<self(T), other(T)>`: plain inner products of
    /// the coefficient vectors, collected by power. Only the nonzero entries
    /// of `self` are visited, so a sparse left operand (the constraint
    /// vector `c(T)`) or a vanishing coefficient is cheap.
    pub(crate) fn inner_product(&self, other: &Self) -> Laurent<S> {
        let mut out = Laurent::monomial(self.low + other.low, S::zero());
        for (p, a) in self.terms() {
            let support: Vec<usize> = (0..a.len()).filter(|&i| a[i] != S::zero()).collect();
            if support.is_empty() {
                continue;
            }
            for (q, b) in other.terms() {
                debug_assert_eq!(a.len(), b.len());
                let ip = support.iter().fold(S::zero(), |acc, &i| acc + a[i] * b[i]);
                out.add_term(p + q, &ip, one());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulletproofspp::util;
    use crate::groups::Scalar;

    fn s(x: u64) -> S {
        S::from(x)
    }

    #[test]
    fn test_pow() {
        let tau = s(3);
        let tau_inv = tau.inverse().unwrap();
        assert_eq!(pow(tau, tau_inv, 0), one());
        assert_eq!(pow(tau, tau_inv, 3), s(27));
        assert_eq!(pow(tau, tau_inv, -2) * s(9), one());
    }

    #[test]
    fn test_add_term_grows_both_ways() {
        // 2*T + 5*T^{-2} + 7*T^3
        let mut p = Laurent::monomial(1, s(2));
        p.add_term(-2, &s(5), one());
        p.add_term(3, &s(7), one());
        p.add_term(1, &s(1), s(3)); // T coefficient 2 + 3 = 5
        assert_eq!(
            p.terms().map(|(e, c)| (e, *c)).collect::<Vec<_>>(),
            vec![
                (-2, s(5)),
                (-1, s(0)),
                (0, s(0)),
                (1, s(5)),
                (2, s(0)),
                (3, s(7)),
            ]
        );
        assert_eq!(p.at(4), S::zero());
        assert_eq!(p.at(-3), S::zero());

        let tau = s(2);
        let tau_inv = tau.inverse().unwrap();
        // 5/4 + 10 + 56
        assert_eq!(
            p.eval(tau, tau_inv),
            s(5) * tau_inv * tau_inv + s(10) + s(56)
        );
    }

    #[test]
    fn test_vector_inner_product_matches_evaluation() {
        let mut rng = rand::thread_rng();
        let mut rand_vec = || (0..3).map(|_| S::rand(&mut rng)).collect::<Vec<_>>();
        let a = Laurent::from_terms([(-1, rand_vec()), (2, rand_vec())]);
        let b = Laurent::from_terms([(0, rand_vec()), (1, rand_vec()), (3, rand_vec())]);
        let ab = a.inner_product(&b);

        let tau = S::rand(&mut rng);
        let tau_inv = tau.inverse().unwrap();
        assert_eq!(
            ab.eval(tau, tau_inv),
            util::inner_product(&a.eval(tau, tau_inv), &b.eval(tau, tau_inv))
        );
        assert_eq!(ab.terms().next().unwrap().0, -1);
        assert_eq!(
            ab.at(5),
            util::inner_product(a.coeff(2).unwrap(), b.coeff(3).unwrap())
        );
    }
}
