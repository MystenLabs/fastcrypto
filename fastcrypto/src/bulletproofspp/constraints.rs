// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The constraints of the range circuit, folded with the challenges into the
//! public parts of the combined commitment.
//!
//! # Witness
//!
//! For `m` inputs `V_i = v_i*G + s_i*H_0`, `i = 0..m`, with `d` base-16 digits
//! each, the prover commits norm vectors of length `nm >= n_d = m*d`:
//! - digits `d_k`: slot `k = d*i + t` holds digit `t` of `v_i`, zero padding
//!   for `k >= n_d`;
//! - reciprocals `r_k`: honestly `(alpha + d_k)^{-1}` for `k < n_d` and zero
//!   padding;
//! - multiplicities `m_j`, `j = 1..15`, in slot `j - 1`: honestly the number
//!   of digits equal to `j` (`m_0` is implicit).
//!
//! # Constraints
//!
//! Each of these rows must be zero:
//! - value link, for each input `i`: `v_i - sum_t 16^t*d_{d*i+t}`;
//! - set membership: `sum_{k<n_d} r_k + sum_{j=1}^{15} j*m_j/(alpha*(alpha+j))
//!   - n_d/alpha`, that is `sum_k 1/(alpha+d_k) = sum_{j=0}^{15} m_j/(alpha+j)`
//!   with `m_0 = n_d - sum_{j>=1} m_j`;
//! - Hadamard, for each slot `k`: `d_k*r_k + alpha*r_k - 1` if `k < n_d`, and
//!   `d_k*r_k` on the padding;
//! - shape, for each input `i`: every coordinate of `V_i` other than those on
//!   `G` and `H_0`.
//!
//! The value link, set membership and Hadamard rows are folded into
//! ```text
//! F = sum_i lambda^i*(value link i) - lambda^m*(set membership)
//!     - sum_k mu^{k+1}*(Hadamard k)
//! ```
//! and for inputs on the `(G, H_0)`-plane, `F` is half the `T^3` coefficient of
//! the error polynomial. The shape row for coordinate `G_vec[k]` of `V_i` is
//! folded at `lambda^{m(k+1)+1+i}`, and for coordinate `H_p`, `p = 1..7`, at
//! `lambda^{m(nm+p)+1+i}`.

use crate::bulletproofspp::circuit::CircuitParams;
use crate::bulletproofspp::crs::{BASE, H_LEN};
use crate::bulletproofspp::laurent::Laurent;
use crate::bulletproofspp::util::*;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::RistrettoScalar;
use crate::groups::{GroupElement, Scalar};
use itertools::iterate;

type S = RistrettoScalar;

/// The public vectors of the folded constraints, computed from the challenges
/// alone.
pub(crate) struct Constraints {
    /// Norm weights `(mu, mu^2, ..., mu^nm)`.
    bar_mu: Vec<S>,
    /// Value links: slot `k = d*i+t` holds `lambda^i * 16^t / mu^{k+1}`; zero
    /// at the padding slots `k >= n_d`.
    cn_l: Vec<S>,
    /// Set membership + Hadamard: `cn_r[k] = lambda^m / mu^{k+1} + alpha`;
    /// zero at the padding slots.
    cn_r: Vec<S>,
    /// Multiplicities: `cn_o[k] = (k+1)*lambda^m / (alpha*(alpha+k+1)*mu^{k+1})`
    /// for `k <= 14`; zero above (`m_0` is implicit).
    cn_o: Vec<S>,
    /// G_vec shape rows: `cn_v[k] = lambda^{m(k+1)+1} / mu^{k+1}`, all slots
    /// (padding included).
    cn_v: Vec<S>,
    /// H shape rows: `cl_v[p] = lambda^{m(nm+p)+1}` for `p = 1..7`, zero first
    /// entry exempting the honest blinding on `H_0`.
    cl_v: Vec<S>,
    /// Constant terms: `lambda_al = n_d * lambda^m / alpha` (set membership)
    /// and `mu_am = sum_{k<n_d} mu^{k+1}` (Hadamard).
    lambda_al: S,
    mu_am: S,
    /// `(1, lambda, ..., lambda^m)`.
    lambdas: Vec<S>,
}

impl Constraints {
    pub(crate) fn new(
        params: &CircuitParams,
        alpha: S,
        mu: S,
        lambda: S,
    ) -> FastCryptoResult<Self> {
        let &CircuitParams { m, d, n_d, nm, .. } = params;
        let mu_inv = mu.inverse()?;
        // Only the lambda-powers that are used: `lambda^0..lambda^m` and the
        // shape-row powers `shape[j-1] = lambda^{m*j+1}`, `j = 1..=nm+7`.
        let lambdas = power_vector(lambda, m + 1);
        let lam_m = lambdas[m];
        let shape: Vec<S> = iterate(lambda * lam_m, |x| x * lam_m)
            .take(nm + H_LEN - 1)
            .collect();
        let base = S::from(BASE);

        let mut bar_mu = Vec::with_capacity(nm);
        let mut cn_l = Vec::with_capacity(nm);
        let mut cn_r = Vec::with_capacity(nm);
        let mut cn_v = Vec::with_capacity(nm);
        let mut mu_am = S::zero();
        let mut mu_pow = one(); // mu^{k+1}, built incrementally
        let mut mu_inv_pow = one(); // mu^{-(k+1)}
        let mut base_pow = one(); // 16^t, reset per value block
        for k in 0..nm {
            mu_pow *= mu;
            mu_inv_pow *= mu_inv;
            bar_mu.push(mu_pow);
            if k < n_d {
                mu_am += mu_pow;
                if k % d == 0 {
                    base_pow = one();
                }
                cn_l.push(lambdas[k / d] * base_pow * mu_inv_pow);
                base_pow *= base;
                cn_r.push(lam_m * mu_inv_pow + alpha);
            } else {
                cn_l.push(S::zero());
                cn_r.push(S::zero());
            }
            cn_v.push(shape[k] * mu_inv_pow);
        }

        // cn_o via one batch inversion of the denominators alpha*(alpha+j)*mu^j.
        let bm1 = (BASE - 1) as usize;
        let denominators: Vec<S> = (0..bm1)
            .map(|k| alpha * (alpha + S::from(k as u64 + 1)) * bar_mu[k])
            .collect();
        let inverses = batch_invert(&denominators)?;
        let mut cn_o: Vec<S> = (0..bm1)
            .map(|k| S::from(k as u64 + 1) * lam_m * inverses[k])
            .collect();
        cn_o.resize(nm, S::zero());

        let lambda_al = S::from(n_d as u64) * lam_m * alpha.inverse()?;

        let mut cl_v = vec![S::zero()];
        cl_v.extend((1..H_LEN).map(|p| shape[nm + p - 1]));

        Ok(Self {
            bar_mu,
            cn_l,
            cn_r,
            cn_o,
            cn_v,
            cl_v,
            lambda_al,
            mu_am,
            lambdas,
        })
    }

    /// The norm weights `(mu, mu^2, ..., mu^nm)`.
    pub(crate) fn norm_weights(&self) -> &[S] {
        &self.bar_mu
    }

    /// The weights `(1, lambda, ..., lambda^{m-1})` of the inputs.
    pub(crate) fn input_weights(&self) -> &[S] {
        &self.lambdas[..self.lambdas.len() - 1]
    }

    /// The H shape rows: the constant part of the linear constraint vector.
    pub(crate) fn shape_h(&self) -> &[S] {
        &self.cl_v
    }

    /// The public part of the norm vector `n(T)`:
    /// `p_n(T) = cn_v + T*cn_r + T^2*cn_l + T^3*delta^{-1}*cn_o`.
    pub(crate) fn p_n(&self, delta_inv: S) -> Laurent<Vec<S>> {
        Laurent::new(
            0,
            vec![
                self.cn_v.clone(),
                self.cn_r.clone(),
                self.cn_l.clone(),
                vec_scalar_mul(delta_inv, &self.cn_o),
            ],
        )
    }

    /// The constant `2*(lambda_al + mu_am)` in the public part of the `G`
    /// coordinate, `p_s(T) = |p_n(T)|^2_mu + p_s_constant()*T^3`.
    pub(crate) fn p_s_constant(&self) -> S {
        S::from(2u64) * (self.lambda_al + self.mu_am)
    }
}

/// `F` from the module doc, folded directly from the rows: `values` are the
/// `v_i`, `digits`, `reciprocals` and `multiplicities` the norm vectors.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn fold(
    params: &CircuitParams,
    alpha: S,
    mu: S,
    lambda: S,
    values: &[S],
    digits: &[S],
    reciprocals: &[S],
    multiplicities: &[S],
) -> S {
    let &CircuitParams { m, d, n_d, nm, .. } = params;
    let pow = |x: S, e: usize| (0..e).fold(one(), |acc, _| acc * x);

    let value_links = (0..m).map(|i| {
        let digit_sum = (0..d).fold(S::zero(), |acc, t| {
            acc + pow(S::from(BASE), t) * digits[d * i + t]
        });
        pow(lambda, i) * (values[i] - digit_sum)
    });

    let set_membership = reciprocals[..n_d].iter().fold(S::zero(), |acc, r| acc + r)
        + (1..BASE as usize).fold(S::zero(), |acc, j| {
            let j_s = S::from(j as u64);
            acc + j_s * multiplicities[j - 1] * (alpha * (alpha + j_s)).inverse().unwrap()
        })
        - S::from(n_d as u64) * alpha.inverse().unwrap();

    let hadamard = (0..nm).map(|k| {
        let row = digits[k] * reciprocals[k]
            + if k < n_d {
                alpha * reciprocals[k] - one()
            } else {
                S::zero()
            };
        pow(mu, k + 1) * row
    });

    value_links.fold(S::zero(), |acc, x| acc + x)
        - pow(lambda, m) * set_membership
        - hadamard.fold(S::zero(), |acc, x| acc + x)
}
