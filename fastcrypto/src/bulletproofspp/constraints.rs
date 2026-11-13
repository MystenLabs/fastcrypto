// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The constraints of the range circuit, folded with the challenges into the
//! public parts of the combined commitment. Notation and equation numbers
//! follow §4.3 and §5.1 of [ePrint 2026/2648](https://eprint.iacr.org/2026/2648),
//! with `M = params.m`, `D = params.d`, `N_d = params.n_d`, `nm = params.nm`.
//! Inputs are indexed `i = 1..M` as in the paper; the code uses `i - 1`.
//!
//! # Witness (22)
//!
//! For inputs `V_i = v_i*G + s_i*H_0` with digits `v_i = sum_t d_{i,t}*16^t`:
//! - `n_L[D(i-1)+t] = d_{i,t}`, zero for slots `>= N_d`;
//! - `n_R[D(i-1)+t] = r_{i,t} = (alpha + d_{i,t})^{-1}`, zero for slots `>= N_d`;
//! - `n_O[j-1] = m_j = |{(i,t) : d_{i,t} = j}|` for `j = 1..15` (`m_0` is
//!   implicit).
//!
//! # Constraints (4)–(7)
//!
//! - Hadamard (4), for each slot `k < N_d`: `n_L[k]*n_R[k] = 1 - alpha*n_R[k]`,
//!   and `n_L[k]*n_R[k] = 0` on the padding;
//! - value link (5), for each input: `sum_t 16^t*n_L[D(i-1)+t] = u_i`, the
//!   `G`-coordinate of `V_i` (21);
//! - set membership (6): `sum_{k<N_d} n_R[k] + sum_{j=1}^{15}
//!   j/(alpha(alpha+j))*m_j = N_d/alpha`;
//! - shape (7), for each input: every coordinate of `V_i` other than `u_i` on
//!   `G` and `h_{i,0}` on `H_0` is zero.
//!
//! # Value row (29)
//!
//! The `T^3` coefficient of the polynomial `f(T)` of the combined commitment is
//! ```text
//! f[T^3] = sum_i lambda^{i-1}*L_i + E_0 + lambda^M*S
//!          - 4*sum_{k,i} lambda^{M(k+1)+1+(i-1)}*n_{V_i,k}
//!          - 2*sum_{m=1..7,i} lambda^{g_m+(i-1)}*h_{i,m}
//! ```
//! with `L_i`, `E_0`, `S` as in (30). Each family of rows is folded at its own
//! powers of `lambda` and `mu`, so `f[T^3] = 0` for random challenges only if
//! every row holds.

use crate::bulletproofspp::circuit::CircuitParams;
use crate::bulletproofspp::crs::{BASE, H_LEN};
use crate::bulletproofspp::laurent::Laurent;
use crate::bulletproofspp::util::*;
use crate::error::FastCryptoResult;
use crate::groups::ristretto255::RistrettoScalar;
use crate::groups::{AdditiveGroup, Scalar};
use itertools::iterate;

type S = RistrettoScalar;

/// The public data (23), computed from the challenges alone.
pub(crate) struct Constraints {
    /// Norm weights `(mu, mu^2, ..., mu^{nm})`.
    pub(crate) norm_weights: Vec<S>,
    /// `c_{n,L}[D(i-1)+t] = lambda^{i-1}*16^t / mu^{D(i-1)+t+1}`; zero for
    /// slots `>= N_d`.
    cn_l: Vec<S>,
    /// `c_{n,R}[k] = lambda^M / mu^{k+1} + alpha`; zero for slots `>= N_d`.
    cn_r: Vec<S>,
    /// `c_{n,O}[k] = (k+1)*lambda^M / (alpha(alpha+k+1)*mu^{k+1})` for
    /// `k <= 14`; zero above.
    cn_o: Vec<S>,
    /// `c_{n,V}[k] = lambda^{M(k+1)+1} / mu^{k+1}`.
    cn_v: Vec<S>,
    /// `c_{l,V} = (0, lambda^{g_1}, ..., lambda^{g_7})`, `g_m = M(nm+m)+1`.
    pub(crate) cl_v: Vec<S>,
    /// `lambda_al = N_d*lambda^M / alpha`.
    pub(crate) lambda_al: S,
    /// `mu_am = sum_{k=1}^{N_d} mu^k`.
    pub(crate) mu_am: S,
    /// `(1, lambda, ..., lambda^M)`.
    pub(crate) lambdas: Vec<S>,
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
        // Only the lambda-powers that are used: `lambda^0..lambda^M` and the
        // shape-row powers `shape[j-1] = lambda^{M*j+1}`, `j = 1..=nm+7`.
        let lambdas = power_vector(lambda, m + 1);
        let lam_m = lambdas[m];
        let shape: Vec<S> = iterate(lambda * lam_m, |x| x * lam_m)
            .take(nm + H_LEN - 1)
            .collect();
        let base = S::from(BASE);

        let mut norm_weights = Vec::with_capacity(nm);
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
            norm_weights.push(mu_pow);
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
            .map(|k| alpha * (alpha + S::from(k as u64 + 1)) * norm_weights[k])
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
            norm_weights,
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

    /// `p_n(T) = c_{n,V} + T*c_{n,R} + T^2*c_{n,L} + delta^{-1}*T^3*c_{n,O}` (24).
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
}

/// The value row (29) for inputs on the `(G, H_0)`-plane and blinding with
/// the zero pattern (22), computed directly from (30): `values` are the `u_i`,
/// `n_l`, `n_r`, `n_o` the norm vectors. Written for readability, not speed:
/// it only serves to test that [Constraints::new] matches the paper.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn value_row(
    params: &CircuitParams,
    alpha: S,
    mu: S,
    lambda: S,
    values: &[S],
    n_l: &[S],
    n_r: &[S],
    n_o: &[S],
) -> S {
    let &CircuitParams { m, d, n_d, nm, .. } = params;
    let pow = |x: S, e: usize| (0..e).fold(one(), |acc, _| acc * x);
    fn sum(it: impl Iterator<Item = S>) -> S {
        it.fold(S::zero(), |acc, x| acc + x)
    }
    let two = S::from(2u64);

    // L_i = 2u_i - 2*sum_t 16^t*n_L[D(i-1)+t], weighted by lambda^{i-1}.
    let l = sum((0..m).map(|i| {
        let digits = sum((0..d).map(|t| pow(S::from(BASE), t) * n_l[d * i + t]));
        pow(lambda, i) * two * (values[i] - digits)
    }));

    // E_0 = -2*sum_{k<N_d} mu^{k+1}(n_L n_R + alpha n_R - 1)
    //       - 2*sum_{k>=N_d} mu^{k+1} n_L n_R.
    let e_0 = -sum((0..nm).map(|k| {
        let row = n_l[k] * n_r[k]
            + if k < n_d {
                alpha * n_r[k] - one()
            } else {
                S::zero()
            };
        two * pow(mu, k + 1) * row
    }));

    // S = 2(N_d/alpha - sum_{k<N_d} n_R[k] - sum_j j/(alpha(alpha+j))*n_O[j-1]).
    let s = two
        * (S::from(n_d as u64) * alpha.inverse().unwrap()
            - sum(n_r[..n_d].iter().copied())
            - sum((1..BASE as usize).map(|j| {
                let j_s = S::from(j as u64);
                j_s * n_o[j - 1] * (alpha * (alpha + j_s)).inverse().unwrap()
            })));

    l + e_0 + pow(lambda, m) * s
}
