// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shape-constrained reciprocal range circuit (the spec's fully-constrained
//! exact-form protocol, batched per its appendix). Proves, for M Pedersen
//! commitments `V_i = v_i*G + s_i*H_0`, that every `v_i` lies in
//! `[0, 2^n_bits)` within one transcript. The prover commits digits,
//! reciprocals, and shared multiplicities, reduces the circuit to one
//! norm-linear relation at a random evaluation point, and delegates to the
//! norm-linear argument.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::groups::{GroupElement, MixedMultiScalarMul, MultiScalarMul, Scalar};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;

use crate::bulletproofspp::crs::{dims, Generators, Range, BASE, H_LEN};
use crate::bulletproofspp::norm_linear::{self, NormLinearProof};
use crate::bulletproofspp::transcript::BpppTranscript;
use crate::bulletproofspp::util::*;

type S = RistrettoScalar;

/// tau-powers of the blinding constraint entries `hat_c_r`,
/// slots 1..7. The gap at 4 keeps `C_S` out of the value row.
const CR_POWERS: [i32; 7] = [-1, 1, 2, 3, 5, 6, 7];

/// Largest `log2(nm)` a decoded proof may claim; bounds the shape search in
/// [CircuitProof::from_bytes] far above any practical statement (2^32 norm
/// slots is 2^28 values of 64 bits).
const MAX_LOG_NM: u32 = 32;

/// Circuit proof: the four commitments plus the norm-linear proof.
/// For 1x64: 4 + 6 group elements + 3 scalars = 416 bytes.
#[derive(Clone, Debug)]
pub(crate) struct CircuitProof {
    pub(crate) c_l: RistrettoPoint,
    pub(crate) c_o: RistrettoPoint,
    pub(crate) c_r: RistrettoPoint,
    pub(crate) c_s: RistrettoPoint,
    pub(crate) nl_proof: NormLinearProof,
}

impl CircuitProof {
    /// Serialize: `C_L, C_O, C_R, C_S`, then the norm-linear proof.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 * 32 + self.nl_proof.serialized_len());
        for point in [&self.c_l, &self.c_o, &self.c_r, &self.c_s] {
            bytes.extend(point.to_byte_array());
        }
        bytes.extend(self.nl_proof.to_bytes());
        bytes
    }

    /// Deserialize. The length of the norm-linear part selects the norm
    /// length `nm` (a power of two from `BASE` to `2^MAX_LOG_NM`), which
    /// fixes the proof shape; consistency with the statement is checked at
    /// verification.
    pub(crate) fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        if bytes.len() < 4 * 32 {
            return Err(FastCryptoError::InvalidInput);
        }
        let (head, tail) = bytes.split_at(4 * 32);
        let nm = (BASE.ilog2()..=MAX_LOG_NM)
            .map(|k| 1usize << k)
            .find(|&nm| NormLinearProof::serialized_len_for(H_LEN, nm) == tail.len())
            .ok_or(FastCryptoError::InvalidInput)?;
        let mut chunks = head.chunks_exact(32);
        Ok(CircuitProof {
            c_l: decode_next(&mut chunks)?,
            c_o: decode_next(&mut chunks)?,
            c_r: decode_next(&mut chunks)?,
            c_s: decode_next(&mut chunks)?,
            nl_proof: NormLinearProof::from_bytes(tail, H_LEN, nm)?,
        })
    }
}

/// Dimensions of a batched instance: `m` values in `range`, `d = bits/4`
/// digits per value, `n_d = m*d` digits overall, norm length
/// `nm = max(n_d, 16)` rounded to a power of two.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CircuitParams {
    pub(crate) range: Range,
    pub(crate) m: usize,
    pub(crate) d: usize,
    pub(crate) n_d: usize,
    pub(crate) nm: usize,
}

impl CircuitParams {
    /// `m` must be `>= 1`.
    pub(crate) fn new(range: Range, m: usize) -> FastCryptoResult<Self> {
        if m == 0 {
            return Err(FastCryptoError::InvalidInput);
        }
        let (d, n_d, nm) = dims(range, m);
        Ok(CircuitParams {
            range,
            m,
            d,
            n_d,
            nm,
        })
    }
}

/// Public constraint blocks, computed from the challenges alone.
/// One block per committed vector; the shape blocks `cn_v` and `cl_v` are
/// the exact-form addition. Every linear row is aggregated at its own power
/// of lambda: value link of `V_i` at `lambda^{i-1}`, shared set membership
/// at `lambda^M`, the shape row for norm coordinate `k` of `V_i` at
/// `lambda^{M(k+1)+1+(i-1)}`, and for H-coordinate `m` of `V_i` at
/// `lambda^{M(nm+m)+1+(i-1)}` — one band of M consecutive powers per
/// coordinate, one power per input.
struct Blocks {
    /// Norm weights `(mu, mu^2, ..., mu^nm)`.
    bar_mu: Vec<S>,
    /// Value links: slot `k = d*(i-1)+t` holds `lambda^{i-1} * 16^t / mu^{k+1}`;
    /// zero at the padding slots `k >= n_d`.
    cn_l: Vec<S>,
    /// Set membership + Hadamard: `cn_r[k] = lambda^M / mu^{k+1} + alpha`;
    /// zero at the padding slots.
    cn_r: Vec<S>,
    /// Multiplicities: `cn_o[k] = (k+1)*lambda^M / (alpha*(alpha+k+1)*mu^{k+1})`
    /// for `k <= 14`; zero above (`m_0` is implicit).
    cn_o: Vec<S>,
    /// G-side shape rows: `cn_v[k] = lambda^{M(k+1)+1} / mu^{k+1}`, all slots
    /// (padding included).
    cn_v: Vec<S>,
    /// H-side shape rows: `cl_v[p] = lambda^{M(nm+p)+1}` for `p = 1..7`, zero
    /// first entry exempting the honest blinding slot.
    cl_v: Vec<S>,
    /// Affine terms: `lambda_al = n_d * lambda^M / alpha`,
    /// `mu_am = sum_{k=1}^{n_d} mu^k` (Hadamard right-hand sides, real digit
    /// slots only).
    lambda_al: S,
    mu_am: S,
    /// `(1, lambda, ..., lambda^M)`: the per-value aggregation weights.
    /// Only `lambda^0..lambda^{M-1}` are read outside `compute_blocks`.
    lambdas: Vec<S>,
}

fn compute_blocks(params: &CircuitParams, alpha: S, mu: S, lambda: S) -> FastCryptoResult<Blocks> {
    let &CircuitParams { m, d, n_d, nm, .. } = params;
    let mu_inv = mu.inverse()?;
    // Only two families of lambda-powers are ever read: the per-value weights
    // `lambda^0..lambda^M`, and the shape-row powers `lambda^{M*j+1}` for
    // `j = 1..=nm+7`. The dense vector up to `lambda^{M(nm+8)}` that spans
    // both is quadratic in the batch size and ~99% unread, so build the two
    // families directly: `shape[j-1] = lambda^{M*j+1}`, stepping by lambda^M.
    let lambdas = power_vector(lambda, m + 1);
    let lam_m = lambdas[m];
    let mut shape = Vec::with_capacity(nm + 7);
    let mut shape_pow = lambda;
    for _ in 0..nm + 7 {
        shape_pow *= lam_m;
        shape.push(shape_pow);
    }
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

    Ok(Blocks {
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

impl Blocks {
    /// Coefficients of `p_s(T) = |p_n(T)|^2_mu + 2*(lambda_al + mu_am)*T^3`
    /// at powers `T^0..T^6`, where
    /// `p_n(T) = cn_v + T*cn_r + T^2*cn_l + T^3*delta^{-1}*cn_o`.
    /// Reference formulation kept for the test provers; production code
    /// evaluates `p_s(tau)` directly and cancels `|p_n|^2` inside `hat_f`.
    #[cfg(test)]
    fn ps_coefficients(&self, delta_inv: S) -> [S; 7] {
        let pn3 = vec_scalar_mul(delta_inv, &self.cn_o);
        let pn = [&self.cn_v, &self.cn_r, &self.cn_l, &pn3];
        let pn_weighted: Vec<Vec<S>> = pn.iter().map(|v| hadamard(v, &self.bar_mu)).collect();
        let mut ps = [S::zero(); 7];
        for i in 0..pn.len() {
            for j in i..pn.len() {
                let ip = inner_product(&pn_weighted[i], pn[j]);
                ps[i + j] += if i == j { ip } else { ip + ip };
            }
        }
        ps[3] += S::from(2u64) * (self.lambda_al + self.mu_am);
        ps
    }

    /// `p_n(tau)` as a vector (verifier side).
    fn pn_at(&self, tau: S, delta_inv: S) -> Vec<S> {
        let t2 = tau * tau;
        let t3di = t2 * tau * delta_inv;
        (0..self.bar_mu.len())
            .map(|k| self.cn_v[k] + tau * self.cn_r[k] + t2 * self.cn_l[k] + t3di * self.cn_o[k])
            .collect()
    }

    /// The linear constraint vector `c(tau) = hat_c_r(tau) + cl_v`:
    /// beta-weighted tau-monomials plus the constant H-side shape block
    /// (slot 8 carries only the shape entry).
    fn c_at(&self, tau: S, tau_inv: S, beta: S) -> Vec<S> {
        let tau_pows = power_vector(tau, 8);
        let mut c: Vec<S> = CR_POWERS
            .iter()
            .zip(&self.cl_v)
            .map(|(&a, &shape)| {
                let tau_pow = if a < 0 { tau_inv } else { tau_pows[a as usize] };
                beta * tau_pow + shape
            })
            .collect();
        c.push(self.cl_v[7]);
        c
    }
}

/// Norm-linear commitment `C_X = r[0]*G + <r[1..8] || l, H> + <n, G_vec>`.
/// `H_0..H_6` carry the blinding slots 1..7, `H_7` the linear witness. The
/// scalar layout matches the precomputed tables `[G, h_vec.., g_vec..]`.
fn commit(gens: &Generators, r: &[S], l: S, n: &[S]) -> FastCryptoResult<RistrettoPoint> {
    debug_assert_eq!(r.len(), H_LEN);
    debug_assert_eq!(n.len(), gens.g_vec.len());
    let mut scalars = Vec::with_capacity(1 + H_LEN + n.len());
    scalars.push(r[0]);
    scalars.extend(&r[1..H_LEN]);
    scalars.push(l);
    scalars.extend(n);
    gens.precomp.mixed_multi_scalar_mul(&scalars, &[], &[])
}

/// A blinding vector with the spec's zero pattern: random except at the
/// given positions, which keep blinding out of the value row and bound the
/// T-support of the error terms.
fn blinding_vector(rng: &mut impl AllowedRng, zeros: &[usize]) -> Vec<S> {
    (0..H_LEN)
        .map(|i| {
            if zeros.contains(&i) {
                S::zero()
            } else {
                S::rand(rng)
            }
        })
        .collect()
}

/// Little-endian base-16 digits of `value`, `d` of them.
fn decompose(value: u64, d: usize) -> Vec<u64> {
    let bits = BASE.ilog2();
    (0..d as u32)
        .map(|t| (value >> (bits * t)) & (BASE - 1))
        .collect()
}

/// Shared multiplicities `m_j = |{(i,t) : d_{i,t} = j}|` for `j = 1..15`
/// (`m_0` implicit).
fn multiplicities(digits: &[u64]) -> Vec<u64> {
    let mut m = vec![0u64; (BASE - 1) as usize];
    for &d in digits {
        if d > 0 {
            m[(d - 1) as usize] += 1;
        }
    }
    m
}

/// Prove that every `values[i]` lies in `[0, 2^n_bits)` under the Pedersen
/// commitments `V_i = values[i]*G + blindings[i]*H_0`, which are computed
/// here, absorbed into the transcript, and returned alongside the proof.
pub(crate) fn prove(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    params: &CircuitParams,
    rng: &mut impl AllowedRng,
    values: &[u64],
    blindings: &[S],
) -> FastCryptoResult<(CircuitProof, Vec<RistrettoPoint>)> {
    if values.len() != params.m
        || blindings.len() != params.m
        || gens.g_vec.len() != params.nm
        || values.iter().any(|&v| !params.range.is_in_range(v))
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let two = S::from(2u64);

    let v_commitments: Vec<RistrettoPoint> = values
        .iter()
        .zip(blindings)
        .map(|(&v, s)| {
            RistrettoPoint::multi_scalar_mul(&[S::from(v), *s], &[gens.g, gens.h_vec[0]])
        })
        .collect::<FastCryptoResult<_>>()?;

    transcript.domain_sep(b"bppp_circuit");
    for v in &v_commitments {
        transcript.append_point(b"V", v);
    }

    // Step 1: commit digits (C_L) and shared multiplicities (C_O). Slot
    // d*(i-1)+t holds digit t of value i; slots beyond n_d are zero.
    let digits: Vec<u64> = values
        .iter()
        .flat_map(|&v| decompose(v, params.d))
        .collect();
    let n_l = pad_to(
        &digits.iter().map(|&d| S::from(d)).collect::<Vec<_>>(),
        params.nm,
    );
    let mut n_o: Vec<S> = multiplicities(&digits)
        .iter()
        .map(|&m| S::from(m))
        .collect();
    n_o.resize(params.nm, S::zero());
    let r_o = blinding_vector(rng, &[4, 7]);
    let r_l = blinding_vector(rng, &[3, 6, 7]);
    let c_l = commit(gens, &r_l, S::zero(), &n_l)?;
    let c_o = commit(gens, &r_o, S::zero(), &n_o)?;
    transcript.append_point(b"C_L", &c_l);
    transcript.append_point(b"C_O", &c_o);

    // Step 2: reciprocal challenge, drawn after the digits and
    // multiplicities are committed.
    let alpha = transcript.challenge_scalar(b"alpha");

    // Step 3: reciprocals r_k = (alpha + d_k)^{-1} for the real digit slots
    // (C_R); padding slots stay zero.
    let recips = batch_invert(
        &digits
            .iter()
            .map(|&d| alpha + S::from(d))
            .collect::<Vec<_>>(),
    )?;
    let n_r = pad_to(&recips, params.nm);
    let r_r = blinding_vector(rng, &[2, 5, 6, 7]);
    let c_r = commit(gens, &r_r, S::zero(), &n_r)?;
    transcript.append_point(b"C_R", &c_r);

    // Step 4: constraint challenges.
    let rho = transcript.challenge_scalar(b"rho");
    let lambda = transcript.challenge_scalar(b"lambda");
    let beta = transcript.challenge_scalar(b"beta");
    let delta = transcript.challenge_scalar(b"delta");
    let mu = rho * rho;
    let delta_inv = delta.inverse()?;
    let blocks = compute_blocks(params, alpha, mu, lambda)?;

    // Step 5: masks, then solve the blinding r_S of C_S.
    let n_s: Vec<S> = (0..params.nm).map(|_| S::rand(rng)).collect();
    let l_s = S::rand(rng);
    // Rescaled aggregate input hat_V = 2*sum_i lambda^{i-1} V_i:
    // hat_v = 2*sum lambda^{i-1} v_i, r_V = (0, 2*sum lambda^{i-1} s_i, 0, ...).
    let v_hat = two
        * values.iter().enumerate().fold(S::zero(), |acc, (i, &v)| {
            acc + blocks.lambdas[i] * S::from(v)
        });
    let mut r_v = vec![S::zero(); H_LEN];
    r_v[1] = two
        * blindings
            .iter()
            .enumerate()
            .fold(S::zero(), |acc, (i, s)| acc + blocks.lambdas[i] * s);

    // Vector coefficients of n(T) at powers T^{-1}..T^3 (the honest
    // n_hat_V = 0, so T^3 carries only the public block).
    let n_poly: [Vec<S>; 5] = [
        n_s.clone(),
        vec_add(&vec_scalar_mul(delta, &n_o), &blocks.cn_v),
        vec_add(&n_l, &blocks.cn_r),
        vec_add(&n_r, &blocks.cn_l),
        vec_scalar_mul(delta_inv, &blocks.cn_o),
    ];

    // Error polynomial hat_f(T) = p_s(T) + hat_v*T^3 - |n(T)|^2_mu, Laurent
    // coefficients at T^{-2}..T^6 stored at index p+2. The public square
    // |p_n(T)|^2 inside p_s cancels against |n(T)|^2, leaving
    //   hat_f = (hat_v + 2*(lambda_al + mu_am))*T^3 - <w(T), n(T) + p_n(T)>_mu
    // with w = n - p_n the witness part (n_s, delta*n_o, n_l, n_r at
    // T^{-1}..T^2), so only the 4x5 witness-side products are computed.
    let w_weighted: [Vec<S>; 4] = [
        hadamard(&n_s, &blocks.bar_mu),
        hadamard(&vec_scalar_mul(delta, &n_o), &blocks.bar_mu),
        hadamard(&n_l, &blocks.bar_mu),
        hadamard(&n_r, &blocks.bar_mu),
    ];
    let n_plus_pn: [Vec<S>; 5] = [
        n_poly[0].clone(),
        vec_add(&n_poly[1], &blocks.cn_v),
        vec_add(&n_poly[2], &blocks.cn_r),
        vec_add(&n_poly[3], &blocks.cn_l),
        vec_scalar_mul(two, &n_poly[4]),
    ];
    let mut fh = [S::zero(); 9];
    fh[3 + 2] = v_hat + two * (blocks.lambda_al + blocks.mu_am);
    for (i, w) in w_weighted.iter().enumerate() {
        for (j, s) in n_plus_pn.iter().enumerate() {
            // powers: p_i = i - 1, p_j = j - 1, index (p_i + p_j) + 2 = i + j.
            fh[i + j] -= inner_product(w, s);
        }
    }
    // Value row: zero for a valid witness. This checks every block formula
    // at once.
    debug_assert_eq!(fh[3 + 2], S::zero(), "value row not zero");

    // known[p]: T^p coefficient of <c(T), l(T)> - r_0(T) restricted to the
    // committed material r_O, r_L, r_R, r_V (spec "Choosing r_S"). Slot j's
    // committed component at T^q meets beta*T^{a_j} at T^{a_j+q}, and the
    // constant shape entry cl_v[j] at T^q itself. Index p+2; sized for the
    // largest reachable power a_7 + 3 = 10.
    let mut known = [S::zero(); 13];
    for slot in 1..H_LEN {
        let committed = [
            (0i32, delta * r_o[slot]),
            (1, r_l[slot]),
            (2, r_r[slot]),
            (3, r_v[slot]),
        ];
        let a = CR_POWERS[slot - 1];
        for &(q, coefficient) in &committed {
            known[(a + q + 2) as usize] += beta * coefficient;
            known[(q + 2) as usize] += blocks.cl_v[slot - 1] * coefficient;
        }
    }
    known[2] -= delta * r_o[0];
    known[3] -= r_l[0];
    known[4] -= r_r[0];

    // Diagonal solve: r_S[j] cancels the error row at T^{a_j - 1}; slot 0
    // last, with factor -1 (not divided by beta), absorbing the T^{-1}
    // contributions (row index 1) of the already-solved r_S[2..8] and l_S
    // through the constant shape entries.
    let beta_inv = beta.inverse()?;
    let mut r_s = vec![S::zero(); H_LEN];
    for slot in 1..H_LEN {
        let p = CR_POWERS[slot - 1] - 1;
        r_s[slot] = (fh[(p + 2) as usize] - known[(p + 2) as usize]) * beta_inv;
    }
    let shape_sum = (2..H_LEN).fold(S::zero(), |acc, j| acc + blocks.cl_v[j - 1] * r_s[j]);
    r_s[0] = -(fh[1] - known[1] - shape_sum - blocks.cl_v[7] * l_s);

    let c_s = commit(gens, &r_s, l_s, &n_s)?;
    transcript.append_point(b"C_S", &c_s);

    // Step 6: evaluation point, drawn after every commitment.
    let tau = transcript.challenge_scalar(b"tau");

    // Step 7: evaluate the opening at tau and run the norm-linear argument.
    let tau_inv = tau.inverse()?;
    let t2 = tau * tau;
    let t3 = t2 * tau;
    let r_tau: Vec<S> = (0..H_LEN)
        .map(|i| tau_inv * r_s[i] + delta * r_o[i] + tau * r_l[i] + t2 * r_r[i] + t3 * r_v[i])
        .collect();
    let mut l_tau = r_tau[1..H_LEN].to_vec();
    l_tau.push(tau_inv * l_s);
    let n_tau: Vec<S> = (0..params.nm)
        .map(|k| {
            tau_inv * n_poly[0][k]
                + n_poly[1][k]
                + tau * n_poly[2][k]
                + t2 * n_poly[3][k]
                + t3 * n_poly[4][k]
        })
        .collect();
    let c_tau = blocks.c_at(tau, tau_inv, beta);

    let nl_proof = norm_linear::prove(transcript, gens, &c_tau, rho, &l_tau, &n_tau)?;

    Ok((
        CircuitProof {
            c_l,
            c_o,
            c_r,
            c_s,
            nl_proof,
        },
        v_commitments,
    ))
}

/// Verify a circuit proof against the Pedersen commitments `v_commitments`.
pub(crate) fn verify(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    params: &CircuitParams,
    proof: &CircuitProof,
    v_commitments: &[RistrettoPoint],
) -> FastCryptoResult<()> {
    if v_commitments.len() != params.m || gens.g_vec.len() != params.nm {
        return Err(FastCryptoError::InvalidInput);
    }
    transcript.domain_sep(b"bppp_circuit");
    for v in v_commitments {
        transcript.append_point(b"V", v);
    }
    transcript.append_point(b"C_L", &proof.c_l);
    transcript.append_point(b"C_O", &proof.c_o);
    let alpha = transcript.challenge_scalar(b"alpha");
    transcript.append_point(b"C_R", &proof.c_r);
    let rho = transcript.challenge_scalar(b"rho");
    let lambda = transcript.challenge_scalar(b"lambda");
    let beta = transcript.challenge_scalar(b"beta");
    let delta = transcript.challenge_scalar(b"delta");
    let mu = rho * rho;
    let delta_inv = delta.inverse()?;
    transcript.append_point(b"C_S", &proof.c_s);
    let tau = transcript.challenge_scalar(b"tau");
    let tau_inv = tau.inverse()?;
    let t2 = tau * tau;
    let t3 = t2 * tau;

    let blocks = compute_blocks(params, alpha, mu, lambda)?;
    let pn_tau = blocks.pn_at(tau, delta_inv);
    // p_s(tau) = |p_n(tau)|^2_mu + 2*(lambda_al + mu_am)*tau^3, evaluated
    // directly on pn_tau rather than via the coefficients of p_s(T).
    let ps_tau =
        weighted_norm(&pn_tau, mu) + S::from(2u64) * (blocks.lambda_al + blocks.mu_am) * t3;
    let c_tau = blocks.c_at(tau, tau_inv, beta);

    // Combined commitment, decomposed so it joins the norm-linear verifier's
    // single MSM (g_vec is touched only there):
    //   C(tau) = <p_n(tau), G_vec> + p_s(tau)*G
    //          + tau^{-1}*C_S + delta*C_O + tau*C_L + tau^2*C_R + tau^3*hat_V
    // with hat_V = 2*sum_i lambda^{i-1} V_i.
    let two_t3 = S::from(2u64) * t3;
    let mut extra = vec![
        (ps_tau, gens.g),
        (tau_inv, proof.c_s),
        (delta, proof.c_o),
        (tau, proof.c_l),
        (t2, proof.c_r),
    ];
    for (i, v) in v_commitments.iter().enumerate() {
        extra.push((two_t3 * blocks.lambdas[i], *v));
    }

    norm_linear::verify(
        transcript,
        gens,
        &c_tau,
        &pn_tau,
        &extra,
        rho,
        &proof.nl_proof,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn prove_batch(
        range: Range,
        values: &[u64],
    ) -> (
        Arc<Generators>,
        CircuitParams,
        CircuitProof,
        Vec<RistrettoPoint>,
    ) {
        let mut rng = rand::thread_rng();
        let gens = Generators::new(range, values.len()).unwrap();
        let params = CircuitParams::new(range, values.len()).unwrap();
        let blindings: Vec<S> = (0..values.len()).map(|_| S::rand(&mut rng)).collect();
        let mut t = BpppTranscript::new(b"test");
        let (proof, v_commitments) =
            prove(&mut t, &gens, &params, &mut rng, values, &blindings).unwrap();
        (gens, params, proof, v_commitments)
    }

    fn verify_batch(
        gens: &Generators,
        params: &CircuitParams,
        proof: &CircuitProof,
        v_commitments: &[RistrettoPoint],
    ) -> FastCryptoResult<()> {
        let mut t = BpppTranscript::new(b"test");
        verify(&mut t, gens, params, proof, v_commitments)
    }

    #[test]
    fn test_decompose_and_multiplicities() {
        assert_eq!(decompose(0, 16), vec![0; 16]);
        let digits = decompose(0x1234, 4);
        assert_eq!(digits, vec![4, 3, 2, 1]);

        let m = multiplicities(&digits);
        assert_eq!(m[0], 1); // digit 1
        assert_eq!(m[3], 1); // digit 4
        assert_eq!(m.iter().sum::<u64>(), 4);
    }

    #[test]
    fn test_roundtrip_single_64() {
        let mut rng = rand::thread_rng();
        for value in [0, 1, 0xdeadbeef, u64::MAX, rand::Rng::gen(&mut rng)] {
            let (gens, params, proof, v_commitments) = prove_batch(Range::Bits64, &[value]);
            assert!(
                verify_batch(&gens, &params, &proof, &v_commitments).is_ok(),
                "roundtrip failed for {value}"
            );
        }
    }

    /// The spec's batched configurations, with their expected norm-linear
    /// proof shapes (rounds, final l, final n), plus the widths not
    /// instantiated there (8-bit, 64-bit x M).
    #[test]
    fn test_roundtrip_batched_configs() {
        let mut rng = rand::thread_rng();
        let configs: [(Range, usize, usize, usize); 8] = [
            (Range::Bits16, 2, 3, 2), // 416 bytes
            (Range::Bits16, 4, 3, 2), // 416 bytes
            (Range::Bits16, 8, 3, 4), // 480 bytes
            (Range::Bits32, 8, 4, 4), // 544 bytes
            (Range::Bits8, 1, 3, 2),
            (Range::Bits8, 4, 3, 2),
            (Range::Bits16, 5, 3, 4), // non-power-of-two digit count
            (Range::Bits64, 4, 4, 4),
        ];
        for (range, m, rounds, n_final) in configs {
            let n_bits = range.bits();
            let max = if n_bits == 64 {
                u64::MAX
            } else {
                (1u64 << n_bits) - 1
            };
            let values: Vec<u64> = (0..m as u64)
                .map(|i| match i {
                    0 => 0,
                    1 => max,
                    _ => rand::Rng::gen::<u64>(&mut rng) & max,
                })
                .collect();
            let (gens, params, proof, v_commitments) = prove_batch(range, &values);
            assert_eq!(
                (
                    proof.nl_proof.rounds.len(),
                    proof.nl_proof.l_final.len(),
                    proof.nl_proof.n_final.len()
                ),
                (rounds, 1, n_final),
                "unexpected shape for {n_bits}x{m}"
            );
            assert!(
                verify_batch(&gens, &params, &proof, &v_commitments).is_ok(),
                "roundtrip failed for {n_bits}x{m}"
            );
        }
    }

    /// Per-value binding of the lambda^{i-1} weighting: the same commitments
    /// in a different order must not verify.
    #[test]
    fn test_swapped_commitments_fail() {
        let (gens, params, proof, mut v_commitments) = prove_batch(Range::Bits16, &[1, 2, 3, 4]);
        assert!(verify_batch(&gens, &params, &proof, &v_commitments).is_ok());
        v_commitments.swap(0, 1);
        assert!(verify_batch(&gens, &params, &proof, &v_commitments).is_err());
    }

    #[test]
    fn test_out_of_range_rejected() {
        let mut rng = rand::thread_rng();
        let gens = Generators::new(Range::Bits16, 2).unwrap();
        let params = CircuitParams::new(Range::Bits16, 2).unwrap();
        let blindings = vec![S::rand(&mut rng), S::rand(&mut rng)];
        let mut t = BpppTranscript::new(b"test");
        assert_eq!(
            prove(&mut t, &gens, &params, &mut rng, &[1, 1 << 16], &blindings).unwrap_err(),
            FastCryptoError::InvalidInput
        );
    }

    #[test]
    fn test_tampered_proof_fails() {
        let (gens, params, proof, v_commitments) = prove_batch(Range::Bits64, &[42]);
        assert!(verify_batch(&gens, &params, &proof, &v_commitments).is_ok());

        // Wrong commitment: to another value, or shifted off the
        // (G, H_0)-plane.
        for shift in [gens.g, gens.g_vec[15], gens.h_vec[7]] {
            let bad = vec![v_commitments[0] + shift];
            assert!(verify_batch(&gens, &params, &proof, &bad).is_err());
        }

        // Tampered circuit commitments.
        for i in 0..4 {
            let mut bad = proof.clone();
            let target = match i {
                0 => &mut bad.c_l,
                1 => &mut bad.c_o,
                2 => &mut bad.c_r,
                _ => &mut bad.c_s,
            };
            *target += gens.g;
            assert!(
                verify_batch(&gens, &params, &bad, &v_commitments).is_err(),
                "tampering {i}"
            );
        }

        // Tampered norm-linear part.
        let mut bad = proof.clone();
        bad.nl_proof.n_final[0] += S::generator();
        assert!(verify_batch(&gens, &params, &bad, &v_commitments).is_err());
    }

    #[test]
    fn test_transcript_binding() {
        let (gens, params, proof, v_commitments) = prove_batch(Range::Bits64, &[42]);
        let mut t = BpppTranscript::new(b"other");
        assert!(verify(&mut t, &gens, &params, &proof, &v_commitments).is_err());
    }

    /// A junk direction outside the (G, H_0)-plane of the statement
    /// commitment.
    enum Junk {
        /// A component on `G_vec[slot]`.
        Norm(usize),
        /// A component on `H_7` (the linear-witness base).
        Linear,
    }

    /// A freely chosen witness for the cheating prover below. The honest
    /// prover derives all of these from `values`; a cheater may pick any of
    /// them, so soundness must come from the circuit and not from the
    /// prover's own well-formedness checks.
    struct Cheat {
        /// Committed values, as arbitrary field elements (not just `u64`).
        values: Vec<S>,
        /// Digits committed in `C_L`, length `nm`.
        n_l: Vec<S>,
        /// Multiplicities committed in `C_O`, length `nm`.
        n_o: Vec<S>,
        /// Reciprocals committed in `C_R`. `None` derives the honest
        /// `(alpha + n_l[k])^{-1}` on the real digit slots, zero on padding.
        n_r: Option<Vec<S>>,
        /// Values forced into the padding slots (`k >= n_d`) of `C_R` after
        /// the honest reciprocals are derived, leaving the real digit slots
        /// correct. `alpha` is drawn mid-protocol, so this is the only way to
        /// keep the real slots honest while cheating on the padding.
        n_r_padding: Option<Vec<S>>,
        /// Slots of `r_L` forced nonzero, breaking the spec's zero pattern.
        r_l_nonzero: Vec<usize>,
        /// A component outside the `(G, H_0)`-plane added to the first
        /// statement commitment `V_0`, i.e. a forged `V_0' = v*G + s*H_0 + junk`.
        junk: Option<Junk>,
    }

    /// The witness an honest prover would build for `values`.
    fn honest_witness(params: &CircuitParams, values: &[u64]) -> Cheat {
        let digits: Vec<u64> = values
            .iter()
            .flat_map(|&v| decompose(v, params.d))
            .collect();
        let scalars = |v: &[u64]| v.iter().map(|&x| S::from(x)).collect::<Vec<_>>();
        Cheat {
            values: scalars(values),
            n_l: pad_to(&scalars(&digits), params.nm),
            n_o: pad_to(&scalars(&multiplicities(&digits)), params.nm),
            n_r: None,
            n_r_padding: None,
            r_l_nonzero: vec![],
            junk: None,
        }
    }

    /// The honest prover with the witness-derivation steps replaced by the
    /// caller's choices. The `r_S` solve is left intact, so the cheater still
    /// cancels every blinded error row it is able to; a rejection therefore
    /// comes from the circuit constraints, which are aggregated into the
    /// `T^3` row that no `r_S` slot can reach. A `junk` component of `V_0`
    /// is opened honestly at `T^3`: the unconstrained protocol accepts that,
    /// the shape blocks pair it into the value row.
    fn prove_cheating(
        transcript: &mut BpppTranscript,
        gens: &Generators,
        params: &CircuitParams,
        rng: &mut impl AllowedRng,
        blindings: &[S],
        cheat: &Cheat,
    ) -> FastCryptoResult<(CircuitProof, Vec<RistrettoPoint>)> {
        let two = S::from(2u64);
        let mut v_commitments: Vec<RistrettoPoint> = cheat
            .values
            .iter()
            .zip(blindings)
            .map(|(v, s)| RistrettoPoint::multi_scalar_mul(&[*v, *s], &[gens.g, gens.h_vec[0]]))
            .collect::<FastCryptoResult<_>>()?;
        // Coordinates of hat_V = 2*sum_i lambda^{i-1} V_i outside the
        // (G, H_0)-plane; the junk sits on V_0, so its weight is 2.
        let mut n_v_hat = vec![S::zero(); params.nm];
        let mut l_v_hat = S::zero();
        match cheat.junk {
            Some(Junk::Norm(slot)) => {
                v_commitments[0] += gens.g_vec[slot];
                n_v_hat[slot] = two;
            }
            Some(Junk::Linear) => {
                v_commitments[0] += gens.h_vec[7];
                l_v_hat = two;
            }
            None => {}
        }

        transcript.domain_sep(b"bppp_circuit");
        for v in &v_commitments {
            transcript.append_point(b"V", v);
        }

        let (n_l, n_o) = (cheat.n_l.clone(), cheat.n_o.clone());
        let r_o = blinding_vector(rng, &[4, 7]);
        let mut r_l = blinding_vector(rng, &[3, 6, 7]);
        for &slot in &cheat.r_l_nonzero {
            r_l[slot] = S::rand(rng);
        }
        let c_l = commit(gens, &r_l, S::zero(), &n_l)?;
        let c_o = commit(gens, &r_o, S::zero(), &n_o)?;
        transcript.append_point(b"C_L", &c_l);
        transcript.append_point(b"C_O", &c_o);
        let alpha = transcript.challenge_scalar(b"alpha");

        let mut n_r = match &cheat.n_r {
            Some(v) => v.clone(),
            None => pad_to(
                &batch_invert(
                    &n_l[..params.n_d]
                        .iter()
                        .map(|d| alpha + d)
                        .collect::<Vec<_>>(),
                )?,
                params.nm,
            ),
        };
        if let Some(padding) = &cheat.n_r_padding {
            n_r[params.n_d..].copy_from_slice(&padding[params.n_d..]);
        }
        let r_r = blinding_vector(rng, &[2, 5, 6, 7]);
        let c_r = commit(gens, &r_r, S::zero(), &n_r)?;
        transcript.append_point(b"C_R", &c_r);

        let rho = transcript.challenge_scalar(b"rho");
        let lambda = transcript.challenge_scalar(b"lambda");
        let beta = transcript.challenge_scalar(b"beta");
        let delta = transcript.challenge_scalar(b"delta");
        let mu = rho * rho;
        let delta_inv = delta.inverse()?;
        let blocks = compute_blocks(params, alpha, mu, lambda)?;
        let ps = blocks.ps_coefficients(delta_inv);

        let n_s: Vec<S> = (0..params.nm).map(|_| S::rand(rng)).collect();
        let l_s = S::rand(rng);
        let v_hat = two
            * cheat
                .values
                .iter()
                .enumerate()
                .fold(S::zero(), |acc, (i, v)| acc + blocks.lambdas[i] * v);
        let mut r_v = vec![S::zero(); H_LEN];
        r_v[1] = two
            * blindings
                .iter()
                .enumerate()
                .fold(S::zero(), |acc, (i, s)| acc + blocks.lambdas[i] * s);

        // n(T) with the junk opening at T^3 alongside the public block.
        let n_poly: [Vec<S>; 5] = [
            n_s.clone(),
            vec_add(&vec_scalar_mul(delta, &n_o), &blocks.cn_v),
            vec_add(&n_l, &blocks.cn_r),
            vec_add(&n_r, &blocks.cn_l),
            vec_add(&vec_scalar_mul(delta_inv, &blocks.cn_o), &n_v_hat),
        ];

        let n_weighted: Vec<Vec<S>> = n_poly.iter().map(|v| hadamard(v, &blocks.bar_mu)).collect();
        let mut fh = [S::zero(); 9];
        for (p, &c) in ps.iter().enumerate() {
            fh[p + 2] += c;
        }
        fh[3 + 2] += v_hat;
        for i in 0..n_poly.len() {
            for j in i..n_poly.len() {
                let ip = inner_product(&n_weighted[i], &n_poly[j]);
                fh[i + j] -= if i == j { ip } else { ip + ip };
            }
        }
        // No value-row assertion: for an invalid witness it is nonzero, which
        // is exactly what the verifier must catch.

        let mut known = [S::zero(); 13];
        for slot in 1..H_LEN {
            let committed = [
                (0i32, delta * r_o[slot]),
                (1, r_l[slot]),
                (2, r_r[slot]),
                (3, r_v[slot]),
            ];
            let a = CR_POWERS[slot - 1];
            for &(q, coefficient) in &committed {
                known[(a + q + 2) as usize] += beta * coefficient;
                known[(q + 2) as usize] += blocks.cl_v[slot - 1] * coefficient;
            }
        }
        known[2] -= delta * r_o[0];
        known[3] -= r_l[0];
        known[4] -= r_r[0];

        let beta_inv = beta.inverse()?;
        let mut r_s = vec![S::zero(); H_LEN];
        for slot in 1..H_LEN {
            let p = CR_POWERS[slot - 1] - 1;
            r_s[slot] = (fh[(p + 2) as usize] - known[(p + 2) as usize]) * beta_inv;
        }
        let shape_sum = (2..H_LEN).fold(S::zero(), |acc, j| acc + blocks.cl_v[j - 1] * r_s[j]);
        r_s[0] = -(fh[1] - known[1] - shape_sum - blocks.cl_v[7] * (l_s + l_v_hat));

        let c_s = commit(gens, &r_s, l_s, &n_s)?;
        transcript.append_point(b"C_S", &c_s);
        let tau = transcript.challenge_scalar(b"tau");

        let tau_inv = tau.inverse()?;
        let t2 = tau * tau;
        let t3 = t2 * tau;
        let r_tau: Vec<S> = (0..H_LEN)
            .map(|i| tau_inv * r_s[i] + delta * r_o[i] + tau * r_l[i] + t2 * r_r[i] + t3 * r_v[i])
            .collect();
        let mut l_tau = r_tau[1..H_LEN].to_vec();
        l_tau.push(tau_inv * l_s + t3 * l_v_hat);
        let n_tau: Vec<S> = (0..params.nm)
            .map(|k| {
                tau_inv * n_poly[0][k]
                    + n_poly[1][k]
                    + tau * n_poly[2][k]
                    + t2 * n_poly[3][k]
                    + t3 * n_poly[4][k]
            })
            .collect();
        let c_tau = blocks.c_at(tau, tau_inv, beta);

        let nl_proof = norm_linear::prove(transcript, gens, &c_tau, rho, &l_tau, &n_tau)?;
        Ok((
            CircuitProof {
                c_l,
                c_o,
                c_r,
                c_s,
                nl_proof,
            },
            v_commitments,
        ))
    }

    /// Run the cheating prover and verify its output. `Ok(())` means the
    /// cheat was accepted.
    fn run_cheat(range: Range, cheat: &Cheat) -> FastCryptoResult<()> {
        let mut rng = rand::thread_rng();
        let m = cheat.values.len();
        let gens = Generators::new(range, m).unwrap();
        let params = CircuitParams::new(range, m).unwrap();
        let blindings: Vec<S> = (0..m).map(|_| S::rand(&mut rng)).collect();
        let mut t = BpppTranscript::new(b"test");
        let (proof, v_commitments) =
            prove_cheating(&mut t, &gens, &params, &mut rng, &blindings, cheat).unwrap();
        let mut t = BpppTranscript::new(b"test");
        verify(&mut t, &gens, &params, &proof, &v_commitments)
    }

    /// Control: with the honest witness the cheating prover is the honest
    /// prover. Without this, every rejection below would be vacuous.
    #[test]
    fn test_cheating_prover_control() {
        for (range, values) in [
            (Range::Bits16, vec![1234u64]),
            (Range::Bits16, vec![0, 65535, 42, 7, 999]),
            (Range::Bits64, vec![u64::MAX, 0]),
            (Range::Bits8, vec![255]),
        ] {
            let params = CircuitParams::new(range, values.len()).unwrap();
            assert!(
                run_cheat(range, &honest_witness(&params, &values)).is_ok(),
                "control failed for {}x{}",
                range.bits(),
                values.len()
            );
        }
    }

    /// Soundness of the range claim: a prover committing to a value outside
    /// `[0, 2^n_bits)` must be rejected however it chooses its digits. Four
    /// digits base 16 cover `[0, 2^16)` exactly, so representing `2^16`
    /// forces a digit outside the base-16 set, which the reciprocal set
    /// membership argument must catch.
    #[test]
    fn test_out_of_range_value_cannot_be_proven() {
        let params = CircuitParams::new(Range::Bits16, 1).unwrap();
        let s = |x: u64| S::from(x);

        // The value link `sum_t d_t*16^t = v` holds for each of these; only
        // the base-16 membership of the digits is violated.
        let mut carry_digit = honest_witness(&params, &[0]);
        carry_digit.values = vec![s(1 << 16)];
        carry_digit.n_l[3] = s(16); // 16 * 16^3 = 2^16
        assert!(run_cheat(Range::Bits16, &carry_digit).is_err());

        // The same, with the cheater also claiming a multiplicity for the
        // out-of-base digit in the highest available slot (digit 15).
        let mut with_mult = honest_witness(&params, &[0]);
        with_mult.values = vec![s(1 << 16)];
        with_mult.n_l[3] = s(16);
        with_mult.n_o[14] = s(1);
        assert!(run_cheat(Range::Bits16, &with_mult).is_err());

        // One oversized low digit rather than a carry out of the top.
        let mut big_digit = honest_witness(&params, &[0]);
        big_digit.values = vec![s(1 << 16)];
        big_digit.n_l[0] = s(1 << 16);
        assert!(run_cheat(Range::Bits16, &big_digit).is_err());

        // Digits placed in the padding slots (k >= n_d) carry no weight in
        // the value link, so they cannot represent the extra magnitude.
        let mut padding = honest_witness(&params, &[0]);
        padding.values = vec![s(1 << 16)];
        padding.n_l[4] = s(1);
        assert!(run_cheat(Range::Bits16, &padding).is_err());
    }

    /// At 64 bits every `u64` is in range, so the meaningful attack is a
    /// committed field element that is not a `u64` at all. `-1 mod l` needs a
    /// negative digit, which the set membership argument must reject.
    #[test]
    fn test_negative_field_value_cannot_be_proven() {
        let params = CircuitParams::new(Range::Bits64, 1).unwrap();

        let mut negative = honest_witness(&params, &[0]);
        negative.values = vec![S::zero() - one()];
        negative.n_l[0] = S::zero() - one(); // d_0 = -1, so sum d_t*16^t = -1
        assert!(run_cheat(Range::Bits64, &negative).is_err());

        // Half the group order: not representable by 16 base-16 digits.
        let mut half = honest_witness(&params, &[0]);
        let inv_two = S::from(2u64).inverse().unwrap();
        half.values = vec![inv_two];
        half.n_l[0] = inv_two;
        assert!(run_cheat(Range::Bits64, &half).is_err());
    }

    /// The remaining witness components are equally unconstrained for a
    /// cheater and equally must be caught: digits of the wrong value, wrong
    /// multiplicities, reciprocals that do not invert the digits, and a
    /// blinding vector that breaks the spec's zero pattern.
    #[test]
    fn test_malformed_witness_rejected() {
        let params = CircuitParams::new(Range::Bits16, 1).unwrap();

        // Digits of a different (in-range) value than the one committed.
        let mut wrong_digits = honest_witness(&params, &[100]);
        wrong_digits.n_l = honest_witness(&params, &[50]).n_l;
        assert!(run_cheat(Range::Bits16, &wrong_digits).is_err());

        // Multiplicities that do not count the digits.
        let mut wrong_mult = honest_witness(&params, &[0x1234]);
        wrong_mult.n_o[0] += one();
        assert!(run_cheat(Range::Bits16, &wrong_mult).is_err());

        // Reciprocals unrelated to the digits.
        let mut rng = rand::thread_rng();
        let mut wrong_recip = honest_witness(&params, &[0x1234]);
        wrong_recip.n_r = Some((0..params.nm).map(|_| S::rand(&mut rng)).collect());
        assert!(run_cheat(Range::Bits16, &wrong_recip).is_err());

        // Reciprocals of zero, the one value that is never a valid inverse.
        let mut zero_recip = honest_witness(&params, &[0x1234]);
        zero_recip.n_r = Some(vec![S::zero(); params.nm]);
        assert!(run_cheat(Range::Bits16, &zero_recip).is_err());

        // Digits permuted within the value: the positional 16^t weighting of
        // the value link must catch it (0x1234 vs 0x1243).
        let mut permuted = honest_witness(&params, &[0x1234]);
        permuted.n_l.swap(0, 1);
        assert!(run_cheat(Range::Bits16, &permuted).is_err());

        // Blinding outside the spec's zero pattern: r_L[6] feeds a row above
        // T^6 that no r_S slot can cancel.
        let mut bad_blinding = honest_witness(&params, &[0x1234]);
        bad_blinding.r_l_nonzero = vec![6];
        assert!(run_cheat(Range::Bits16, &bad_blinding).is_err());

        // r_L[3] would land directly in the value row.
        let mut value_row_blinding = honest_witness(&params, &[0x1234]);
        value_row_blinding.r_l_nonzero = vec![3];
        assert!(run_cheat(Range::Bits16, &value_row_blinding).is_err());
    }

    /// Batched soundness: one out-of-range value hidden among valid ones, at
    /// each position of the batch, must be caught. The per-value `lambda^{i-1}`
    /// weighting is what keeps a bad slot from being masked by a good one.
    #[test]
    fn test_out_of_range_value_in_batch_rejected() {
        let m = 4;
        let params = CircuitParams::new(Range::Bits16, m).unwrap();
        for bad in 0..m {
            let mut cheat = honest_witness(&params, &[1, 2, 3, 4]);
            cheat.values[bad] = S::from(1u64 << 16);
            cheat.n_l[bad * params.d + 3] += S::from(16u64);
            assert!(
                run_cheat(Range::Bits16, &cheat).is_err(),
                "out-of-range value at position {bad} accepted"
            );
        }
    }

    /// Slack, not a break: the slots beyond the real digit count
    /// (`k >= n_d`) and the multiplicity slots above 14 carry zero weight in
    /// every constraint block, so a prover may commit anything there and
    /// still be accepted. This is benign — those slots contribute nothing to
    /// the value link or the set membership row, so the extracted value is
    /// unchanged — but it is a real degree of freedom and is asserted here so
    /// that a future change which makes those slots meaningful cannot pass
    /// unnoticed.
    #[test]
    fn test_unused_slots_are_unconstrained() {
        let params = CircuitParams::new(Range::Bits16, 1).unwrap();
        let mut rng = rand::thread_rng();

        // Junk digits in the padding slots, with the matching reciprocal
        // slots left at zero.
        let mut junk_digits = honest_witness(&params, &[1234]);
        for digit in junk_digits.n_l[params.n_d..].iter_mut() {
            *digit = S::rand(&mut rng);
        }
        assert!(run_cheat(Range::Bits16, &junk_digits).is_ok());

        // Junk in the multiplicity slots above 14, where `cn_o` is zero.
        let mut junk_mult = honest_witness(&params, &[1234]);
        junk_mult.n_o[15] = S::rand(&mut rng);
        assert!(run_cheat(Range::Bits16, &junk_mult).is_ok());
    }

    /// The one way an unused slot does reach the value row is a nonzero
    /// digit/reciprocal *pair* at the same padding index `k`, contributing
    /// `2*n_L[k]*n_R[k]*mu^{k+1}`. Both halves are committed before `mu` is
    /// drawn, so the contribution is an unpredictable function of `mu`: it
    /// cannot be tuned to cancel a range violation, and it breaks an
    /// otherwise valid proof rather than passing through unnoticed. The
    /// slack in [`test_unused_slots_are_unconstrained`] therefore extends
    /// only to slots where one half of the pair is zero.
    #[test]
    fn test_padding_pair_reaches_the_value_row() {
        let params = CircuitParams::new(Range::Bits16, 1).unwrap();
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            // Padding pairs cannot rescue an out-of-range value.
            let mut cheat = honest_witness(&params, &[0]);
            cheat.values = vec![S::from(1u64 << 16)];
            let mut n_r = vec![S::zero(); params.nm];
            for (digit, recip) in cheat.n_l[params.n_d..]
                .iter_mut()
                .zip(&mut n_r[params.n_d..])
            {
                *digit = S::rand(&mut rng);
                *recip = S::rand(&mut rng);
            }
            cheat.n_r_padding = Some(n_r);
            assert!(run_cheat(Range::Bits16, &cheat).is_err());

            // Nor are they free for an honest value: the pair perturbs the
            // value row, which no `r_S` slot can absorb.
            cheat.values = vec![S::zero()];
            assert!(run_cheat(Range::Bits16, &cheat).is_err());
        }

        // Zeroing either half of every pair restores acceptance, confirming
        // that it is the product and not the slot that matters.
        for zero_digits in [true, false] {
            let mut cheat = honest_witness(&params, &[1234]);
            let mut n_r = vec![S::zero(); params.nm];
            for (digit, recip) in cheat.n_l[params.n_d..]
                .iter_mut()
                .zip(&mut n_r[params.n_d..])
            {
                *(if zero_digits { recip } else { digit }) = S::rand(&mut rng);
            }
            cheat.n_r_padding = Some(n_r);
            assert!(run_cheat(Range::Bits16, &cheat).is_ok());
        }
    }

    /// The exact-form soundness fix: a prover opening a commitment with
    /// components outside the (G, H_0)-plane, cancelling every blinded row,
    /// must still be rejected (the unconstrained protocol accepts this).
    /// The junk-free control is `test_cheating_prover_control`.
    #[test]
    fn test_forged_commitment_rejected() {
        let params = CircuitParams::new(Range::Bits64, 1).unwrap();
        let forged = |junk| Cheat {
            junk: Some(junk),
            ..honest_witness(&params, &[42])
        };
        assert!(run_cheat(Range::Bits64, &forged(Junk::Norm(15))).is_err());
        assert!(run_cheat(Range::Bits64, &forged(Junk::Norm(0))).is_err());
        assert!(run_cheat(Range::Bits64, &forged(Junk::Linear)).is_err());
    }
}
