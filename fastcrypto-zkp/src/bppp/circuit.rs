// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shape-constrained reciprocal range circuit (the spec's fully-constrained
//! exact-form protocol, batched per its appendix). Proves, for M Pedersen
//! commitments `V_i = v_i*G + s_i*H_0`, that every `v_i` lies in
//! `[0, 2^n_bits)` within one transcript. The prover commits digits,
//! reciprocals, and shared multiplicities, reduces the circuit to one
//! norm-linear relation at a random evaluation point, and delegates to the
//! norm-linear argument.

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use fastcrypto::traits::AllowedRng;

use crate::bppp::crs::{dims, validate_dims, Generators, BASE, H_LEN};
use crate::bppp::norm_linear::{self, NormLinearProof};
use crate::bppp::transcript::BpppTranscript;
use crate::bppp::util::*;

type S = RistrettoScalar;

/// tau-powers of the blinding constraint entries `hat_c_r`,
/// slots 1..7. The gap at 4 keeps `C_S` out of the value row.
const CR_POWERS: [i32; 7] = [-1, 1, 2, 3, 5, 6, 7];

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

/// Dimensions of a batched instance: `m` values of `n_bits` bits, `d = n_bits/4`
/// digits per value, `n_d = m*d` digits overall, norm length
/// `nm = max(n_d, 16)` rounded to a power of two.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CircuitParams {
    pub(crate) n_bits: usize,
    pub(crate) m: usize,
    pub(crate) d: usize,
    pub(crate) n_d: usize,
    pub(crate) nm: usize,
}

impl CircuitParams {
    /// `n_bits` must be a positive multiple of 4 (at most 64) and `m >= 1`.
    pub(crate) fn new(n_bits: usize, m: usize) -> FastCryptoResult<Self> {
        validate_dims(n_bits, m)?;
        let (d, n_d, nm) = dims(n_bits, m);
        Ok(CircuitParams {
            n_bits,
            m,
            d,
            n_d,
            nm,
        })
    }

    fn value_in_range(&self, value: u64) -> bool {
        self.n_bits == 64 || value >> self.n_bits == 0
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
    /// `(1, lambda, ..., lambda^{M(nm+8)})`.
    lambdas: Vec<S>,
}

fn compute_blocks(params: &CircuitParams, alpha: S, mu: S, lambda: S) -> FastCryptoResult<Blocks> {
    let &CircuitParams { m, d, n_d, nm, .. } = params;
    let mu_inv = mu.inverse()?;
    let lambdas = power_vector(lambda, m * (nm + 8) + 1);
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
            cn_r.push(lambdas[m] * mu_inv_pow + alpha);
        } else {
            cn_l.push(S::zero());
            cn_r.push(S::zero());
        }
        cn_v.push(lambdas[m * (k + 1) + 1] * mu_inv_pow);
    }

    // cn_o via one batch inversion of the denominators alpha*(alpha+j)*mu^j.
    let bm1 = (BASE - 1) as usize;
    let denominators: Vec<S> = (0..bm1)
        .map(|k| alpha * (alpha + S::from(k as u64 + 1)) * bar_mu[k])
        .collect();
    let inverses = batch_invert(&denominators)?;
    let mut cn_o: Vec<S> = (0..bm1)
        .map(|k| S::from(k as u64 + 1) * lambdas[m] * inverses[k])
        .collect();
    cn_o.resize(nm, S::zero());

    let lambda_al = S::from(n_d as u64) * lambdas[m] * alpha.inverse()?;

    let mut cl_v = vec![S::zero()];
    cl_v.extend((1..H_LEN).map(|p| lambdas[m * (nm + p) + 1]));

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
/// `H_0..H_6` carry the blinding slots 1..7, `H_7` the linear witness.
fn commit(gens: &Generators, r: &[S], l: S, n: &[S]) -> FastCryptoResult<RistrettoPoint> {
    debug_assert_eq!(r.len(), H_LEN);
    let mut scalars = Vec::with_capacity(1 + H_LEN + n.len());
    scalars.push(r[0]);
    scalars.extend(&r[1..H_LEN]);
    scalars.push(l);
    scalars.extend(n);
    let mut points = Vec::with_capacity(scalars.len());
    points.push(gens.g);
    points.extend(&gens.h_vec);
    points.extend(&gens.g_vec[..n.len()]);
    RistrettoPoint::multi_scalar_mul(&scalars, &points)
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
        || values.iter().any(|&v| !params.value_in_range(v))
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let two = S::from(2u64);

    let v_commitments: Vec<RistrettoPoint> = values
        .iter()
        .zip(blindings)
        .map(|(&v, s)| RistrettoPoint::multi_scalar_mul(&[S::from(v), *s], &[gens.g, gens.h_vec[0]]))
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
    let n_l = pad_to(&digits.iter().map(|&d| S::from(d)).collect::<Vec<_>>(), params.nm);
    let mut n_o: Vec<S> = multiplicities(&digits).iter().map(|&m| S::from(m)).collect();
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
    let ps = blocks.ps_coefficients(delta_inv);

    // Step 5: masks, then solve the blinding r_S of C_S.
    let n_s: Vec<S> = (0..params.nm).map(|_| S::rand(rng)).collect();
    let l_s = S::rand(rng);
    // Rescaled aggregate input hat_V = 2*sum_i lambda^{i-1} V_i:
    // hat_v = 2*sum lambda^{i-1} v_i, r_V = (0, 2*sum lambda^{i-1} s_i, 0, ...).
    let v_hat = two
        * values
            .iter()
            .enumerate()
            .fold(S::zero(), |acc, (i, &v)| acc + blocks.lambdas[i] * S::from(v));
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
    // coefficients at T^{-2}..T^6 stored at index p+2. |n(T)|^2_mu expands
    // into the 15 unordered pairs <n_i, n_j>_mu at T^{p_i+p_j}.
    let n_weighted: Vec<Vec<S>> = n_poly.iter().map(|v| hadamard(v, &blocks.bar_mu)).collect();
    let mut fh = [S::zero(); 9];
    for (p, &c) in ps.iter().enumerate() {
        fh[p + 2] += c;
    }
    fh[3 + 2] += v_hat;
    for i in 0..n_poly.len() {
        for j in i..n_poly.len() {
            let ip = inner_product(&n_weighted[i], &n_poly[j]);
            // powers: p_i = i - 1, p_j = j - 1, index (p_i + p_j) + 2 = i + j.
            fh[i + j] -= if i == j { ip } else { ip + ip };
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
    let ps = blocks.ps_coefficients(delta_inv);
    let mut ps_tau = S::zero();
    let mut t_pow = one();
    for &c in &ps {
        ps_tau += c * t_pow;
        t_pow *= tau;
    }
    let pn_tau = blocks.pn_at(tau, delta_inv);
    let c_tau = blocks.c_at(tau, tau_inv, beta);

    // Combined commitment:
    //   C(tau) = p_s(tau)*G + <p_n(tau), G_vec>
    //          + tau^{-1}*C_S + delta*C_O + tau*C_L + tau^2*C_R + tau^3*hat_V
    // with hat_V = 2*sum_i lambda^{i-1} V_i.
    let two_t3 = S::from(2u64) * t3;
    let mut scalars = vec![ps_tau];
    let mut points = vec![gens.g];
    scalars.extend(&pn_tau);
    points.extend(&gens.g_vec);
    scalars.extend([tau_inv, delta, tau, t2]);
    points.extend([proof.c_s, proof.c_o, proof.c_l, proof.c_r]);
    for (i, v) in v_commitments.iter().enumerate() {
        scalars.push(two_t3 * blocks.lambdas[i]);
        points.push(*v);
    }
    let c_tau_commitment = RistrettoPoint::multi_scalar_mul(&scalars, &points)?;

    norm_linear::verify(
        transcript,
        gens,
        &c_tau,
        c_tau_commitment,
        rho,
        &proof.nl_proof,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prove_batch(
        n_bits: usize,
        values: &[u64],
    ) -> (
        Generators,
        CircuitParams,
        CircuitProof,
        Vec<RistrettoPoint>,
    ) {
        let mut rng = rand::thread_rng();
        let gens = Generators::new(n_bits, values.len()).unwrap();
        let params = CircuitParams::new(n_bits, values.len()).unwrap();
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
            let (gens, params, proof, v_commitments) = prove_batch(64, &[value]);
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
        let configs: [(usize, usize, usize, usize); 8] = [
            (16, 2, 3, 2),  // 416 bytes
            (16, 4, 3, 2),  // 416 bytes
            (16, 8, 3, 4),  // 480 bytes
            (32, 8, 4, 4),  // 544 bytes
            (8, 1, 3, 2),
            (8, 4, 3, 2),
            (16, 5, 3, 4),  // non-power-of-two digit count
            (64, 4, 4, 4),
        ];
        for (n_bits, m, rounds, n_final) in configs {
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
            let (gens, params, proof, v_commitments) = prove_batch(n_bits, &values);
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
        let (gens, params, proof, mut v_commitments) = prove_batch(16, &[1, 2, 3, 4]);
        assert!(verify_batch(&gens, &params, &proof, &v_commitments).is_ok());
        v_commitments.swap(0, 1);
        assert!(verify_batch(&gens, &params, &proof, &v_commitments).is_err());
    }

    #[test]
    fn test_out_of_range_rejected() {
        let mut rng = rand::thread_rng();
        let gens = Generators::new(16, 2).unwrap();
        let params = CircuitParams::new(16, 2).unwrap();
        let blindings = vec![S::rand(&mut rng), S::rand(&mut rng)];
        let mut t = BpppTranscript::new(b"test");
        assert_eq!(
            prove(&mut t, &gens, &params, &mut rng, &[1, 1 << 16], &blindings).unwrap_err(),
            FastCryptoError::InvalidInput
        );
    }

    #[test]
    fn test_tampered_proof_fails() {
        let (gens, params, proof, v_commitments) = prove_batch(64, &[42]);
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
        let (gens, params, proof, v_commitments) = prove_batch(64, &[42]);
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

    /// A single-value prover for a forged commitment
    /// `V' = v*G + s*H_0 + junk`: it runs the honest algorithm but opens the
    /// junk coordinate of `hat_V = 2V'` honestly at `T^3`, and cancels every
    /// blinded error row with `r_S` as usual. Against the unconstrained
    /// protocol this strategy produces accepting proofs; the shape blocks
    /// pair the junk into the value row, which no `r_S` slot can reach, so
    /// verification must fail. With `junk = None` it reduces to the honest
    /// prover (the control case validating this reimplementation).
    fn prove_forged(
        transcript: &mut BpppTranscript,
        gens: &Generators,
        params: &CircuitParams,
        rng: &mut impl AllowedRng,
        value: u64,
        blinding: &S,
        junk: Option<Junk>,
    ) -> FastCryptoResult<(CircuitProof, RistrettoPoint)> {
        let two = S::from(2u64);
        let mut v_commitment =
            RistrettoPoint::multi_scalar_mul(&[S::from(value), *blinding], &[gens.g, gens.h_vec[0]])?;
        // Coordinates of hat_V = 2V' outside the (G, H_0)-plane.
        let mut n_v_hat = vec![S::zero(); params.nm];
        let mut l_v_hat = S::zero();
        match junk {
            Some(Junk::Norm(slot)) => {
                v_commitment += gens.g_vec[slot];
                n_v_hat[slot] = two;
            }
            Some(Junk::Linear) => {
                v_commitment += gens.h_vec[7];
                l_v_hat = two;
            }
            None => {}
        }

        transcript.domain_sep(b"bppp_circuit");
        transcript.append_point(b"V", &v_commitment);

        let digits = decompose(value, params.d);
        let n_l = pad_to(
            &digits.iter().map(|&d| S::from(d)).collect::<Vec<_>>(),
            params.nm,
        );
        let mut n_o: Vec<S> = multiplicities(&digits).iter().map(|&m| S::from(m)).collect();
        n_o.resize(params.nm, S::zero());
        let r_o = blinding_vector(rng, &[4, 7]);
        let r_l = blinding_vector(rng, &[3, 6, 7]);
        let c_l = commit(gens, &r_l, S::zero(), &n_l)?;
        let c_o = commit(gens, &r_o, S::zero(), &n_o)?;
        transcript.append_point(b"C_L", &c_l);
        transcript.append_point(b"C_O", &c_o);
        let alpha = transcript.challenge_scalar(b"alpha");

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
        let v_hat = two * S::from(value);
        let mut r_v = vec![S::zero(); H_LEN];
        r_v[1] = two * blinding;

        // n(T) with the junk opening at T^3 alongside the public block.
        let n_poly: [Vec<S>; 5] = [
            n_s.clone(),
            vec_add(&vec_scalar_mul(delta, &n_o), &blocks.cn_v),
            vec_add(&n_l, &blocks.cn_r),
            vec_add(&n_r, &blocks.cn_l),
            vec_add(&vec_scalar_mul(delta_inv, &blocks.cn_o), &n_v_hat),
        ];

        let n_weighted: Vec<Vec<S>> =
            n_poly.iter().map(|v| hadamard(v, &blocks.bar_mu)).collect();
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
        // No value-row assertion here: with junk it is nonzero by design.

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
            v_commitment,
        ))
    }

    /// The exact-form soundness fix: a prover opening a commitment with
    /// components outside the (G, H_0)-plane, cancelling every blinded row,
    /// must still be rejected (the unconstrained protocol accepts this).
    #[test]
    fn test_forged_commitment_rejected() {
        let mut rng = rand::thread_rng();
        let gens = Generators::new(64, 1).unwrap();
        let params = CircuitParams::new(64, 1).unwrap();
        let blinding = S::rand(&mut rng);

        let run = |junk: Option<Junk>| {
            let mut rng = rand::thread_rng();
            let mut t = BpppTranscript::new(b"test");
            let (proof, v_commitment) =
                prove_forged(&mut t, &gens, &params, &mut rng, 42, &blinding, junk).unwrap();
            let mut t = BpppTranscript::new(b"test");
            verify(&mut t, &gens, &params, &proof, &[v_commitment])
        };

        // Control: without junk the forged prover is the honest prover.
        assert!(run(None).is_ok());

        assert!(run(Some(Junk::Norm(15))).is_err());
        assert!(run(Some(Junk::Norm(0))).is_err());
        assert!(run(Some(Junk::Linear)).is_err());
    }
}
