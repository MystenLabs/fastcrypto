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
use crate::groups::{GroupElement, MultiScalarMul, Scalar};
use crate::pedersen::{Blinding, PedersenCommitment, Range};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use std::iter::once;

use crate::bulletproofspp::crs::{
    compatible_with_pedersen_commitments, dims, Generators, BASE, H_LEN,
};
use crate::bulletproofspp::laurent::Laurent;
use crate::bulletproofspp::norm_linear::{self, NormLinearProof};
use crate::bulletproofspp::transcript::BpppTranscript;
use crate::bulletproofspp::util::*;

type S = RistrettoScalar;

/// tau-powers of the blinding constraint entries `hat_c_r`,
/// slots 1..7. The gap at 4 keeps `C_S` out of the value row.
const CR_POWERS: [i32; H_LEN - 1] = [-1, 1, 2, 3, 5, 6, 7];

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

    pub(crate) fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        if bytes.len() < 4 * 32 {
            return Err(FastCryptoError::InvalidInput);
        }
        let (head, tail) = bytes.split_at(4 * 32);
        let mut chunks = head.chunks_exact(32);
        Ok(CircuitProof {
            c_l: decode_next(&mut chunks)?,
            c_o: decode_next(&mut chunks)?,
            c_r: decode_next(&mut chunks)?,
            c_s: decode_next(&mut chunks)?,
            nl_proof: NormLinearProof::from_bytes(tail)?,
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
    let mut shape = Vec::with_capacity(nm + H_LEN - 1);
    let mut shape_pow = lambda;
    for _ in 0..nm + H_LEN - 1 {
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
    /// The public part of `n(T)`:
    /// `p_n(T) = cn_v + T*cn_r + T^2*cn_l + T^3*delta^{-1}*cn_o`.
    fn p_n(&self, delta_inv: S) -> Laurent<Vec<S>> {
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

    /// The linear constraint vector
    /// `c(T) = cl_v + beta*sum_j e_j*T^{CR_POWERS[j]}`, with `e_j` the `j`-th
    /// unit vector (slot 8 carries only the shape entry).
    fn c(&self, beta: S) -> Laurent<Vec<S>> {
        Laurent::from_terms(
            once((0, self.cl_v.clone())).chain(CR_POWERS.iter().enumerate().map(|(j, &a)| {
                let mut beta_e_j = vec![S::zero(); H_LEN];
                beta_e_j[j] = beta;
                (a, beta_e_j)
            })),
        )
    }
}

/// Commit to a circuit message: blinding `r` (slot 0 on `G`, slots 1..7 on
/// `H_0..H_6`), linear witness `l` on `H_7`, and norm witness `n`.
fn commit(gens: &Generators, r: &[S], l: S, n: &[S]) -> FastCryptoResult<RistrettoPoint> {
    gens.commit(r[0], &h_coordinates(r, l), n)
}

/// The `H` coordinates `(r_1, ..., r_7, l)` of a circuit message with
/// blinding `r` (slot 0 is on `G`) and linear witness `l` (on `H_7`).
fn h_coordinates(r: &[S], l: S) -> Vec<S> {
    let mut h = r[1..].to_vec();
    h.push(l);
    h
}

/// A blinding vector of length `H_LEN` with zeros at specific positions and
/// random values otherwise. Slot `p` of a commitment entering `C(T)` at
/// `T^e` reaches the error polynomial at row `e + CR_POWERS[p-1]`, so the
/// slots hitting the value row `T^3`, or rows above `T^6` that no `r_S` slot
/// cancels, must be zero. Hence, with entry powers 0, 1, 2 for `C_O`, `C_L`,
/// `C_R`: `r_O` zeros slots `[4, 7]` (rows 3, 7), `r_L` slots `[3, 6, 7]`
/// (rows 3, 7, 8) and `r_R` slots `[2, 5, 6, 7]` (rows 3, 7, 8, 9).
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

/// The honest reciprocals `(alpha + d_k)^{-1}` of the digits `n_l` on the
/// real digit slots, zero on the padding.
fn reciprocals(params: &CircuitParams, n_l: &[S], alpha: S) -> FastCryptoResult<Vec<S>> {
    let denominators: Vec<S> = n_l[..params.n_d].iter().map(|d| alpha + d).collect();
    Ok(pad_to(&batch_invert(&denominators)?, params.nm))
}

/// The prover's witness and randomness, chosen before the first challenge.
struct Witness {
    /// Input openings `V_i = u_i*G + s_i*H_0`: the values `u_i`...
    values: Vec<S>,
    /// ...and the blindings `s_i`.
    blindings: Vec<S>,
    /// Entry `i`, if present, adds coordinates outside the `(G, H_0)`-plane
    /// to `V_i`: on `G_vec`, and on `H_7`. Empty for honest inputs.
    off_plane: Vec<(Vec<S>, S)>,
    /// Digits; slot `d*(i-1)+t` holds digit `t` of value `i`, zero beyond `n_d`.
    n_l: Vec<S>,
    /// Shared multiplicities `m_1..m_15`, zero-padded.
    n_o: Vec<S>,
    r_o: Vec<S>,
    r_l: Vec<S>,
    r_r: Vec<S>,
    /// Masks of `C_S`.
    n_s: Vec<S>,
    l_s: S,
}

impl Witness {
    /// The honest witness for `values` under `blindings`, with fresh
    /// blinding and masks.
    fn new(
        params: &CircuitParams,
        rng: &mut impl AllowedRng,
        values: &[u64],
        blindings: &[S],
    ) -> Self {
        let digits: Vec<u64> = values
            .iter()
            .flat_map(|&v| decompose(v, params.d))
            .collect();
        Witness {
            values: to_scalars(values),
            blindings: blindings.to_vec(),
            off_plane: vec![],
            n_l: pad_to(&to_scalars(&digits), params.nm),
            n_o: pad_to(&to_scalars(&multiplicities(&digits)), params.nm),
            r_o: blinding_vector(rng, &[4, 7]),
            r_l: blinding_vector(rng, &[3, 6, 7]),
            r_r: blinding_vector(rng, &[2, 5, 6, 7]),
            n_s: (0..params.nm).map(|_| S::rand(rng)).collect(),
            l_s: S::rand(rng),
        }
    }

    /// The input commitments `V_i`: Pedersen commitments to the values, plus
    /// any coordinates outside the `(G, H_0)`-plane.
    fn input_commitments(&self, gens: &Generators) -> FastCryptoResult<Vec<PedersenCommitment>> {
        debug_assert!(compatible_with_pedersen_commitments(gens));
        self.values
            .iter()
            .zip(&self.blindings)
            .enumerate()
            .map(|(i, (v, s))| {
                let mut commitment = PedersenCommitment::new(v, &Blinding(*s));
                if let Some((n, l)) = self.off_plane.get(i) {
                    let mut scalars = n.clone();
                    scalars.push(*l);
                    let mut points = gens.g_vec.clone();
                    points.push(gens.h_vec[H_LEN - 1]);
                    commitment.0 += RistrettoPoint::multi_scalar_mul(&scalars, &points)?;
                }
                Ok(commitment)
            })
            .collect()
    }
}

/// Solve the blinding `r_S` of `C_S` (spec "Choosing r_S"). `rest` is the
/// error polynomial less the contribution of the other commitments, and
/// `T^{-1}` times the message of `C_S` must cancel it on the rows
/// `T^{a-1}`, `a` in `CR_POWERS` (slot `j` by `beta*T^{CR_POWERS[j-1]}`), and
/// on `T^{-1}` (slot 0, which also absorbs the shape entries `cl_v` against
/// the `H` coordinates of `C_S`).
fn solve_r_s(blocks: &Blocks, rest: &Laurent<S>, l_s: S, beta: S) -> FastCryptoResult<Vec<S>> {
    let beta_inv = beta.inverse()?;
    let mut r_s = vec![S::zero(); H_LEN];
    for (j, &a) in CR_POWERS.iter().enumerate() {
        r_s[j + 1] = rest.coeff(a - 1) * beta_inv;
    }
    r_s[0] = inner_product(&blocks.cl_v, &h_coordinates(&r_s, l_s)) - rest.coeff(-1);
    Ok(r_s)
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
) -> FastCryptoResult<(CircuitProof, Vec<PedersenCommitment>)> {
    if values.len() != params.m
        || blindings.len() != params.m
        || gens.g_vec.len() != params.nm
        || values.iter().any(|&v| !params.range.is_in_range(v))
    {
        return Err(FastCryptoError::InvalidInput);
    }
    let witness = Witness::new(params, rng, values, blindings);
    prove_witness(transcript, gens, params, &witness, None)
}

/// Run the protocol with `witness`, without checking that it is well formed.
///
/// `bad_reciprocals` replaces the reciprocals and is only used in tests.
fn prove_witness(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    params: &CircuitParams,
    witness: &Witness,
    bad_reciprocals: Option<&dyn Fn(S) -> FastCryptoResult<Vec<S>>>,
) -> FastCryptoResult<(CircuitProof, Vec<PedersenCommitment>)> {
    let two = S::from(2u64);
    let v_commitments = witness.input_commitments(gens)?;
    transcript.domain_sep(b"bppp_circuit");
    transcript.append_commits(b"V", &v_commitments);

    // Step 1: commit digits (C_L) and shared multiplicities (C_O).
    let c_l = commit(gens, &witness.r_l, S::zero(), &witness.n_l)?;
    let c_o = commit(gens, &witness.r_o, S::zero(), &witness.n_o)?;
    transcript.append_point(b"C_L", &c_l);
    transcript.append_point(b"C_O", &c_o);

    // Step 2: reciprocal challenge, drawn after the digits and
    // multiplicities are committed.
    let alpha = transcript.challenge_scalar(b"alpha");

    // Step 3: commit the reciprocals (C_R).
    debug_assert!(cfg!(test) || bad_reciprocals.is_none());
    let n_r = bad_reciprocals.unwrap_or(&|alpha| reciprocals(params, &witness.n_l, alpha))(alpha)?;
    let c_r = commit(gens, &witness.r_r, S::zero(), &n_r)?;
    transcript.append_point(b"C_R", &c_r);

    // Step 4: constraint challenges.
    let rho = transcript.challenge_scalar(b"rho");
    let lambda = transcript.challenge_scalar(b"lambda");
    let beta = transcript.challenge_scalar(b"beta");
    let delta = transcript.challenge_scalar(b"delta");
    let mu = rho * rho;
    let delta_inv = delta.inverse()?;
    let blocks = compute_blocks(params, alpha, mu, lambda)?;

    // Step 5: solve the blinding r_S of C_S. The rescaled aggregate input
    // hat_V = 2*sum_i lambda^{i-1} V_i opens to hat_v on G,
    // 2*sum_i lambda^{i-1} s_i on H_0 and the off-plane coordinates n_hat_V,
    // l_hat_V (zero for honest inputs).
    let weights: Vec<S> = blocks.lambdas[..params.m].iter().map(|l| two * l).collect();
    let v_hat = inner_product(&weights, &witness.values);
    let mut n_v_hat = vec![S::zero(); params.nm];
    let mut l_v_hat = S::zero();
    for ((n_i, l_i), w) in witness.off_plane.iter().zip(&weights) {
        n_v_hat = vec_add(&n_v_hat, &vec_scalar_mul(*w, n_i));
        l_v_hat += *w * l_i;
    }
    let mut v_hat_h = vec![S::zero(); H_LEN];
    v_hat_h[0] = inner_product(&weights, &witness.blindings);
    v_hat_h[H_LEN - 1] = l_v_hat;

    // n(T) = w(T) + p_n(T), the G_vec coordinates of C(T), split into the
    // witness part w and the public part p_n.
    let w = Laurent::new(
        -1,
        vec![
            witness.n_s.clone(),
            vec_scalar_mul(delta, &witness.n_o),
            witness.n_l.clone(),
            n_r,
            n_v_hat,
        ],
    );
    let p_n = blocks.p_n(delta_inv);
    let n = w.clone() + p_n.clone();

    // Error polynomial hat_f(T) = p_s(T) + hat_v*T^3 - |n(T)|^2_mu. The public
    // square |p_n(T)|^2 inside p_s cancels against |n(T)|^2, leaving
    //   hat_f = (hat_v + 2*(lambda_al + mu_am))*T^3 - <w(T), n(T) + p_n(T)>_mu
    // so only the witness-side products are computed.
    let f_hat = Laurent::monomial(3, v_hat + two * (blocks.lambda_al + blocks.mu_am))
        - w.weighted_inner_product(&(n.clone() + p_n), &blocks.bar_mu);

    // The G coordinate r_0(T) and the H coordinates l(T) of C(T) without C_S.
    let r_0 = Laurent::new(
        0,
        vec![delta * witness.r_o[0], witness.r_l[0], witness.r_r[0]],
    );
    let l = Laurent::new(
        0,
        vec![
            vec_scalar_mul(delta, &h_coordinates(&witness.r_o, S::zero())),
            h_coordinates(&witness.r_l, S::zero()),
            h_coordinates(&witness.r_r, S::zero()),
            v_hat_h,
        ],
    );
    let c = blocks.c(beta);
    let rest = f_hat - c.inner_product(&l) + r_0;
    let r_s = solve_r_s(&blocks, &rest, witness.l_s, beta)?;
    let c_s = commit(gens, &r_s, witness.l_s, &witness.n_s)?;
    transcript.append_point(b"C_S", &c_s);

    // Step 6: evaluation point, drawn after every commitment.
    let tau = transcript.challenge_scalar(b"tau");

    // Step 7: evaluate the opening of C(tau) and run the norm-linear argument.
    let l = l + Laurent::monomial(-1, h_coordinates(&r_s, witness.l_s));
    let (c_tau, l_tau, n_tau) = (c.eval(tau)?, l.eval(tau)?, n.eval(tau)?);
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
    v_commitments: &[PedersenCommitment],
) -> FastCryptoResult<()> {
    if v_commitments.len() != params.m || gens.g_vec.len() != params.nm {
        return Err(FastCryptoError::InvalidInput);
    }
    transcript.domain_sep(b"bppp_circuit");
    transcript.append_commits(b"V", v_commitments);
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
    let pn_tau = blocks.p_n(delta_inv).eval(tau)?;
    // p_s(tau) = |p_n(tau)|^2_mu + 2*(lambda_al + mu_am)*tau^3, evaluated
    // directly on pn_tau rather than via the coefficients of p_s(T).
    let ps_tau =
        weighted_norm(&pn_tau, mu) + S::from(2u64) * (blocks.lambda_al + blocks.mu_am) * t3;
    let c_tau = blocks.c(beta).eval(tau)?;

    // Combined commitment, decomposed so it joins the norm-linear verifier's
    // single MSM (g_vec is touched only there):
    //   C(tau) = <p_n(tau), G_vec> + p_s(tau)*G
    //          + tau^{-1}*C_S + delta*C_O + tau*C_L + tau^2*C_R + tau^3*hat_V
    // with hat_V = 2*sum_i lambda^{i-1} V_i.
    let two_t3 = S::from(2u64) * t3;
    let mut extra = vec![
        (tau_inv, proof.c_s),
        (delta, proof.c_o),
        (tau, proof.c_l),
        (t2, proof.c_r),
    ];
    for (i, v_i) in v_commitments.iter().enumerate() {
        extra.push((two_t3 * blocks.lambdas[i], v_i.0));
    }

    norm_linear::verify(
        transcript,
        gens,
        &c_tau,
        ps_tau,
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
        Vec<PedersenCommitment>,
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
        v_commitments: &[PedersenCommitment],
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
    /// proof shapes (rounds, final n), plus the widths not instantiated
    /// there (8-bit, 64-bit x M).
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
            let max = range.max_value();
            let values: Vec<u64> = (0..m as u64)
                .map(|i| match i {
                    0 => 0,
                    1 => max,
                    _ => rand::Rng::gen::<u64>(&mut rng) & max,
                })
                .collect();
            let (gens, params, proof, v_commitments) = prove_batch(range, &values);
            assert_eq!(
                (proof.nl_proof.rounds.len(), proof.nl_proof.n_final.len()),
                (rounds, n_final),
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
        for shift in [gens.g, gens.g_vec[15], gens.h_vec[H_LEN - 1]] {
            let bad = vec![PedersenCommitment(v_commitments[0].0 + shift)];
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

    /// The honest witness for `values`, with random input blindings. The
    /// soundness tests below alter it into a cheating one: a cheater may
    /// pick every component freely, so soundness must come from the circuit
    /// and not from the prover's own well-formedness checks.
    fn honest_witness(params: &CircuitParams, values: &[u64]) -> Witness {
        let mut rng = rand::thread_rng();
        let blindings: Vec<S> = (0..values.len()).map(|_| S::rand(&mut rng)).collect();
        Witness::new(params, &mut rng, values, &blindings)
    }

    /// Run the prover with `witness` (and `bad_reciprocals` in place of the
    /// honest reciprocals, if given), and verify its output. `Ok(())` means the
    /// witness was accepted. The `r_S` solve is left intact, so a cheater
    /// still cancels every blinded error row it is able to; a rejection
    /// therefore comes from the circuit constraints, which are aggregated into
    /// the `T^3` row that no `r_S` slot can reach.
    fn run_cheat_with(
        range: Range,
        witness: &Witness,
        bad_reciprocals: Option<&dyn Fn(S) -> FastCryptoResult<Vec<S>>>,
    ) -> FastCryptoResult<()> {
        let m = witness.values.len();
        let gens = Generators::new(range, m).unwrap();
        let params = CircuitParams::new(range, m).unwrap();
        let mut t = BpppTranscript::new(b"test");
        let (proof, v_commitments) =
            prove_witness(&mut t, &gens, &params, witness, bad_reciprocals).unwrap();
        let mut t = BpppTranscript::new(b"test");
        verify(&mut t, &gens, &params, &proof, &v_commitments)
    }

    /// [run_cheat_with] with the honest reciprocals of the committed digits.
    fn run_cheat(range: Range, witness: &Witness) -> FastCryptoResult<()> {
        run_cheat_with(range, witness, None)
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
        negative.values = vec![-one()];
        negative.n_l[0] = -one(); // d_0 = -1, so sum d_t*16^t = -1
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
        let mut rng = rand::thread_rng();

        // Digits of a different (in-range) value than the one committed.
        let mut wrong_digits = honest_witness(&params, &[100]);
        wrong_digits.n_l = honest_witness(&params, &[50]).n_l;
        assert!(run_cheat(Range::Bits16, &wrong_digits).is_err());

        // Multiplicities that do not count the digits.
        let mut wrong_mult = honest_witness(&params, &[0x1234]);
        wrong_mult.n_o[0] += one();
        assert!(run_cheat(Range::Bits16, &wrong_mult).is_err());

        // Reciprocals unrelated to the digits.
        let honest = honest_witness(&params, &[0x1234]);
        let random: Vec<S> = (0..params.nm).map(|_| S::rand(&mut rng)).collect();
        assert!(run_cheat_with(Range::Bits16, &honest, Some(&|_| Ok(random.clone()))).is_err());

        // Reciprocals of zero, the one value that is never a valid inverse.
        let zeros = vec![S::zero(); params.nm];
        assert!(run_cheat_with(Range::Bits16, &honest, Some(&|_| Ok(zeros.clone()))).is_err());

        // Digits permuted within the value: the positional 16^t weighting of
        // the value link must catch it (0x1234 vs 0x1243).
        let mut permuted = honest_witness(&params, &[0x1234]);
        permuted.n_l.swap(0, 1);
        assert!(run_cheat(Range::Bits16, &permuted).is_err());

        // Blinding outside the spec's zero pattern: r_L[6] feeds a row above
        // T^6 that no r_S slot can cancel.
        let mut bad_blinding = honest_witness(&params, &[0x1234]);
        bad_blinding.r_l[6] = S::rand(&mut rng);
        assert!(run_cheat(Range::Bits16, &bad_blinding).is_err());

        // r_L[3] would land directly in the value row.
        let mut value_row_blinding = honest_witness(&params, &[0x1234]);
        value_row_blinding.r_l[3] = S::rand(&mut rng);
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
        let mut random_padding =
            || -> Vec<S> { (params.n_d..params.nm).map(|_| S::rand(&mut rng)).collect() };
        // Honest reciprocals on the real digit slots, `padding` beyond them.
        let with_padding = |witness: &Witness, padding: Vec<S>| {
            let n_l = witness.n_l.clone();
            move |alpha| {
                let mut n_r = reciprocals(&params, &n_l, alpha)?;
                n_r[params.n_d..].copy_from_slice(&padding);
                Ok(n_r)
            }
        };

        for _ in 0..8 {
            // Padding pairs cannot rescue an out-of-range value.
            let mut cheat = honest_witness(&params, &[0]);
            cheat.values = vec![S::from(1u64 << 16)];
            cheat.n_l[params.n_d..].copy_from_slice(&random_padding());
            let padding = random_padding();
            let recips = with_padding(&cheat, padding.clone());
            assert!(run_cheat_with(Range::Bits16, &cheat, Some(&recips)).is_err());

            // Nor are they free for an honest value: the pair perturbs the
            // value row, which no `r_S` slot can absorb.
            cheat.values = vec![S::zero()];
            let recips = with_padding(&cheat, padding);
            assert!(run_cheat_with(Range::Bits16, &cheat, Some(&recips)).is_err());
        }

        // Zeroing either half of every pair restores acceptance, confirming
        // that it is the product and not the slot that matters.
        let zeros = vec![S::zero(); params.nm - params.n_d];
        for zero_digits in [true, false] {
            let mut cheat = honest_witness(&params, &[1234]);
            let padding = if zero_digits {
                random_padding()
            } else {
                cheat.n_l[params.n_d..].copy_from_slice(&random_padding());
                zeros.clone()
            };
            let recips = with_padding(&cheat, padding);
            assert!(run_cheat_with(Range::Bits16, &cheat, Some(&recips)).is_ok());
        }
    }

    /// The exact-form soundness fix: a prover opening a commitment with
    /// components outside the (G, H_0)-plane, cancelling every blinded row,
    /// must still be rejected (the unconstrained protocol accepts this).
    /// The junk-free control is `test_cheating_prover_control`.
    #[test]
    fn test_forged_commitment_rejected() {
        let params = CircuitParams::new(Range::Bits64, 1).unwrap();
        let forged = |n_junk: Vec<S>, l_junk: S| Witness {
            off_plane: vec![(n_junk, l_junk)],
            ..honest_witness(&params, &[42])
        };
        let unit = |slot: usize| {
            let mut v = vec![S::zero(); params.nm];
            v[slot] = one();
            v
        };
        let zero_n = vec![S::zero(); params.nm];
        assert!(run_cheat(Range::Bits64, &forged(unit(15), S::zero())).is_err());
        assert!(run_cheat(Range::Bits64, &forged(unit(0), S::zero())).is_err());
        assert!(run_cheat(Range::Bits64, &forged(zero_n, one())).is_err());
    }
}
