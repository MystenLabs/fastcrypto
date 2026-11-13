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
use crate::groups::{AdditiveGroup, MultiScalarMul, Scalar};
use crate::pedersen::{Blinding, PedersenCommitment, Range};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::AllowedRng;
use std::iter::once;

use crate::bulletproofspp::constraints::Constraints;
use crate::bulletproofspp::crs::{compatible_with_pedersen_commitments, Generators, BASE, H_LEN};
use crate::bulletproofspp::laurent::Laurent;
use crate::bulletproofspp::norm_linear::{self, NormLinearProof, Opening};
use crate::bulletproofspp::transcript::BpppTranscript;
use crate::bulletproofspp::util::*;

type S = RistrettoScalar;

/// The exponents `a_j` of `c_r_hat(T)`, see [c]. The gap at 4 keeps `C_S`
/// out of the value row.
const CR_POWERS: [i32; H_LEN - 1] = [-1, 1, 2, 3, 5, 6, 7];

/// The powers of `T` of the commitments in
/// `C(T) = T^{-1}*C_S + delta*C_O + T*C_L + T^2*C_R + T^3*V_hat + P(T)`.
const C_S_POWER: i32 = -1;
const C_O_POWER: i32 = 0;
const C_L_POWER: i32 = 1;
const C_R_POWER: i32 = 2;
const V_HAT_POWER: i32 = 3;

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
        let d = range.bits() / BASE.ilog2() as usize;
        let n_d = m * d;
        // The BASE - 1 multiplicity slots set the floor.
        let nm = n_d.max(BASE as usize).next_power_of_two();
        Ok(CircuitParams {
            range,
            m,
            d,
            n_d,
            nm,
        })
    }
}

/// The linear constraint vector `c(T) = c_r_hat(T) + cl_v`, with
/// `c_r_hat(T) = beta*sum_j e_j*T^{a_j}`, `a_j = CR_POWERS[j]`, `e_j` the
/// `j`-th unit vector and `cl_v` the H shape rows (slot 8 carries only the
/// shape entry).
fn c(constraints: &Constraints, beta: S) -> Laurent<Vec<S>> {
    Laurent::from_terms(once((0, constraints.cl_v.clone())).chain(
        CR_POWERS.iter().enumerate().map(|(j, &a)| {
            let mut beta_e_j = vec![S::zero(); H_LEN];
            beta_e_j[j] = beta;
            (a, beta_e_j)
        }),
    ))
}

/// The opening `(sigma, l, n) = (r[0], (r[1], ..., r[7], 0), n)` of the
/// commitment `r[0]*G + r[1]*H_0 + ... + r[7]*H_6 + <n, G_vec>` to the norm
/// vector `n` with blinding `r`, as for `C_O`, `C_L` and `C_R`. The
/// coefficient of `H_7`, the linear witness, is zero.
fn message_opening(r: &[S], n: Vec<S>) -> Opening {
    let mut l = r[1..].to_vec();
    l.push(S::zero());
    Opening { sigma: r[0], l, n }
}

/// The vector `r` of length `H_LEN` with `r[p] = 0` if `p >= 1` and
/// `e + CR_POWERS[p-1]` is not in `{-1} ∪ {CR_POWERS[j] - 1 : j = 0..6}`,
/// and `r[p]` uniformly random otherwise.
///
/// `e` is the power of `T` of the commitment in `C(T)`: [C_O_POWER],
/// [C_L_POWER] or [C_R_POWER]. For `p >= 1`, `f(T)` has the term
/// `-beta*r[p]*T^{e + CR_POWERS[p-1]}`, and [solve_r_s] sets only the
/// coefficients of `T^{-1}` and `T^{CR_POWERS[j] - 1}` of `f(T)` to zero.
fn blinding_vector(rng: &mut impl AllowedRng, e: i32) -> Vec<S> {
    let mut r = vec![S::rand(rng)];
    for a in CR_POWERS {
        let power = e + a;
        if power == -1 || CR_POWERS.contains(&(power + 1)) {
            r.push(S::rand(rng));
        } else {
            r.push(S::zero());
        }
    }
    r
}

/// The honest reciprocals `(alpha + d_k)^{-1}` of the digits `n_l` on the
/// real digit slots, zero on the padding.
fn reciprocals(params: &CircuitParams, n_l: &[S], alpha: S) -> FastCryptoResult<Vec<S>> {
    let denominators: Vec<S> = n_l[..params.n_d]
        .iter()
        .map(|digit| alpha + digit)
        .collect();
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
            .flat_map(|&v| to_digits(v, params.d))
            .collect();
        Witness {
            values: to_scalars(values),
            blindings: blindings.to_vec(),
            off_plane: vec![],
            n_l: pad_to(&to_scalars(&digits), params.nm),
            n_o: pad_to(&to_scalars(&multiplicities(&digits)), params.nm),
            r_o: blinding_vector(rng, C_O_POWER),
            r_l: blinding_vector(rng, C_L_POWER),
            r_r: blinding_vector(rng, C_R_POWER),
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

/// The opening `(sigma(T), l(T), n(T))` of the combined commitment
/// `C(T) = sigma(T)*G + <l(T), H> + <n(T), G_vec>`.
struct CombinedOpening {
    sigma: Laurent<S>,
    l: Laurent<Vec<S>>,
    n: Laurent<Vec<S>>,
}

impl CombinedOpening {
    /// The opening `sum_i T^{p_i}*o_i` of the `terms` `(p_i, o_i)`.
    fn from_terms(terms: &[(i32, Opening)]) -> Self {
        CombinedOpening {
            sigma: Laurent::from_terms(terms.iter().map(|(p, o)| (*p, o.sigma))),
            l: Laurent::from_terms(terms.iter().map(|(p, o)| (*p, o.l.clone()))),
            n: Laurent::from_terms(terms.iter().map(|(p, o)| (*p, o.n.clone()))),
        }
    }

    /// This opening with the blinding `r_S[0]` and `H` coordinates `h` of
    /// `C_S` added at `T^{C_S_POWER}`.
    fn with_r_s(self, r_s0: S, h: Vec<S>) -> Self {
        CombinedOpening {
            sigma: self.sigma + Laurent::monomial(C_S_POWER, r_s0),
            l: self.l + Laurent::monomial(C_S_POWER, h),
            ..self
        }
    }

    /// The opening of `C(tau)`.
    fn eval(&self, tau: S) -> FastCryptoResult<Opening> {
        Ok(Opening {
            sigma: self.sigma.eval(tau)?,
            l: self.l.eval(tau)?,
            n: self.n.eval(tau)?,
        })
    }
}

/// The polynomial `f(T) = sigma(T) - <c(T), l(T)> - |n(T)|^2_mu` for the
/// opening `(sigma(T), l(T), n(T))` of `C(T)`. `C(tau)` satisfies the
/// norm-linear relation iff `f(tau) = 0`. The `T^3` coefficient is zero iff
/// the circuit constraints hold.
fn f(opening: &CombinedOpening, c: &Laurent<Vec<S>>, norm_weights: &[S]) -> Laurent<S> {
    let CombinedOpening { sigma, l, n } = opening;
    sigma.clone() - c.inner_product(l) - n.weighted_inner_product(n, norm_weights)
}

/// The blinding of `C_S` (spec "Choosing r_S"): its `G` coordinate `r_S[0]`
/// and its `H` coordinates `h = (r_S[1..], l_S)`, such that the
/// polynomial [f] vanishes at every power of `T` except `T^3`.
///
/// The residual `f_bar(T)` is `f(T)` with `r_S = 0` and `l_S = 0`, so
///   `f(T) = f_bar(T) + T^{-1}*(r_S[0] - <c(T), h>)`.
/// With `a_j = CR_POWERS[j]`, setting the coefficients of `T^{a_j - 1}` and
/// `T^{-1}` of `f(T)` to zero gives the linear equations
///   `beta*h_j = f_bar[T^{a_j - 1}]`  for `j = 0..6`,
///   `r_S[0] = <cl_v, h> - f_bar[T^{-1}]`,
/// solved in this order. `l_S = h_7` is free.
fn solve_r_s(
    constraints: &Constraints,
    f_bar: &Laurent<S>,
    l_s: S,
    beta: S,
) -> FastCryptoResult<(S, Vec<S>)> {
    let beta_inv = beta.inverse()?;
    let h: Vec<S> = CR_POWERS
        .iter()
        .map(|&a| f_bar.coeff(a - 1) * beta_inv)
        .chain(once(l_s))
        .collect();
    Ok((inner_product(&constraints.cl_v, &h) - f_bar.coeff(-1), h))
}

/// The opening of the combined commitment
/// `C(T) = T^{-1}*C_S + delta*C_O + T*C_L + T^2*C_R + T^3*V_hat + P(T)`,
/// with `P(T) = p_s(T)*G + <p_n(T), G_vec>`, and with the blinding `r_S` and
/// linear witness `l_S` of `C_S` set to zero, so that [f] of it is the
/// residual `f_bar(T)` of [solve_r_s]. The mask `n_S` of `C_S` is included.
/// `n_r` are the committed reciprocals.
fn opening_without_r_s(
    params: &CircuitParams,
    constraints: &Constraints,
    witness: &Witness,
    n_r: Vec<S>,
    delta: S,
    delta_inv: S,
) -> CombinedOpening {
    let two = S::from(2u64);

    // The rescaled aggregate input
    // V_hat = 2*sum_i lambda^{i-1} V_i opens to v_hat on G,
    // 2*sum_i lambda^{i-1} s_i on H_0 and the off-plane coordinates n_V_hat,
    // l_V_hat (zero for honest inputs).
    let weights: Vec<S> = constraints.lambdas[..params.m]
        .iter()
        .map(|l| two * l)
        .collect();
    let mut v_hat = Opening {
        sigma: inner_product(&weights, &witness.values),
        l: vec![S::zero(); H_LEN],
        n: vec![S::zero(); params.nm],
    };
    v_hat.l[0] = inner_product(&weights, &witness.blindings);
    for ((n_i, l_i), w) in witness.off_plane.iter().zip(&weights) {
        v_hat.n = vec_add(&v_hat.n, &vec_scalar_mul(*w, n_i));
        v_hat.l[H_LEN - 1] += *w * l_i;
    }

    let o = message_opening(&witness.r_o, witness.n_o.clone());
    // TODO: Remove if delta is redundant (#1128).
    let delta_o = Opening {
        sigma: delta * o.sigma,
        l: vec_scalar_mul(delta, &o.l),
        n: vec_scalar_mul(delta, &o.n),
    };
    let CombinedOpening { sigma, l, n } = CombinedOpening::from_terms(&[
        (C_O_POWER, delta_o),
        (
            C_L_POWER,
            message_opening(&witness.r_l, witness.n_l.clone()),
        ),
        (C_R_POWER, message_opening(&witness.r_r, n_r)),
        (V_HAT_POWER, v_hat),
    ]);

    let p_n = constraints.p_n(delta_inv);
    let p_s = p_n.weighted_inner_product(&p_n, &constraints.norm_weights)
        + Laurent::monomial(3, two * (constraints.lambda_al + constraints.mu_am));
    CombinedOpening {
        sigma: sigma + p_s,
        l,
        n: n + Laurent::monomial(C_S_POWER, witness.n_s.clone()) + p_n,
    }
}

/// Commit to `C_S` (spec "Choosing r_S"): choose its blinding `r_S` so that
/// [f] of the opening of `C(T)` is zero at every power of `T` except `T^3`.
/// Returns `C_S` and the opening of `C(T)`.
#[allow(clippy::too_many_arguments)]
fn commit_c_s(
    gens: &Generators,
    params: &CircuitParams,
    constraints: &Constraints,
    witness: &Witness,
    n_r: Vec<S>,
    c: &Laurent<Vec<S>>,
    beta: S,
    delta: S,
    delta_inv: S,
) -> FastCryptoResult<(RistrettoPoint, CombinedOpening)> {
    let opening = opening_without_r_s(params, constraints, witness, n_r, delta, delta_inv);
    let f_bar = f(&opening, c, &constraints.norm_weights);
    let (r_s0, h) = solve_r_s(constraints, &f_bar, witness.l_s, beta)?;
    let c_s = gens.commit(&Opening {
        sigma: r_s0,
        l: h.clone(),
        n: witness.n_s.clone(),
    })?;
    Ok((c_s, opening.with_r_s(r_s0, h)))
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
    prove_witness(transcript, gens, params, &witness, &|alpha| {
        reciprocals(params, &witness.n_l, alpha)
    })
}

/// Run the protocol with `witness`, without checking that it is well formed.
///
/// `reciprocals_of(alpha)` gives the committed reciprocals: [prove] passes
/// the honest [reciprocals], and tests pass others.
fn prove_witness(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    params: &CircuitParams,
    witness: &Witness,
    reciprocals_of: &dyn Fn(S) -> FastCryptoResult<Vec<S>>,
) -> FastCryptoResult<(CircuitProof, Vec<PedersenCommitment>)> {
    let v_commitments = witness.input_commitments(gens)?;
    transcript.domain_sep(b"bppp_circuit");
    transcript.append_commits(b"V", &v_commitments);

    // Step 1: commit digits (C_L) and shared multiplicities (C_O).
    let c_l = gens.commit(&message_opening(&witness.r_l, witness.n_l.clone()))?;
    let c_o = gens.commit(&message_opening(&witness.r_o, witness.n_o.clone()))?;
    transcript.append_point(b"C_L", &c_l);
    transcript.append_point(b"C_O", &c_o);

    // Step 2: reciprocal challenge, drawn after the digits and
    // multiplicities are committed.
    let alpha = transcript.challenge_scalar(b"alpha");

    // Step 3: commit the reciprocals (C_R).
    let n_r = reciprocals_of(alpha)?;
    let c_r = gens.commit(&message_opening(&witness.r_r, n_r.clone()))?;
    transcript.append_point(b"C_R", &c_r);

    // Step 4: constraint challenges.
    let rho = transcript.challenge_scalar(b"rho");
    let lambda = transcript.challenge_scalar(b"lambda");
    let beta = transcript.challenge_scalar(b"beta");
    let delta = transcript.challenge_scalar(b"delta");
    let mu = rho * rho;
    let delta_inv = delta.inverse()?;
    let constraints = Constraints::new(params, alpha, mu, lambda)?;

    // Step 5: commit to C_S.
    let c = c(&constraints, beta);
    let (c_s, opening) = commit_c_s(
        gens,
        params,
        &constraints,
        witness,
        n_r,
        &c,
        beta,
        delta,
        delta_inv,
    )?;
    transcript.append_point(b"C_S", &c_s);

    // Step 6: evaluation point, drawn after every commitment.
    let tau = transcript.challenge_scalar(b"tau");

    // Step 7: evaluate the opening of C(tau) and run the norm-linear argument.
    let nl_proof = norm_linear::prove(transcript, gens, &c.eval(tau)?, rho, &opening.eval(tau)?)?;

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
    let tau_pow = |power: i32| Laurent::monomial(power, one()).eval(tau);

    let constraints = Constraints::new(params, alpha, mu, lambda)?;
    let p_n_tau = constraints.p_n(delta_inv).eval(tau)?;
    // p_s(tau) = |p_n(tau)|^2_mu + 2*(lambda_al + mu_am)*tau^3, evaluated
    // directly on p_n_tau rather than via the coefficients of p_s(T).
    let p_s_tau = weighted_norm(&p_n_tau, mu)
        + S::from(2u64) * (constraints.lambda_al + constraints.mu_am) * tau_pow(3)?;
    let c_tau = c(&constraints, beta).eval(tau)?;

    // Combined commitment, decomposed so it joins the norm-linear verifier's
    // single MSM (g_vec is touched only there):
    //   C(tau) = <p_n(tau), G_vec> + p_s(tau)*G
    //          + tau^{-1}*C_S + delta*C_O + tau*C_L + tau^2*C_R + tau^3*V_hat
    // with V_hat = 2*sum_i lambda^{i-1} V_i.
    let mut extra = vec![
        (tau_pow(C_S_POWER)?, proof.c_s),
        (delta * tau_pow(C_O_POWER)?, proof.c_o),
        (tau_pow(C_L_POWER)?, proof.c_l),
        (tau_pow(C_R_POWER)?, proof.c_r),
    ];
    let v_hat_weight = S::from(2u64) * tau_pow(V_HAT_POWER)?;
    for (i, v_i) in v_commitments.iter().enumerate() {
        extra.push((v_hat_weight * constraints.lambdas[i], v_i.0));
    }

    norm_linear::verify(
        transcript,
        gens,
        &c_tau,
        p_s_tau,
        &p_n_tau,
        &extra,
        rho,
        &proof.nl_proof,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blinding_zero_patterns() {
        // C_O, C_L and C_R enter C(T) at T^0, T^1 and T^2.
        let mut rng = rand::thread_rng();
        let mut zeros = |e| -> Vec<usize> {
            let r = blinding_vector(&mut rng, e);
            (0..H_LEN).filter(|&i| r[i] == S::zero()).collect()
        };
        assert_eq!(zeros(0), [4, 7]);
        assert_eq!(zeros(1), [3, 6, 7]);
        assert_eq!(zeros(2), [2, 5, 6, 7]);
    }

    #[test]
    fn test_params_dimensions() {
        let dims = |range, m| {
            let p = CircuitParams::new(range, m).unwrap();
            (p.d, p.n_d, p.nm)
        };
        assert_eq!(dims(Range::Bits64, 1), (16, 16, 16));
        // Fewer digits than the multiplicity floor: nm stays at 16.
        assert_eq!(dims(Range::Bits16, 1), (4, 4, 16));
        assert_eq!(dims(Range::Bits32, 1), (8, 8, 16));
        assert_eq!(dims(Range::Bits8, 1), (2, 2, 16));
        // Batches, including non-power-of-two digit counts.
        assert_eq!(dims(Range::Bits16, 2), (4, 8, 16));
        assert_eq!(dims(Range::Bits16, 4), (4, 16, 16));
        assert_eq!(dims(Range::Bits16, 5), (4, 20, 32));
        assert_eq!(dims(Range::Bits16, 8), (4, 32, 32));
        assert_eq!(dims(Range::Bits32, 8), (8, 64, 64));
        assert_eq!(dims(Range::Bits64, 16), (16, 256, 256));
        assert!(CircuitParams::new(Range::Bits64, 0).is_err());
    }
    use crate::bulletproofspp::constraints::value_row;
    use std::array::from_fn;
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
        let params = CircuitParams::new(range, values.len()).unwrap();
        let gens = Generators::new(params.nm).unwrap();
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
    fn test_honest_f_is_zero() {
        // For an honest witness, f(T) with the solved r_S vanishes identically: off T^3 by the choice of r_S, and
        // at T^3 because the constraints hold.
        let mut rng = rand::thread_rng();
        for (range, m) in [(Range::Bits64, 1), (Range::Bits16, 4), (Range::Bits8, 3)] {
            let params = CircuitParams::new(range, m).unwrap();
            let values: Vec<u64> = (0..m)
                .map(|_| rand::Rng::gen::<u64>(&mut rng) & range.max_value())
                .collect();
            let witness = honest_witness(&params, &values);
            let [alpha, mu, lambda, beta, delta] = from_fn(|_| S::rand(&mut rng));
            let constraints = Constraints::new(&params, alpha, mu, lambda).unwrap();
            let n_r = reciprocals(&params, &witness.n_l, alpha).unwrap();
            let delta_inv = delta.inverse().unwrap();
            let c = c(&constraints, beta);
            let opening_without_r_s = opening_without_r_s(
                &params,
                &constraints,
                &witness,
                n_r.clone(),
                delta,
                delta_inv,
            );
            assert!(!f(&opening_without_r_s, &c, &constraints.norm_weights).is_zero());

            let gens = Generators::new(params.nm).unwrap();
            let (_, opening) = commit_c_s(
                &gens,
                &params,
                &constraints,
                &witness,
                n_r,
                &c,
                beta,
                delta,
                delta_inv,
            )
            .unwrap();
            assert!(f(&opening, &c, &constraints.norm_weights).is_zero());
        }
    }

    #[test]
    fn test_value_row_matches_the_paper() {
        // For any witness with inputs on the (G, H_0)-plane, the T^3
        // coefficient of f(T) is the value row (29)-(30).
        let mut rng = rand::thread_rng();
        for (range, m) in [(Range::Bits64, 1), (Range::Bits16, 4), (Range::Bits8, 3)] {
            let params = CircuitParams::new(range, m).unwrap();
            let [alpha, mu, lambda, beta, delta] = from_fn(|_| S::rand(&mut rng));
            let mut random = |len: usize| (0..len).map(|_| S::rand(&mut rng)).collect::<Vec<S>>();
            let mut witness = honest_witness(&params, &vec![0; m]);
            witness.values = random(m);
            witness.n_l = random(params.nm);
            witness.n_o = random(params.nm);
            let n_r = random(params.nm);

            let constraints = Constraints::new(&params, alpha, mu, lambda).unwrap();
            let delta_inv = delta.inverse().unwrap();
            let opening = opening_without_r_s(
                &params,
                &constraints,
                &witness,
                n_r.clone(),
                delta,
                delta_inv,
            );
            let f_bar = f(&opening, &c(&constraints, beta), &constraints.norm_weights);
            let value_row = value_row(
                &params,
                alpha,
                mu,
                lambda,
                &witness.values,
                &witness.n_l,
                &n_r,
                &witness.n_o,
            );
            assert_eq!(f_bar.coeff(3), value_row);
        }
    }

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
        let params = CircuitParams::new(Range::Bits16, 2).unwrap();
        let gens = Generators::new(params.nm).unwrap();
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
        let params = CircuitParams::new(range, m).unwrap();
        let gens = Generators::new(params.nm).unwrap();
        let mut t = BpppTranscript::new(b"test");
        let honest = |alpha| reciprocals(&params, &witness.n_l, alpha);
        let (proof, v_commitments) = prove_witness(
            &mut t,
            &gens,
            &params,
            witness,
            bad_reciprocals.unwrap_or(&honest),
        )
        .unwrap();
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
