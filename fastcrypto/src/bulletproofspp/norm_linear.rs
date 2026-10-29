// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Weighted norm-linear argument (spec, "Norm-linear argument"; BP++ paper §4).
//!
//! Proves knowledge of an opening `(sigma, l, n)` of
//! `C = sigma*G + <l, H> + <n, G_vec>` satisfying
//! `sigma = <c, l> + |n|^2_mu` with `mu = rho^2`, for public `c` and `rho`.
//! Each round halves `l` and `n` by a symmetric even/odd fold until fewer
//! than 6 scalars remain, which are then sent in the clear.

use crate::error::{FastCryptoError, FastCryptoResult};
use crate::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use crate::groups::{GroupElement, MultiScalarMul, Scalar};
use crate::serde_helpers::ToFromByteArray;
use itertools::Itertools;

use crate::bulletproofspp::crs::{Generators, BASE, H_LEN};
use crate::bulletproofspp::transcript::BpppTranscript;
use crate::bulletproofspp::util::*;

/// Fold until fewer than this many scalars remain; the remaining opening is
/// sent in the clear. 6 balances rounds (2 points each) against final scalars.
const FOLD_THRESHOLD: usize = 6;

/// Largest `log2(n_len)` a decoded proof may claim; bounds the shape search
/// in [NormLinearProof::proof_shape_for_serialized_len] far above any
/// practical statement (2^32 norm slots is 2^28 values of 64 bits).
const MAX_LOG_N_LEN: u32 = 32;

/// Norm-linear proof: one `(X, R)` pair per fold round, then the final
/// opening `(l, n)` in the clear (`sigma` is implied by the relation).
/// Folding runs until `l` is a single scalar, so only `rounds` and
/// `n_final` are variable-length.
#[derive(Clone, Debug)]
pub(crate) struct NormLinearProof {
    pub(crate) rounds: Vec<(RistrettoPoint, RistrettoPoint)>,
    pub(crate) l_final: RistrettoScalar,
    pub(crate) n_final: Vec<RistrettoScalar>,
}

impl NormLinearProof {
    /// Serialized size of a proof for initial vector lengths `(l_len, n_len)`.
    fn serialized_len_for(l_len: usize, n_len: usize) -> usize {
        let (rounds, n_len) = proof_shape(l_len, n_len);
        32 * (2 * rounds + 1 + n_len)
    }

    /// The shape of a proof with this serialized size: `l_len = H_LEN`, `n_len` a power of two `>= BASE`.
    fn proof_shape_for_serialized_len(len: usize) -> FastCryptoResult<(usize, usize)> {
        (BASE.ilog2()..=MAX_LOG_N_LEN)
            .map(|k| 1usize << k)
            .find(|&n_len| Self::serialized_len_for(H_LEN, n_len) == len)
            .map(|n_len| proof_shape(H_LEN, n_len))
            .ok_or(FastCryptoError::InvalidInput)
    }

    pub(crate) fn serialized_len(&self) -> usize {
        32 * (2 * self.rounds.len() + 1 + self.n_final.len())
    }

    /// Serialize: the per-round `(X, R)` pairs, then `l_final`, then
    /// `n_final`, 32 bytes each.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.serialized_len());
        for (x, r) in &self.rounds {
            bytes.extend(x.to_byte_array());
            bytes.extend(r.to_byte_array());
        }
        bytes.extend(self.l_final.to_byte_array());
        for scalar in &self.n_final {
            bytes.extend(scalar.to_byte_array());
        }
        bytes
    }

    /// Deserialize. The byte length alone selects the proof shape, see
    /// [Self::proof_shape_for_serialized_len]; consistency with the statement
    /// is checked at verification.
    pub(crate) fn from_bytes(bytes: &[u8]) -> FastCryptoResult<Self> {
        let (rounds, n_len) = Self::proof_shape_for_serialized_len(bytes.len())?;
        let mut chunks = bytes.chunks_exact(32);
        let rounds = (0..rounds)
            .map(|_| Ok((decode_next(&mut chunks)?, decode_next(&mut chunks)?)))
            .collect::<FastCryptoResult<Vec<_>>>()?;
        let l_final = decode_next(&mut chunks)?;
        let n_final = (0..n_len)
            .map(|_| decode_next(&mut chunks))
            .collect::<FastCryptoResult<Vec<_>>>()?;
        Ok(NormLinearProof {
            rounds,
            l_final,
            n_final,
        })
    }
}

/// The shape of a proof for initial sizes `(l_len, n_len)`: the number of
/// rounds and the final `n` length. Each round pads to even length and
/// halves, and folding continues until `l` is a single scalar, so the final
/// `l` length is always 1 and is not reported.
fn proof_shape(mut l_len: usize, mut n_len: usize) -> (usize, usize) {
    let mut rounds = 0;
    while l_len > 1 || l_len + n_len >= FOLD_THRESHOLD {
        l_len = l_len.div_ceil(2);
        n_len = n_len.div_ceil(2);
        rounds += 1;
    }
    (rounds, n_len)
}

/// Grow a fold tensor by one level, the new round in the top bit:
/// `[w*f0.., w*f1..]`, i.e. entry `t + b*|w|` is `w[t]` times `f1` if `b`
/// else `f0`.
fn tensor_grow(
    w: &[RistrettoScalar],
    f0: RistrettoScalar,
    f1: RistrettoScalar,
) -> Vec<RistrettoScalar> {
    let mut next = Vec::with_capacity(2 * w.len());
    next.extend(w.iter().map(|wt| *wt * f0));
    next.extend(w.iter().map(|wt| *wt * f1));
    next
}

#[cfg(test)]
fn pad_even_point(v: &mut Vec<RistrettoPoint>) {
    if !v.len().is_multiple_of(2) {
        v.push(RistrettoPoint::zero());
    }
}

/// Element-wise point fold `f0*[p]_0 + f1*[p]_1` of the even/odd halves.
/// Test-only reference for the lazy folding in [prove].
#[cfg(test)]
fn fold_points(
    p: &[RistrettoPoint],
    f0: RistrettoScalar,
    f1: RistrettoScalar,
) -> Vec<RistrettoPoint> {
    p.iter()
        .tuples()
        .map(|(p0, p1)| *p0 * f0 + p1 * f1)
        .collect()
}

/// Return `ceil(base.len() / w.len())` points defined by
/// `out[j] = sum_t w[t] * base[j*w.len() + t]`, where absent points of `base`
/// count as zero.
fn apply_weights(
    base: &[RistrettoPoint],
    w: &[RistrettoScalar],
) -> FastCryptoResult<Vec<RistrettoPoint>> {
    base.chunks(w.len())
        .map(|chunk| RistrettoPoint::multi_scalar_mul(&w[..chunk.len()], chunk))
        .collect()
}

/// Batch-fold the base generators every this many rounds: one
/// `2^FOLD_BATCH_ROUNDS`-term MSM per surviving generator is ~4x cheaper
/// than the equivalent chain of per-round 2-term combinations.
const FOLD_BATCH_ROUNDS: u32 = 3;

/// The points the pending fold weights of [LazyBases] apply to.
enum BasePoints<'a> {
    Crs(&'a Generators),
    Folded {
        g: RistrettoPoint,
        folded: (Vec<RistrettoPoint>, Vec<RistrettoPoint>),
    },
}

/// The current round's bases `H`, `G_vec`, folded lazily: folds are kept
/// as weights and materialised every [FOLD_BATCH_ROUNDS] rounds.
struct LazyBases<'a> {
    points: BasePoints<'a>,
    weights: (Vec<RistrettoScalar>, Vec<RistrettoScalar>),
}

impl<'a> LazyBases<'a> {
    fn new(gens: &'a Generators) -> Self {
        LazyBases {
            points: BasePoints::Crs(gens),
            weights: (vec![one()], vec![one()]),
        }
    }

    /// The bases for the next, half-length round: each new base combines
    /// two adjacent current ones, `H'_j = H_{2j} + gamma*H_{2j+1}` and
    /// `G'_j = rho*G_{2j} + gamma*G_{2j+1}`.
    fn fold(self, rho: RistrettoScalar, gamma: RistrettoScalar) -> Self {
        LazyBases {
            weights: (
                tensor_grow(&self.weights.0, one(), gamma),
                tensor_grow(&self.weights.1, rho, gamma),
            ),
            ..self
        }
    }

    /// The base `G` and the `(h_vec, g_vec)` vectors the weights currently
    /// apply to.
    fn points(&self) -> (RistrettoPoint, (&[RistrettoPoint], &[RistrettoPoint])) {
        match &self.points {
            BasePoints::Crs(gens) => (gens.g, (&gens.h_vec, &gens.g_vec)),
            BasePoints::Folded {
                g,
                folded: (h_vec, g_vec),
            } => (*g, (h_vec, g_vec)),
        }
    }

    /// The lengths of the `(h_vec, g_vec)` vectors the weights currently
    /// apply to.
    fn len(&self) -> (usize, usize) {
        let (_, (h_vec, g_vec)) = self.points();
        (h_vec.len(), g_vec.len())
    }

    /// `v*G + <h_coeffs, H> + <g_coeffs, G_vec>` over the current bases.
    fn msm(
        &mut self,
        v: RistrettoScalar,
        h_coeffs: &[RistrettoScalar],
        g_coeffs: &[RistrettoScalar],
    ) -> FastCryptoResult<RistrettoPoint> {
        // Fold the points every few rounds to keep the MSMs small.
        if self.weights.0.len() == 1 << FOLD_BATCH_ROUNDS {
            let (g, (h_vec, g_vec)) = self.points();
            let folded = (
                apply_weights(h_vec, &self.weights.0)?,
                apply_weights(g_vec, &self.weights.1)?,
            );
            self.points = BasePoints::Folded { g, folded };
            self.weights = (vec![one()], vec![one()]);
        }

        let (h_len, g_len) = self.len();
        let h_scalars = expand(&self.weights.0, h_coeffs, h_len);
        let g_scalars = expand(&self.weights.1, g_coeffs, g_len);
        match &self.points {
            BasePoints::Crs(gens) => gens.msm(v, h_scalars, g_scalars, &[], &[]),
            BasePoints::Folded {
                g,
                folded: (h_vec, g_vec),
            } => {
                let (sc, pts): (Vec<RistrettoScalar>, Vec<RistrettoPoint>) =
                    std::iter::once((v, *g))
                        .chain(h_scalars.zip(h_vec.iter().copied()))
                        .chain(g_scalars.zip(g_vec.iter().copied()))
                        .filter(|(s, _)| *s != RistrettoScalar::zero())
                        .unzip();
                RistrettoPoint::multi_scalar_mul(&sc, &pts)
            }
        }
    }
}

/// Expand coefficients on the folded positions onto the underlying points:
/// point `i` gets `w[i % |w|] * coeffs[i / |w|]`, and zero where the
/// coefficient is absent (padding).
fn expand<'b>(
    w: &'b [RistrettoScalar],
    coeffs: &'b [RistrettoScalar],
    len: usize,
) -> impl Iterator<Item = RistrettoScalar> + 'b {
    (0..len).map(move |i| {
        coeffs
            .get(i / w.len())
            .map_or(RistrettoScalar::zero(), |c| sparse_mul(*c, w[i % w.len()]))
    })
}

/// `a * b`, skipping the multiplication when `a` is zero.
#[inline]
fn sparse_mul(a: RistrettoScalar, b: RistrettoScalar) -> RistrettoScalar {
    if a == RistrettoScalar::zero() {
        a
    } else {
        a * b
    }
}

/// The even- and odd-indexed halves of `v`, padded to even length with a
/// zero.
fn halves(mut v: Vec<RistrettoScalar>) -> (Vec<RistrettoScalar>, Vec<RistrettoScalar>) {
    if !v.len().is_multiple_of(2) {
        v.push(RistrettoScalar::zero());
    }
    v.into_iter().tuples().unzip()
}

/// The vector with even-indexed half `even` and odd-indexed half `odd`.
fn from_halves(even: &[RistrettoScalar], odd: &[RistrettoScalar]) -> Vec<RistrettoScalar> {
    debug_assert_eq!(even.len(), odd.len());
    even.iter().zip(odd).flat_map(|(x, y)| [*x, *y]).collect()
}

/// The vector with odd-indexed half `odd` and zeros at the even indices.
fn from_odd_half(odd: &[RistrettoScalar]) -> Vec<RistrettoScalar> {
    odd.iter()
        .flat_map(|y| [RistrettoScalar::zero(), *y])
        .collect()
}

/// Prove the norm-linear relation for the opening `(l, n)` of a commitment
/// under `gens`. Requires `l`, `c`, `gens.h_vec` of equal length and `n`,
/// `gens.g_vec` of equal length.
pub(crate) fn prove(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    c: &[RistrettoScalar],
    rho: RistrettoScalar,
    l: &[RistrettoScalar],
    n: &[RistrettoScalar],
) -> FastCryptoResult<NormLinearProof> {
    debug_assert_eq!(l.len(), c.len());
    debug_assert_eq!(l.len(), gens.h_vec.len());
    debug_assert_eq!(n.len(), gens.g_vec.len());
    transcript.domain_sep(b"norm_linear");
    prove_rec(
        transcript,
        LazyBases::new(gens),
        c.to_vec(),
        rho,
        l.to_vec(),
        n.to_vec(),
    )
}

/// One round: commit to the cross terms (`X`) and odd-odd terms (`R`) of the
/// folded relation, fold `(c, l, n)` and the bases with the challenge, and
/// recurse on the half-size instance with weight `mu^2`. Once fewer than
/// [FOLD_THRESHOLD] scalars remain the opening is sent in the clear.
///
/// Errors only if `rho` is zero and at least one round is needed.
fn prove_rec(
    transcript: &mut BpppTranscript,
    mut bases: LazyBases<'_>,
    c: Vec<RistrettoScalar>,
    rho: RistrettoScalar,
    l: Vec<RistrettoScalar>,
    n: Vec<RistrettoScalar>,
) -> FastCryptoResult<NormLinearProof> {
    if l.len() <= 1 && l.len() + n.len() < FOLD_THRESHOLD {
        transcript.append_scalars(b"l_final", &l);
        transcript.append_scalars(b"n_final", &n);
        debug_assert_eq!(l.len(), 1);
        return Ok(NormLinearProof {
            rounds: vec![],
            l_final: l[0],
            n_final: n,
        });
    }

    let (l0, l1) = halves(l);
    let (n0, n1) = halves(n);
    let (c0, c1) = halves(c);

    let mu = rho * rho;
    let mu2 = mu * mu;
    let rho_inv = rho.inverse()?;
    let two = RistrettoScalar::from(2u64);

    // gamma^1 and (gamma^2 - 1) coefficients of the folded opening:
    //   vx = 2*rho^{-1}*<n0, n1>_{mu^2} + <c0, l1> + <c1, l0>
    //   vr = |n1|^2_{mu^2} + <c1, l1>
    let vx = two * rho_inv * weighted_inner_product(&n0, &n1, mu2)
        + inner_product(&c0, &l1)
        + inner_product(&c1, &l0);
    let vr = weighted_norm(&n1, mu2) + inner_product(&c1, &l1);

    // X carries the cross terms and R the odd-odd terms:
    //   X = vx*G + <l1, H_even> + <l0, H_odd> + rho*<n1, G_even> + rho^{-1}*<n0, G_odd>
    //   R = vr*G + <l1, H_odd> + <n1, G_odd>
    let x_point = bases.msm(
        vx,
        &from_halves(&l1, &l0),
        &from_halves(&vec_scalar_mul(rho, &n1), &vec_scalar_mul(rho_inv, &n0)),
    )?;
    let r_point = bases.msm(vr, &from_odd_half(&l1), &from_odd_half(&n1))?;

    transcript.append_point(b"X", &x_point);
    transcript.append_point(b"R", &r_point);
    let gamma = transcript.challenge_scalar(b"gamma");

    // Fold: l' = l0 + gamma*l1, n' = rho^{-1}*n0 + gamma*n1,
    // c' = c0 + gamma*c1, and the bases as in [LazyBases::fold].
    let mut proof = prove_rec(
        transcript,
        bases.fold(rho, gamma),
        vec_add(&c0, &vec_scalar_mul(gamma, &c1)),
        mu,
        vec_add(&l0, &vec_scalar_mul(gamma, &l1)),
        vec_add(&vec_scalar_mul(rho_inv, &n0), &vec_scalar_mul(gamma, &n1)),
    )?;
    proof.rounds.insert(0, (x_point, r_point));
    Ok(proof)
}

/// Verify a norm-linear proof in a single multi-scalar multiplication.
///
/// The commitment is supplied in decomposed form so it joins the same MSM:
/// `ps` is its public coefficient on `G`, `pn` its public coefficients over
/// `g_vec` and `extra` the remaining `(scalar, point)` terms, i.e. the
/// commitment equals `ps*G + <pn, g_vec> + sum extra`.
///
/// Instead of folding the generator vectors round by round, each base
/// generator's final coefficient is computed from the bits of its index:
/// position `i` survives the `k` rounds at final slot `i >> k`, picking up
/// per round `r` a factor `gamma_r` when bit `r` of `i` is set, else
/// `rho_r = rho^{2^r}` on the `g_vec` side and `1` on the `h_vec` side.
/// The per-round identity padding never hosts a base generator, so the
/// per-bit product is exact, and the base-case check becomes
///   (sigma - ps)*G + <w_h ⊙ l, H> + <w_g ⊙ n - pn, G_vec>
///     - sum extra - sum_r (gamma_r*X_r + (gamma_r^2 - 1)*R_r) == 0.
///
/// `c` and `pn` must have the lengths of `gens.h_vec` and `gens.g_vec`.
/// Errors with `InvalidProof` on any mismatch, including a proof whose shape
/// differs from the one implied by the base lengths.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    c: &[RistrettoScalar],
    ps: RistrettoScalar,
    pn: &[RistrettoScalar],
    extra: &[(RistrettoScalar, RistrettoPoint)],
    rho: RistrettoScalar,
    proof: &NormLinearProof,
) -> FastCryptoResult<()> {
    if c.len() != gens.h_vec.len() || pn.len() != gens.g_vec.len() {
        return Err(FastCryptoError::InvalidInput);
    }
    // The prover's fold count and final lengths are determined by the base
    // lengths; reject any other shape.
    let (rounds, n_len) = proof_shape(gens.h_vec.len(), gens.g_vec.len());
    if proof.rounds.len() != rounds || proof.n_final.len() != n_len {
        return Err(FastCryptoError::InvalidProof);
    }

    let k = rounds;
    let mut c = c.to_vec();
    let mut rho = rho;
    let mut mu = rho * rho;
    let mut gammas = Vec::with_capacity(k);
    // Challenge-product weights via tensor tables (all 2^k products in
    // 2^{k+1} muls), grown round by round exactly as the prover's:
    // w_h[t] = prod_r (gamma_r if bit_r(t) else 1),
    // w_g[t] = prod_r (gamma_r if bit_r(t) else rho_r).
    let mut w_h = vec![one()];
    let mut w_g = vec![one()];

    transcript.domain_sep(b"norm_linear");

    for (x_point, r_point) in &proof.rounds {
        transcript.append_point(b"X", x_point);
        transcript.append_point(b"R", r_point);
        let gamma = transcript.challenge_scalar(b"gamma");
        gammas.push(gamma);
        w_h = tensor_grow(&w_h, one(), gamma);
        w_g = tensor_grow(&w_g, rho, gamma);

        // Fold only the (cheap) scalar constraint vector.
        let (c0, c1) = halves(c);
        c = vec_add(&c0, &vec_scalar_mul(gamma, &c1));

        rho = mu;
        mu = mu * mu;
    }

    transcript.append_scalars(b"l_final", std::slice::from_ref(&proof.l_final));
    transcript.append_scalars(b"n_final", &proof.n_final);

    // `c` folds exactly as `l` did, so it is a single scalar here too.
    debug_assert_eq!(c.len(), 1);
    let sigma = c[0] * proof.l_final + weighted_norm(&proof.n_final, mu);

    let mask = (1usize << k) - 1;

    let l = (0..gens.h_vec.len()).map(|i| w_h[i & mask] * proof.l_final);
    let n = pn
        .iter()
        .enumerate()
        .map(|(i, pn_i)| w_g[i & mask] * proof.n_final[i >> k] - *pn_i);

    let mut dynamic_scalars = Vec::with_capacity(extra.len() + 2 * k);
    let mut dynamic_points = Vec::with_capacity(extra.len() + 2 * k);
    for (s, p) in extra {
        dynamic_scalars.push(-*s);
        dynamic_points.push(*p);
    }
    for ((x_point, r_point), gamma) in proof.rounds.iter().zip(&gammas) {
        dynamic_scalars.push(-*gamma);
        dynamic_points.push(*x_point);
        dynamic_scalars.push(one() - *gamma * *gamma);
        dynamic_points.push(*r_point);
    }

    let result = gens.msm(sigma - ps, l, n, &dynamic_scalars, &dynamic_points)?;

    if result == RistrettoPoint::zero() {
        Ok(())
    } else {
        Err(FastCryptoError::InvalidProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A random valid instance: a CRS sliced to the requested lengths,
    /// random `(c, rho, l, n)`, and the commitment to `(sigma, l, n)`.
    #[derive(Clone)]
    struct Instance {
        gens: Arc<Generators>,
        c: Vec<RistrettoScalar>,
        rho: RistrettoScalar,
        l: Vec<RistrettoScalar>,
        n: Vec<RistrettoScalar>,
        commitment: RistrettoPoint,
    }

    fn random_instance(l_len: usize, n_len: usize) -> Instance {
        let mut rng = rand::thread_rng();
        let full = Generators::new(crate::pedersen::Range::Bits64, 4).unwrap();
        let gens = Arc::new(
            Generators::from_parts(
                full.g,
                full.h_vec[..l_len].to_vec(),
                full.g_vec[..n_len].to_vec(),
            )
            .unwrap(),
        );
        let rand_vec = |len: usize, rng: &mut rand::rngs::ThreadRng| -> Vec<RistrettoScalar> {
            (0..len).map(|_| RistrettoScalar::rand(rng)).collect()
        };
        let c = rand_vec(l_len, &mut rng);
        let l = rand_vec(l_len, &mut rng);
        let n = rand_vec(n_len, &mut rng);
        let rho = RistrettoScalar::rand(&mut rng);
        let mu = rho * rho;

        let sigma = inner_product(&c, &l) + weighted_norm(&n, mu);
        let mut scalars = vec![sigma];
        let mut points = vec![gens.g];
        scalars.extend(&l);
        points.extend(&gens.h_vec);
        scalars.extend(&n);
        points.extend(&gens.g_vec);
        let commitment = RistrettoPoint::multi_scalar_mul(&scalars, &points).unwrap();

        Instance {
            gens,
            c,
            rho,
            l,
            n,
            commitment,
        }
    }

    fn prove_instance(inst: &Instance) -> NormLinearProof {
        let mut t = BpppTranscript::new(b"test");
        prove(&mut t, &inst.gens, &inst.c, inst.rho, &inst.l, &inst.n).unwrap()
    }

    fn verify_instance(inst: &Instance, proof: &NormLinearProof) -> FastCryptoResult<()> {
        let mut t = BpppTranscript::new(b"test");
        verify(
            &mut t,
            &inst.gens,
            &inst.c,
            RistrettoScalar::zero(),
            &vec![RistrettoScalar::zero(); inst.gens.g_vec.len()],
            &[(one(), inst.commitment)],
            inst.rho,
            proof,
        )
    }

    #[test]
    fn test_roundtrip_sizes() {
        // (8, 16) is the 64-bit range-proof shape: 3 rounds, l plus 2
        // scalars. (8, 15) is the 16/32-bit shape, (8, 64) the aggregated
        // 32-bit x 8 shape (4 rounds, 4 final n). Small and odd sizes
        // exercise padding and the shortest fold.
        for (l_len, n_len) in [(8, 16), (8, 15), (8, 64), (1, 2), (2, 4), (3, 5), (4, 1)] {
            let inst = random_instance(l_len, n_len);
            let proof = prove_instance(&inst);
            let (rounds, fn_) = proof_shape(l_len, n_len);
            assert_eq!(proof.rounds.len(), rounds);
            assert_eq!(proof.n_final.len(), fn_);
            assert!(
                verify_instance(&inst, &proof).is_ok(),
                "roundtrip failed for ({l_len}, {n_len})"
            );
        }
        let inst = random_instance(8, 16);
        assert_eq!(prove_instance(&inst).rounds.len(), 3);
    }

    #[test]
    fn test_tampered_proof_fails() {
        let inst = random_instance(8, 16);
        let proof = prove_instance(&inst);

        let mut bad = proof.clone();
        bad.n_final[0] += RistrettoScalar::generator();
        assert!(verify_instance(&inst, &bad).is_err());

        let mut bad = proof.clone();
        bad.l_final += RistrettoScalar::generator();
        assert!(verify_instance(&inst, &bad).is_err());

        let mut bad = proof.clone();
        bad.rounds[0].0 += inst.gens.g;
        assert!(verify_instance(&inst, &bad).is_err());
    }

    #[test]
    fn test_wrong_statement_fails() {
        let inst = random_instance(8, 16);
        let proof = prove_instance(&inst);

        // Wrong commitment.
        let mut wrong_commitment = inst.clone();
        wrong_commitment.commitment = inst.commitment + inst.gens.g;
        assert!(verify_instance(&wrong_commitment, &proof).is_err());

        // Wrong constraint vector.
        let mut wrong_c = inst.clone();
        wrong_c.c[0] += RistrettoScalar::generator();
        assert!(verify_instance(&wrong_c, &proof).is_err());

        // Wrong weight.
        let mut wrong_rho = inst.clone();
        wrong_rho.rho += RistrettoScalar::generator();
        assert!(verify_instance(&wrong_rho, &proof).is_err());
    }

    /// The relation, not just the commitment, is binding: a commitment built
    /// with any `sigma` other than `<c, l> + |n|^2_mu` must be rejected even
    /// though the prover opens `(l, n)` honestly.
    #[test]
    fn test_wrong_sigma_rejected() {
        for (l_len, n_len) in [(8, 16), (8, 15), (1, 2), (3, 5)] {
            let inst = random_instance(l_len, n_len);
            let proof = prove_instance(&inst);
            let mut shifted = inst.clone();
            shifted.commitment = inst.commitment + inst.gens.g;
            assert!(
                verify_instance(&shifted, &proof).is_err(),
                "sigma shift accepted for ({l_len}, {n_len})"
            );
        }
    }

    /// Every final scalar is bound, including the slots that exist only
    /// because of odd-length padding. A folded generator that collapsed to
    /// the identity would leave its slot free; these shapes pad at several
    /// rounds and must still bind each coordinate.
    #[test]
    fn test_every_final_scalar_is_bound() {
        for (l_len, n_len) in [(8, 16), (8, 15), (8, 64), (3, 5), (2, 4)] {
            let inst = random_instance(l_len, n_len);
            let proof = prove_instance(&inst);
            assert!(verify_instance(&inst, &proof).is_ok());

            let mut bad = proof.clone();
            bad.l_final += RistrettoScalar::generator();
            assert!(
                verify_instance(&inst, &bad).is_err(),
                "l_final unbound for ({l_len}, {n_len})"
            );
            for i in 0..proof.n_final.len() {
                let mut bad = proof.clone();
                bad.n_final[i] += RistrettoScalar::generator();
                assert!(
                    verify_instance(&inst, &bad).is_err(),
                    "n_final[{i}] unbound for ({l_len}, {n_len})"
                );
            }
            for i in 0..proof.rounds.len() {
                for which in 0..2 {
                    let mut bad = proof.clone();
                    let p = if which == 0 {
                        &mut bad.rounds[i].0
                    } else {
                        &mut bad.rounds[i].1
                    };
                    *p += inst.gens.g;
                    assert!(
                        verify_instance(&inst, &bad).is_err(),
                        "round {i} point {which} unbound for ({l_len}, {n_len})"
                    );
                }
            }
        }
    }

    /// No folded generator may collapse to the identity: the odd-length
    /// padding uses the identity point, and if it ever survived a fold the
    /// corresponding witness slot would be unconstrained.
    #[test]
    fn test_folded_generators_are_nondegenerate() {
        for (l_len, n_len) in [(8, 15), (8, 16), (3, 5), (7, 13), (5, 31)] {
            let inst = random_instance(l_len, n_len);
            let mut t = BpppTranscript::new(b"test");
            let mut h_vec = inst.gens.h_vec.clone();
            let mut g_vec = inst.gens.g_vec.clone();
            let mut rho = inst.rho;
            let mut mu = rho * rho;
            let proof = prove(&mut t, &inst.gens, &inst.c, inst.rho, &inst.l, &inst.n).unwrap();

            let mut t = BpppTranscript::new(b"test");
            t.domain_sep(b"norm_linear");
            for (x, r) in &proof.rounds {
                t.append_point(b"X", x);
                t.append_point(b"R", r);
                let gamma = t.challenge_scalar(b"gamma");
                pad_even_point(&mut h_vec);
                pad_even_point(&mut g_vec);
                h_vec = fold_points(&h_vec, one(), gamma);
                g_vec = fold_points(&g_vec, rho, gamma);
                rho = mu;
                mu = mu * mu;
                for (i, p) in h_vec.iter().chain(&g_vec).enumerate() {
                    assert_ne!(
                        *p,
                        RistrettoPoint::zero(),
                        "folded generator {i} is the identity for ({l_len}, {n_len})"
                    );
                }
            }
        }
    }

    #[test]
    fn test_to_from_bytes() {
        for (l_len, n_len) in [(H_LEN, 16), (H_LEN, 32), (H_LEN, 64)] {
            let inst = random_instance(l_len, n_len);
            let proof = prove_instance(&inst);
            let bytes = proof.to_bytes();
            assert_eq!(
                bytes.len(),
                NormLinearProof::serialized_len_for(l_len, n_len)
            );
            let recovered = NormLinearProof::from_bytes(&bytes).unwrap();
            assert!(verify_instance(&inst, &recovered).is_ok());
            assert!(NormLinearProof::from_bytes(&bytes[..bytes.len() - 32]).is_err());
        }
    }

    #[test]
    fn test_wrong_shape_fails() {
        let inst = random_instance(8, 16);
        let proof = prove_instance(&inst);

        let mut truncated = proof.clone();
        truncated.rounds.pop();
        assert_eq!(
            verify_instance(&inst, &truncated),
            Err(FastCryptoError::InvalidProof)
        );

        let mut padded = proof.clone();
        padded.n_final.push(RistrettoScalar::zero());
        assert_eq!(
            verify_instance(&inst, &padded),
            Err(FastCryptoError::InvalidProof)
        );
    }
}
