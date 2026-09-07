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

use crate::bulletproofspp::crs::Generators;
#[cfg(test)]
use crate::bulletproofspp::crs::H_LEN;
use crate::bulletproofspp::transcript::BpppTranscript;
use crate::bulletproofspp::util::*;
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Debug;
use typenum::{
    Unsigned, U10, U1024, U11, U128, U16, U2, U2048, U256, U3, U32, U4, U4096, U5, U512, U6, U64,
    U7, U8, U8192, U9,
};

/// Fold until fewer than this many scalars remain; the remaining opening is
/// sent in the clear. 6 balances rounds (2 points each) against final scalars.
const FOLD_THRESHOLD: usize = 6;

/// Norm-linear proof: one `(X, R)` pair per fold round, then the final
/// opening `(l, n)` in the clear (`sigma` is implied by the relation).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub(crate) struct NormLinearProof<N: NormLength> {
    pub(crate) rounds: GenericArray<(RistrettoPoint, RistrettoPoint), N::Rounds>,
    pub(crate) l_final: RistrettoScalar,
    pub(crate) n_final: GenericArray<RistrettoScalar, N::NFinal>,
}

/// A norm length a proof can be made for, together with the dimensions it
/// implies: how many fold rounds the proof has, and how long its final `n`
/// opening is.
pub trait NormLength: Unsigned {
    /// Number of fold rounds, each contributing an `(X, R)` pair.
    type Rounds: ArrayLength<(RistrettoPoint, RistrettoPoint)> + Debug;
    /// Length of the final `n` opening.
    type NFinal: ArrayLength<RistrettoScalar> + Debug;
}

/// One row of the table: norm length, rounds, final `n` length.
macro_rules! norm_lengths {
    ($($n:ty => ($rounds:ty, $n_final:ty)),* $(,)?) => {
        $(impl NormLength for $n {
            type Rounds = $rounds;
            type NFinal = $n_final;
        })*
    };
}

// Norm lengths a statement can actually have: powers of two from BASE up.
norm_lengths! {
    U16 => (U3, U2),
    U32 => (U3, U4),
    U64 => (U4, U4),
    U128 => (U5, U4),
    U256 => (U6, U4),
    U512 => (U7, U4),
    U1024 => (U8, U4),
    U2048 => (U9, U4),
    U4096 => (U10, U4),
    U8192 => (U11, U4),
}

// An odd norm length, so the tests can still exercise the padding path. No
// statement produces one, since `nm` is rounded to a power of two.
#[cfg(test)]
norm_lengths! {
    typenum::U15 => (U3, U2),
    typenum::U31 => (U3, U4),
}

/// Rounds and final `n` length for `(l_len, n_len)`; final `l` is always 1.
/// Production reads the [NormLength] table; this defines what it must equal.
#[cfg(test)]
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

fn pad_even_scalar(v: &mut Vec<RistrettoScalar>) {
    if !v.len().is_multiple_of(2) {
        v.push(RistrettoScalar::zero());
    }
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
    even_elements(p)
        .iter()
        .zip(odd_elements(p))
        .map(|(p0, p1)| *p0 * f0 + p1 * f1)
        .collect()
}

/// Execute deferred folds at once, collapsing the lazily folded generators
/// into real points: `out[j] = sum_t w[t] * base[j*|w| + t]`.
fn batch_fold(
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

/// Prove the norm-linear relation for the opening `(l, n)` of a commitment
/// under `gens`. Requires `l`, `c`, `gens.h_vec` of equal length and `n`,
/// `gens.g_vec` of equal length.
///
/// Generator folding is lazy: no points are folded per round. After `levels`
/// rounds (since the last batch fold) the current generators are implicit,
///   `H'_j = sum_t w_h[t] * base_h[j*2^levels + t]`, `w_h = tensor_i (1, gamma_i)`,
///   `G'_j = sum_t w_g[t] * base_g[j*2^levels + t]`, `w_g = tensor_i (rho_i, gamma_i)`
/// (newest round in the top bit; absent base points read as the identity,
/// reproducing the odd-length padding), so each round's X and R are single
/// MSMs over the base generators with tensor-expanded coefficients — over
/// the precomputed tables while the base is still the original CRS.
pub(crate) fn prove<N: NormLength>(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    c: &[RistrettoScalar],
    rho: RistrettoScalar,
    l: &[RistrettoScalar],
    n: &[RistrettoScalar],
) -> FastCryptoResult<NormLinearProof<N>> {
    debug_assert_eq!(l.len(), c.len());
    debug_assert_eq!(l.len(), gens.h_vec.len());
    debug_assert_eq!(n.len(), gens.g_vec.len());
    let two = RistrettoScalar::from(2u64);
    let mut l = l.to_vec();
    let mut n = n.to_vec();
    let mut c = c.to_vec();
    let mut base_h = Cow::Borrowed(gens.h_vec.as_slice());
    let mut base_g = Cow::Borrowed(gens.g_vec.as_slice());
    let mut w_h: Vec<RistrettoScalar> = vec![one()];
    let mut w_g: Vec<RistrettoScalar> = vec![one()];
    let mut levels: u32 = 0;
    let mut rho = rho;
    let mut mu = rho * rho;
    let mut rounds = Vec::new();

    transcript.domain_sep(b"norm_linear");

    while l.len() > 1 || l.len() + n.len() >= FOLD_THRESHOLD {
        if levels == FOLD_BATCH_ROUNDS {
            base_h = Cow::Owned(batch_fold(&base_h, &w_h)?);
            base_g = Cow::Owned(batch_fold(&base_g, &w_g)?);
            w_h = vec![one()];
            w_g = vec![one()];
            levels = 0;
        }

        pad_even_scalar(&mut l);
        pad_even_scalar(&mut n);
        pad_even_scalar(&mut c);

        let l0 = even_elements(&l);
        let l1 = odd_elements(&l);
        let n0 = even_elements(&n);
        let n1 = odd_elements(&n);
        let c0 = even_elements(&c);
        let c1 = odd_elements(&c);

        let rho_inv = rho.inverse()?;
        let mu2 = mu * mu;

        // gamma^1 and (gamma^2 - 1) coefficients of the folded opening:
        //   vx = 2*rho^{-1}*<n0, n1>_{mu^2} + <c0, l1> + <c1, l0>
        //   vr = |n1|^2_{mu^2} + <c1, l1>
        let vx = two * rho_inv * weighted_inner_product(&n0, &n1, mu2)
            + inner_product(&c0, &l1)
            + inner_product(&c1, &l0);
        let vr = weighted_norm(&n1, mu2) + inner_product(&c1, &l1);

        // Per folded position, X carries the cross terms and R the odd-odd
        // terms:
        //   X = vx*G + <l1, H'_even> + <l0, H'_odd> + rho*<n1, G'_even> + rho^{-1}*<n0, G'_odd>
        //   R = vr*G + <l1, H'_odd> + <n1, G'_odd>
        let mut xh = vec![RistrettoScalar::zero(); l.len()];
        let mut rh = vec![RistrettoScalar::zero(); l.len()];
        for s in 0..l.len() / 2 {
            xh[2 * s] = l1[s];
            xh[2 * s + 1] = l0[s];
            rh[2 * s + 1] = l1[s];
        }
        let mut xg = vec![RistrettoScalar::zero(); n.len()];
        let mut rg = vec![RistrettoScalar::zero(); n.len()];
        for s in 0..n.len() / 2 {
            xg[2 * s] = rho * n1[s];
            xg[2 * s + 1] = rho_inv * n0[s];
            rg[2 * s + 1] = n1[s];
        }

        // Expand folded-position coefficients onto the base generators: base
        // index i contributes w[t] * coeff[j] with j = i >> levels,
        // t = i & (2^levels - 1); absent or zero coefficients stay zero.
        let mask = (1usize << levels) - 1;
        let expand = |w: &[RistrettoScalar], coeffs: &[RistrettoScalar], base_len: usize| {
            (0..base_len)
                .map(|i| {
                    let (j, t) = (i >> levels, i & mask);
                    match coeffs.get(j) {
                        Some(c) if *c != RistrettoScalar::zero() => w[t] * c,
                        _ => RistrettoScalar::zero(),
                    }
                })
                .collect::<Vec<_>>()
        };
        let xh_base = expand(&w_h, &xh, base_h.len());
        let rh_base = expand(&w_h, &rh, base_h.len());
        let xg_base = expand(&w_g, &xg, base_g.len());
        let rg_base = expand(&w_g, &rg, base_g.len());

        // One MSM per commitment: over the precomputed tables while the base
        // is the original CRS, afterwards a dynamic MSM over the shrunken
        // base, skipping zero coefficients (R's even positions, padding).
        let msm = |v: RistrettoScalar,
                   h: &[RistrettoScalar],
                   g: &[RistrettoScalar]|
         -> FastCryptoResult<RistrettoPoint> {
            if h.len() == gens.h_vec.len() && g.len() == gens.g_vec.len() {
                return gens.msm(v, h.iter().copied(), g.iter().copied(), &[], &[]);
            }
            let (sc, pts): (Vec<RistrettoScalar>, Vec<RistrettoPoint>) =
                std::iter::once((&v, &gens.g))
                    .chain(h.iter().zip(base_h.iter()))
                    .chain(g.iter().zip(base_g.iter()))
                    .filter(|(s, _)| **s != RistrettoScalar::zero())
                    .map(|(s, p)| (*s, *p))
                    .unzip();
            RistrettoPoint::multi_scalar_mul(&sc, &pts)
        };
        let x_point = msm(vx, &xh_base, &xg_base)?;
        let r_point = msm(vr, &rh_base, &rg_base)?;

        transcript.append_point(b"X", &x_point);
        transcript.append_point(b"R", &r_point);
        rounds.push((x_point, r_point));
        let gamma = transcript.challenge_scalar(b"gamma");

        // Fold the scalar vectors: l' = l0 + gamma*l1,
        // n' = rho^{-1}*n0 + gamma*n1, c' = c0 + gamma*c1.
        l = vec_add(&l0, &vec_scalar_mul(gamma, &l1));
        n = vec_add(&vec_scalar_mul(rho_inv, &n0), &vec_scalar_mul(gamma, &n1));
        c = vec_add(&c0, &vec_scalar_mul(gamma, &c1));

        // Grow the implicit fold tensors by one level:
        // H' = H0 + gamma*H1, G' = rho*G0 + gamma*G1.
        w_h = tensor_grow(&w_h, one(), gamma);
        w_g = tensor_grow(&w_g, rho, gamma);
        levels += 1;

        rho = mu;
        mu = mu2;
    }

    transcript.append_scalar(b"l_final", &l[0]);
    transcript.append_scalars(b"n_final", &n);

    // The fold ran the shape `N` promises, so these are exactly full; a
    // caller that named the wrong `N` is caught here rather than silently
    // producing a proof of another shape.
    debug_assert_eq!(l.len(), 1);
    Ok(NormLinearProof::<N> {
        rounds: GenericArray::from_exact_iter(rounds).ok_or(FastCryptoError::InvalidInput)?,
        l_final: l[0],
        n_final: GenericArray::from_exact_iter(n).ok_or(FastCryptoError::InvalidInput)?,
    })
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
pub(crate) fn verify<N: NormLength>(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    c: &[RistrettoScalar],
    ps: RistrettoScalar,
    pn: &[RistrettoScalar],
    extra: &[(RistrettoScalar, RistrettoPoint)],
    rho: RistrettoScalar,
    proof: &NormLinearProof<N>,
) -> FastCryptoResult<()> {
    if c.len() != gens.h_vec.len() || pn.len() != gens.g_vec.len() || gens.g_vec.len() != N::USIZE {
        return Err(FastCryptoError::InvalidInput);
    }

    let k = proof.rounds.len();
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
        pad_even_scalar(&mut c);
        c = vec_add(
            &even_elements(&c),
            &vec_scalar_mul(gamma, &odd_elements(&c)),
        );

        rho = mu;
        mu = mu * mu;
    }

    transcript.append_scalar(b"l_final", &proof.l_final);
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
    use typenum::{U15, U31};

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

    fn prove_instance<N: NormLength>(inst: &Instance) -> NormLinearProof<N> {
        let mut t = BpppTranscript::new(b"test");
        prove(&mut t, &inst.gens, &inst.c, inst.rho, &inst.l, &inst.n).unwrap()
    }

    fn verify_instance<N: NormLength>(
        inst: &Instance,
        proof: &NormLinearProof<N>,
    ) -> FastCryptoResult<()> {
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

    /// A random instance at the base lengths `N` implies.
    fn instance_for<N: NormLength>() -> Instance {
        random_instance(H_LEN, N::USIZE)
    }

    /// The table is the only source of a proof's lengths, so it must agree
    /// with the fold that actually runs.
    #[test]
    fn test_table_matches_the_fold() {
        fn check<N: NormLength>() {
            assert_eq!(
                (N::Rounds::USIZE, N::NFinal::USIZE),
                proof_shape(H_LEN, N::USIZE),
                "table wrong for norm length {}",
                N::USIZE
            );
        }
        check::<U15>();
        check::<U16>();
        check::<U32>();
        check::<U64>();
        check::<U128>();
        check::<U256>();
        check::<U512>();
        check::<U1024>();
        check::<U2048>();
        check::<U4096>();
        check::<U8192>();
    }

    #[test]
    fn test_roundtrip_sizes() {
        // U16 is the 64-bit range-proof shape: 3 rounds, l plus 2 scalars.
        // U15 is an odd length exercising padding, U64 the aggregated
        // 32-bit x 8 shape (4 rounds, 4 final n).
        fn roundtrip<N: NormLength>() {
            let inst = instance_for::<N>();
            let proof = prove_instance::<N>(&inst);
            assert_eq!(proof.rounds.len(), N::Rounds::USIZE);
            assert_eq!(proof.n_final.len(), N::NFinal::USIZE);
            assert!(
                verify_instance(&inst, &proof).is_ok(),
                "roundtrip failed for norm length {}",
                N::USIZE
            );
        }
        roundtrip::<U15>();
        roundtrip::<U16>();
        roundtrip::<U32>();
        roundtrip::<U64>();
    }

    #[test]
    fn test_tampered_proof_fails() {
        let inst = instance_for::<U16>();
        let proof = prove_instance::<U16>(&inst);

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
        let inst = instance_for::<U16>();
        let proof = prove_instance::<U16>(&inst);

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
        fn check<N: NormLength>() {
            let inst = instance_for::<N>();
            let proof = prove_instance::<N>(&inst);
            let mut shifted = inst.clone();
            shifted.commitment = inst.commitment + inst.gens.g;
            assert!(
                verify_instance(&shifted, &proof).is_err(),
                "sigma shift accepted for norm length {}",
                N::USIZE
            );
        }
        check::<U15>();
        check::<U16>();
        check::<U32>();
    }

    /// Every final scalar is bound, including the slots that exist only
    /// because of odd-length padding. A folded generator that collapsed to
    /// the identity would leave its slot free; these shapes pad at several
    /// rounds and must still bind each coordinate.
    #[test]
    fn test_every_final_scalar_is_bound() {
        fn check<N: NormLength>() {
            let n_len = N::USIZE;
            let inst = instance_for::<N>();
            let proof = prove_instance::<N>(&inst);
            assert!(verify_instance(&inst, &proof).is_ok());

            let mut bad = proof.clone();
            bad.l_final += RistrettoScalar::generator();
            assert!(
                verify_instance(&inst, &bad).is_err(),
                "l_final unbound for norm length {n_len}"
            );
            for i in 0..proof.n_final.len() {
                let mut bad = proof.clone();
                bad.n_final[i] += RistrettoScalar::generator();
                assert!(
                    verify_instance(&inst, &bad).is_err(),
                    "n_final[{i}] unbound for norm length {n_len}"
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
                        "round {i} point {which} unbound for norm length {n_len}"
                    );
                }
            }
        }
        check::<U15>();
        check::<U16>();
        check::<U64>();
    }

    /// No folded generator may collapse to the identity: the odd-length
    /// padding uses the identity point, and if it ever survived a fold the
    /// corresponding witness slot would be unconstrained.
    #[test]
    fn test_folded_generators_are_nondegenerate() {
        fn check<N: NormLength>() {
            let n_len = N::USIZE;
            let inst = instance_for::<N>();
            let mut t = BpppTranscript::new(b"test");
            let mut h_vec = inst.gens.h_vec.clone();
            let mut g_vec = inst.gens.g_vec.clone();
            let mut rho = inst.rho;
            let mut mu = rho * rho;
            let proof: NormLinearProof<N> =
                prove(&mut t, &inst.gens, &inst.c, inst.rho, &inst.l, &inst.n).unwrap();

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
                        "folded generator {i} is the identity for norm length {n_len}"
                    );
                }
            }
        }
        check::<U15>();
        check::<U16>();
        check::<U31>();
        check::<U64>();
    }

    #[test]
    fn test_serde_roundtrip() {
        fn roundtrip<N: NormLength>() {
            let inst = instance_for::<N>();
            let proof = prove_instance::<N>(&inst);
            let bytes = bcs::to_bytes(&proof).unwrap();
            // 32 bytes per group element and scalar, and nothing else.
            assert_eq!(
                bytes.len(),
                32 * (2 * N::Rounds::USIZE + 1 + N::NFinal::USIZE)
            );

            let recovered: NormLinearProof<N> = bcs::from_bytes(&bytes).unwrap();
            assert!(verify_instance(&inst, &recovered).is_ok());

            // Truncated and trailing-byte encodings are rejected.
            assert!(bcs::from_bytes::<NormLinearProof<N>>(&bytes[..bytes.len() - 32]).is_err());
            let mut extended = bytes.clone();
            extended.push(0);
            assert!(bcs::from_bytes::<NormLinearProof<N>>(&extended).is_err());
        }
        roundtrip::<U15>();
        roundtrip::<U16>();
        roundtrip::<U32>();
        roundtrip::<U64>();
    }

    #[test]
    fn test_wrong_norm_length_fails() {
        let proof = prove_instance::<U16>(&instance_for::<U16>());
        let wider = instance_for::<U32>();
        assert_eq!(
            verify_instance(&wider, &proof),
            Err(FastCryptoError::InvalidInput)
        );
    }
}
