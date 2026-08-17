// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Weighted norm-linear argument (spec, "Norm-linear argument"; BP++ paper §4).
//!
//! Proves knowledge of an opening `(sigma, l, n)` of
//! `C = sigma*G + <l, H> + <n, G_vec>` satisfying
//! `sigma = <c, l> + |n|^2_mu` with `mu = rho^2`, for public `c` and `rho`.
//! Each round halves `l` and `n` by a symmetric even/odd fold until fewer
//! than 6 scalars remain, which are then sent in the clear.

use fastcrypto::error::{FastCryptoError, FastCryptoResult};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{GroupElement, MixedMultiScalarMul, MultiScalarMul, Scalar};

use crate::bppp::crs::Generators;
use crate::bppp::transcript::BpppTranscript;
use crate::bppp::util::*;

/// Fold until fewer than this many scalars remain; the remaining opening is
/// sent in the clear. 6 balances rounds (2 points each) against final scalars.
const FOLD_THRESHOLD: usize = 6;

/// Norm-linear proof: one `(X, R)` pair per fold round, then the final
/// opening `(l, n)` in the clear (`sigma` is implied by the relation).
#[derive(Clone, Debug)]
pub(crate) struct NormLinearProof {
    pub(crate) rounds: Vec<(RistrettoPoint, RistrettoPoint)>,
    pub(crate) l_final: Vec<RistrettoScalar>,
    pub(crate) n_final: Vec<RistrettoScalar>,
}

/// The vector lengths of a proof for initial sizes `(l_len, n_len)`:
/// number of rounds and final `l`/`n` lengths. Each round pads to even
/// length and halves.
fn proof_shape(mut l_len: usize, mut n_len: usize) -> (usize, usize, usize) {
    let mut rounds = 0;
    while l_len + n_len >= FOLD_THRESHOLD {
        l_len = l_len.div_ceil(2);
        n_len = n_len.div_ceil(2);
        rounds += 1;
    }
    (rounds, l_len, n_len)
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
    let two = RistrettoScalar::from(2u64);
    let mut l = l.to_vec();
    let mut n = n.to_vec();
    let mut c = c.to_vec();
    let mut base_h = gens.h_vec.clone();
    let mut base_g = gens.g_vec.clone();
    let mut original_base = true;
    let mut w_h: Vec<RistrettoScalar> = vec![one()];
    let mut w_g: Vec<RistrettoScalar> = vec![one()];
    let mut levels: u32 = 0;
    let mut rho = rho;
    let mut mu = rho * rho;
    let mut rounds = Vec::new();

    transcript.domain_sep(b"norm_linear");

    while l.len() + n.len() >= FOLD_THRESHOLD {
        if levels == FOLD_BATCH_ROUNDS {
            base_h = batch_fold(&base_h, &w_h)?;
            base_g = batch_fold(&base_g, &w_g)?;
            w_h = vec![one()];
            w_g = vec![one()];
            levels = 0;
            original_base = false;
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

        // Expand folded-position coefficients onto the base generators, laid
        // out as [G, base_h.., base_g..]: base index i contributes
        // w[t] * coeff[j] with j = i >> levels, t = i & (2^levels - 1).
        let mask = (1usize << levels) - 1;
        let g_off = 1 + base_h.len();
        let mut x_coeffs = vec![RistrettoScalar::zero(); 1 + base_h.len() + base_g.len()];
        let mut r_coeffs = vec![RistrettoScalar::zero(); x_coeffs.len()];
        x_coeffs[0] = vx;
        r_coeffs[0] = vr;
        for i in 0..base_h.len() {
            let (j, t) = (i >> levels, i & mask);
            if j >= xh.len() {
                continue;
            }
            x_coeffs[1 + i] = w_h[t] * xh[j];
            if rh[j] != RistrettoScalar::zero() {
                r_coeffs[1 + i] = w_h[t] * rh[j];
            }
        }
        for i in 0..base_g.len() {
            let (j, t) = (i >> levels, i & mask);
            if j >= xg.len() {
                continue;
            }
            x_coeffs[g_off + i] = w_g[t] * xg[j];
            if rg[j] != RistrettoScalar::zero() {
                r_coeffs[g_off + i] = w_g[t] * rg[j];
            }
        }

        // One MSM per commitment: over the precomputed tables while the base
        // is the original CRS (the coefficient layout matches them exactly),
        // afterwards a dynamic MSM over the shrunken base, skipping zero
        // coefficients (R's even positions, padding).
        let msm = |coeffs: &[RistrettoScalar]| -> FastCryptoResult<RistrettoPoint> {
            if original_base {
                return gens.precomp.mixed_multi_scalar_mul(coeffs, &[]);
            }
            let (sc, pts): (Vec<RistrettoScalar>, Vec<RistrettoPoint>) = coeffs
                .iter()
                .zip(
                    std::iter::once(&gens.g)
                        .chain(base_h.iter())
                        .chain(base_g.iter()),
                )
                .filter(|(s, _)| **s != RistrettoScalar::zero())
                .map(|(s, p)| (*s, *p))
                .unzip();
            RistrettoPoint::multi_scalar_mul(&sc, &pts)
        };
        let x_point = msm(&x_coeffs)?;
        let r_point = msm(&r_coeffs)?;

        transcript.append_point(b"X", &x_point);
        transcript.append_point(b"R", &r_point);
        rounds.push((x_point, r_point));
        let gamma = transcript.challenge_scalar(b"gamma");

        // Fold the scalar vectors: l' = l0 + gamma*l1,
        // n' = rho^{-1}*n0 + gamma*n1, c' = c0 + gamma*c1.
        l = vec_add(&l0, &vec_scalar_mul(gamma, &l1));
        n = vec_add(&vec_scalar_mul(rho_inv, &n0), &vec_scalar_mul(gamma, &n1));
        c = vec_add(&c0, &vec_scalar_mul(gamma, &c1));

        // Grow the implicit fold tensors by one level (the new round is the
        // top bit): H' = H0 + gamma*H1, G' = rho*G0 + gamma*G1.
        let grow = |w: &[RistrettoScalar], f0: RistrettoScalar, f1: RistrettoScalar| {
            let mut next = Vec::with_capacity(2 * w.len());
            next.extend(w.iter().map(|wt| *wt * f0));
            next.extend(w.iter().map(|wt| *wt * f1));
            next
        };
        w_h = grow(&w_h, one(), gamma);
        w_g = grow(&w_g, rho, gamma);
        levels += 1;

        rho = mu;
        mu = mu2;
    }

    for s in &l {
        transcript.append_scalar(b"l_final", s);
    }
    for s in &n {
        transcript.append_scalar(b"n_final", s);
    }

    Ok(NormLinearProof {
        rounds,
        l_final: l,
        n_final: n,
    })
}

/// Verify a norm-linear proof in a single multi-scalar multiplication.
///
/// The commitment is supplied in decomposed form so it joins the same MSM:
/// `pn` are public coefficients over `g_vec` and `extra` the remaining
/// `(scalar, point)` terms, i.e. the commitment equals
/// `<pn, g_vec> + sum extra` (missing tail entries of `pn` count as zero).
///
/// Instead of folding the generator vectors round by round, each base
/// generator's final coefficient is computed from the bits of its index:
/// position `i` survives the `k` rounds at final slot `i >> k`, picking up
/// per round `r` a factor `gamma_r` when bit `r` of `i` is set, else
/// `rho_r = rho^{2^r}` on the `g_vec` side and `1` on the `h_vec` side.
/// The per-round identity padding never hosts a base generator, so the
/// per-bit product is exact, and the base-case check becomes
///   sigma*G + <w_h ⊙ l, H> + <w_g ⊙ n - pn, G_vec>
///     - sum extra - sum_r (gamma_r*X_r + (gamma_r^2 - 1)*R_r) == 0.
///
/// `c` must have the length of `gens.h_vec`. Errors with `InvalidProof` on
/// any mismatch, including a proof whose shape differs from the one implied
/// by the base lengths.
pub(crate) fn verify(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    c: &[RistrettoScalar],
    pn: &[RistrettoScalar],
    extra: &[(RistrettoScalar, RistrettoPoint)],
    rho: RistrettoScalar,
    proof: &NormLinearProof,
) -> FastCryptoResult<()> {
    if c.len() != gens.h_vec.len() || pn.len() > gens.g_vec.len() {
        return Err(FastCryptoError::InvalidInput);
    }
    // The prover's fold count and final lengths are determined by the base
    // lengths; reject any other shape.
    let (rounds, l_len, n_len) = proof_shape(gens.h_vec.len(), gens.g_vec.len());
    if proof.rounds.len() != rounds || proof.l_final.len() != l_len || proof.n_final.len() != n_len
    {
        return Err(FastCryptoError::InvalidProof);
    }

    let k = rounds;
    let mut c = c.to_vec();
    let mut rho = rho;
    let mut mu = rho * rho;
    let mut gammas = Vec::with_capacity(k);
    let mut rhos = Vec::with_capacity(k);

    transcript.domain_sep(b"norm_linear");

    for (x_point, r_point) in &proof.rounds {
        transcript.append_point(b"X", x_point);
        transcript.append_point(b"R", r_point);
        let gamma = transcript.challenge_scalar(b"gamma");
        rhos.push(rho);
        gammas.push(gamma);

        // Fold only the (cheap) scalar constraint vector.
        pad_even_scalar(&mut c);
        c = vec_add(
            &even_elements(&c),
            &vec_scalar_mul(gamma, &odd_elements(&c)),
        );

        rho = mu;
        mu = mu * mu;
    }

    for s in &proof.l_final {
        transcript.append_scalar(b"l_final", s);
    }
    for s in &proof.n_final {
        transcript.append_scalar(b"n_final", s);
    }

    let sigma = inner_product(&c, &proof.l_final) + weighted_norm(&proof.n_final, mu);

    // Challenge-product weights via tensor tables (all 2^k products in
    // 2^{k+1} muls): w[t] = prod_r (set_r if bit_r(t) else unset_r).
    let tensor_table = |set: &[RistrettoScalar], unset: &[RistrettoScalar]| {
        let mut w = vec![one()];
        for (s, u) in set.iter().zip(unset) {
            let mut next = Vec::with_capacity(2 * w.len());
            next.extend(w.iter().map(|p| *p * *u)); // bit r = 0
            next.extend(w.iter().map(|p| *p * *s)); // bit r = 1
            w = next;
        }
        w
    };
    let ones = vec![one(); k];
    let w_h = tensor_table(&gammas, &ones);
    let w_g = tensor_table(&gammas, &rhos);
    let mask = (1usize << k) - 1;

    // Static scalars, laid out to match the precomputed tables
    // `[G, h_vec.., g_vec..]`.
    let mut static_scalars = Vec::with_capacity(1 + gens.h_vec.len() + gens.g_vec.len());
    static_scalars.push(sigma);
    for i in 0..gens.h_vec.len() {
        static_scalars.push(w_h[i & mask] * proof.l_final[i >> k]);
    }
    for i in 0..gens.g_vec.len() {
        let pn_i = pn.get(i).copied().unwrap_or_else(RistrettoScalar::zero);
        static_scalars.push(w_g[i & mask] * proof.n_final[i >> k] - pn_i);
    }

    let mut dyn_scalars = Vec::with_capacity(extra.len() + 2 * k);
    let mut dyn_points = Vec::with_capacity(extra.len() + 2 * k);
    for (s, p) in extra {
        dyn_scalars.push(-*s);
        dyn_points.push(*p);
    }
    for ((x_point, r_point), gamma) in proof.rounds.iter().zip(&gammas) {
        dyn_scalars.push(-*gamma);
        dyn_points.push(*x_point);
        dyn_scalars.push(one() - *gamma * *gamma);
        dyn_points.push(*r_point);
    }

    // Both paths take the same scalars, the static ones first.
    let mut scalars = static_scalars;
    scalars.append(&mut dyn_scalars);

    // The precomputed path always uses Straus, which loses to Pippenger for
    // large MSMs; above the measured crossover (bulletproofpp's
    // benches/mixed_msm.rs, ~440 static points for this workload shape) fall
    // back to one plain MSM.
    let result = if gens.precomp.num_static_points() <= 440 {
        gens.precomp.mixed_multi_scalar_mul(&scalars, &dyn_points)?
    } else {
        let mut points = Vec::with_capacity(scalars.len());
        points.push(gens.g);
        points.extend(&gens.h_vec);
        points.extend(&gens.g_vec);
        points.append(&mut dyn_points);
        RistrettoPoint::multi_scalar_mul(&scalars, &points)?
    };

    if result == RistrettoPoint::zero() {
        Ok(())
    } else {
        Err(FastCryptoError::InvalidProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A random valid instance: a CRS sliced to the requested lengths,
    /// random `(c, rho, l, n)`, and the commitment to `(sigma, l, n)`.
    #[derive(Clone)]
    struct Instance {
        gens: Generators,
        c: Vec<RistrettoScalar>,
        rho: RistrettoScalar,
        l: Vec<RistrettoScalar>,
        n: Vec<RistrettoScalar>,
        commitment: RistrettoPoint,
    }

    fn random_instance(l_len: usize, n_len: usize) -> Instance {
        let mut rng = rand::thread_rng();
        let full = Generators::new(64, 4).unwrap();
        let gens = Generators::from_parts(
            full.g,
            full.h_vec[..l_len].to_vec(),
            full.g_vec[..n_len].to_vec(),
        )
        .unwrap();
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
            &[],
            &[(one(), inst.commitment)],
            inst.rho,
            proof,
        )
    }

    #[test]
    fn test_roundtrip_sizes() {
        // (8, 16) is the 64-bit range-proof shape: 3 rounds + 1 + 2 scalars.
        // (8, 15) is the 16/32-bit shape, (8, 64) the aggregated 32-bit x 8
        // shape (4 rounds, finals (1, 4)). Small and odd sizes exercise
        // padding and the no-round base case.
        for (l_len, n_len) in [(8, 16), (8, 15), (8, 64), (1, 2), (2, 4), (3, 5), (4, 1)] {
            let inst = random_instance(l_len, n_len);
            let proof = prove_instance(&inst);
            let (rounds, fl, fn_) = proof_shape(l_len, n_len);
            assert_eq!(proof.rounds.len(), rounds);
            assert_eq!((proof.l_final.len(), proof.n_final.len()), (fl, fn_));
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
        bad.l_final[0] += RistrettoScalar::generator();
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

            for i in 0..proof.l_final.len() {
                let mut bad = proof.clone();
                bad.l_final[i] += RistrettoScalar::generator();
                assert!(
                    verify_instance(&inst, &bad).is_err(),
                    "l_final[{i}] unbound for ({l_len}, {n_len})"
                );
            }
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
