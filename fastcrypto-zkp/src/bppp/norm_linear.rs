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
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};

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

fn pad_even_point(v: &mut Vec<RistrettoPoint>) {
    if !v.len().is_multiple_of(2) {
        v.push(RistrettoPoint::zero());
    }
}

/// Element-wise point fold `f0*[p]_0 + f1*[p]_1` of the even/odd halves.
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
    let g = gens.g;
    let two = RistrettoScalar::from(2u64);
    let mut l = l.to_vec();
    let mut n = n.to_vec();
    let mut c = c.to_vec();
    let mut h_vec = gens.h_vec.clone();
    let mut g_vec = gens.g_vec.clone();
    let mut rho = rho;
    let mut mu = rho * rho;
    let mut rounds = Vec::new();

    transcript.domain_sep(b"norm_linear");

    while l.len() + n.len() >= FOLD_THRESHOLD {
        pad_even_scalar(&mut l);
        pad_even_scalar(&mut n);
        pad_even_scalar(&mut c);
        pad_even_point(&mut h_vec);
        pad_even_point(&mut g_vec);

        let l0 = even_elements(&l);
        let l1 = odd_elements(&l);
        let n0 = even_elements(&n);
        let n1 = odd_elements(&n);
        let c0 = even_elements(&c);
        let c1 = odd_elements(&c);
        let h0 = even_elements(&h_vec);
        let h1 = odd_elements(&h_vec);
        let g0 = even_elements(&g_vec);
        let g1 = odd_elements(&g_vec);

        let rho_inv = rho.inverse()?;
        let mu2 = mu * mu;

        // gamma^1 and (gamma^2 - 1) coefficients of the folded opening:
        //   vx = 2*rho^{-1}*<n0, n1>_{mu^2} + <c0, l1> + <c1, l0>
        //   vr = |n1|^2_{mu^2} + <c1, l1>
        let vx = two * rho_inv * weighted_inner_product(&n0, &n1, mu2)
            + inner_product(&c0, &l1)
            + inner_product(&c1, &l0);
        let vr = weighted_norm(&n1, mu2) + inner_product(&c1, &l1);

        // X carries the cross terms:
        //   X = vx*G + <l1, H_even> + <l0, H_odd> + rho*<n1, G_even> + rho^{-1}*<n0, G_odd>
        let mut x_scalars = vec![vx];
        let mut x_points = vec![g];
        for s in 0..h0.len() {
            x_scalars.push(l1[s]);
            x_points.push(h0[s]);
            x_scalars.push(l0[s]);
            x_points.push(h1[s]);
        }
        for s in 0..g0.len() {
            x_scalars.push(rho * n1[s]);
            x_points.push(g0[s]);
            x_scalars.push(rho_inv * n0[s]);
            x_points.push(g1[s]);
        }
        let x_point = RistrettoPoint::multi_scalar_mul(&x_scalars, &x_points)?;

        // R carries the odd-odd terms:
        //   R = vr*G + <l1, H_odd> + <n1, G_odd>
        let mut r_scalars = vec![vr];
        let mut r_points = vec![g];
        for s in 0..h0.len() {
            r_scalars.push(l1[s]);
            r_points.push(h1[s]);
        }
        for s in 0..g0.len() {
            r_scalars.push(n1[s]);
            r_points.push(g1[s]);
        }
        let r_point = RistrettoPoint::multi_scalar_mul(&r_scalars, &r_points)?;

        transcript.append_point(b"X", &x_point);
        transcript.append_point(b"R", &r_point);
        rounds.push((x_point, r_point));
        let gamma = transcript.challenge_scalar(b"gamma");

        // Fold: l' = l0 + gamma*l1, n' = rho^{-1}*n0 + gamma*n1,
        // c' = c0 + gamma*c1, H' = H0 + gamma*H1, G' = rho*G0 + gamma*G1.
        l = vec_add(&l0, &vec_scalar_mul(gamma, &l1));
        n = vec_add(&vec_scalar_mul(rho_inv, &n0), &vec_scalar_mul(gamma, &n1));
        c = vec_add(&c0, &vec_scalar_mul(gamma, &c1));
        h_vec = fold_points(&h_vec, one(), gamma);
        g_vec = fold_points(&g_vec, rho, gamma);

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

/// Verify a norm-linear proof against `commitment`. `c` must have the length
/// of `gens.h_vec`. Errors with `InvalidProof` on any mismatch, including a
/// proof whose shape differs from the one implied by the base lengths.
pub(crate) fn verify(
    transcript: &mut BpppTranscript,
    gens: &Generators,
    c: &[RistrettoScalar],
    commitment: RistrettoPoint,
    rho: RistrettoScalar,
    proof: &NormLinearProof,
) -> FastCryptoResult<()> {
    if c.len() != gens.h_vec.len() {
        return Err(FastCryptoError::InvalidInput);
    }
    // The prover's fold count and final lengths are determined by the base
    // lengths; reject any other shape.
    let (rounds, l_len, n_len) = proof_shape(gens.h_vec.len(), gens.g_vec.len());
    if proof.rounds.len() != rounds || proof.l_final.len() != l_len || proof.n_final.len() != n_len
    {
        return Err(FastCryptoError::InvalidProof);
    }

    let g = gens.g;
    let mut c = c.to_vec();
    let mut h_vec = gens.h_vec.clone();
    let mut g_vec = gens.g_vec.clone();
    let mut commitment = commitment;
    let mut rho = rho;
    let mut mu = rho * rho;

    transcript.domain_sep(b"norm_linear");

    for (x_point, r_point) in &proof.rounds {
        transcript.append_point(b"X", x_point);
        transcript.append_point(b"R", r_point);
        let gamma = transcript.challenge_scalar(b"gamma");

        // C' = C + gamma*X + (gamma^2 - 1)*R.
        commitment = commitment + *x_point * gamma + *r_point * (gamma * gamma - one());

        pad_even_scalar(&mut c);
        pad_even_point(&mut h_vec);
        pad_even_point(&mut g_vec);
        c = vec_add(
            &even_elements(&c),
            &vec_scalar_mul(gamma, &odd_elements(&c)),
        );
        h_vec = fold_points(&h_vec, one(), gamma);
        g_vec = fold_points(&g_vec, rho, gamma);

        rho = mu;
        mu = mu * mu;
    }

    for s in &proof.l_final {
        transcript.append_scalar(b"l_final", s);
    }
    for s in &proof.n_final {
        transcript.append_scalar(b"n_final", s);
    }

    // Base case: with sigma = <c, l> + |n|^2_mu computed from
    // the final scalars, check that the folded commitment opens as
    //   C = sigma*G + <l, H> + <n, G_vec>.
    let sigma = inner_product(&c, &proof.l_final) + weighted_norm(&proof.n_final, mu);
    let mut scalars = vec![sigma];
    let mut points = vec![g];
    scalars.extend(&proof.l_final);
    points.extend(&h_vec);
    scalars.extend(&proof.n_final);
    points.extend(&g_vec);
    let recomputed = RistrettoPoint::multi_scalar_mul(&scalars, &points)?;

    if commitment == recomputed {
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
        let gens = Generators {
            g: full.g,
            h_vec: full.h_vec[..l_len].to_vec(),
            g_vec: full.g_vec[..n_len].to_vec(),
        };
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
            inst.commitment,
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
