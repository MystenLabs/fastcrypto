// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Most of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::polynomial::*;
use crate::types::ShareIndex;
use fastcrypto::groups::bls12381::{G1Element, G2Element, Scalar as BlsScalar};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{GroupElement, MultiScalarMul, Scalar};
use rand::prelude::*;
use std::num::NonZeroU32;

const I10: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(10) };

#[generic_tests::define]
mod scalar_tests {
    use super::*;

    #[test]
    fn test_degree<S: Scalar>() {
        let s: u32 = 5;
        let p = Poly::<S>::rand(s, &mut thread_rng());
        assert_eq!(p.degree(), s);
    }

    #[test]
    fn add<S: Scalar>() {
        let p1 = Poly::<S>::rand(3, &mut thread_rng());
        let p2 = Poly::<S>::zero();
        let mut res = p1.clone();
        res.add(&p2);
        assert_eq!(res, p1);

        let p1 = Poly::<S>::zero();
        let p2 = Poly::<S>::rand(3, &mut thread_rng());
        let mut res = p1;
        res.add(&p2);
        assert_eq!(res, p2);

        let p1 = Poly::<S>::rand(3, &mut thread_rng());
        let p2 = Poly::<S>::rand(5, &mut thread_rng());
        let mut p3 = p1.clone();
        p3.add(&p2);
        assert_eq!(p1.eval(I10).value + p2.eval(I10).value, p3.eval(I10).value);
    }

    #[test]
    fn test_recover_c0_errors<S: Scalar>() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = Poly::<S>::rand(4, &mut thread_rng());
        // insufficient shares gathered
        let shares = (1..threshold).map(|i| poly.eval(ShareIndex::new(i).unwrap()));
        Poly::<S>::recover_c0(threshold, shares).unwrap_err();
        // duplications
        let shares = (1..=threshold)
            .map(|i| poly.eval(ShareIndex::new(i).unwrap()))
            .chain(std::iter::once(poly.eval(ShareIndex::new(1).unwrap()))); // duplicate value 1
        Poly::<S>::recover_c0(threshold, shares).unwrap_err();
    }

    #[test]
    fn test_recover_c0<S: Scalar>() {
        let poly = Poly::<S>::rand(123, &mut thread_rng());
        // insufficient shares gathered
        let mut shares = (1..300)
            .map(|i| poly.eval(ShareIndex::new(i).unwrap()))
            .collect::<Vec<_>>();
        let c0 = poly.c0();
        for _ in 0..10 {
            shares.shuffle(&mut thread_rng());
            let used_shares = shares.iter().take(124);
            assert_eq!(c0, &Poly::<S>::recover_c0(124, used_shares).unwrap());
        }
    }

    #[instantiate_tests(<RistrettoScalar>)]
    mod ristretto_scalar {}

    #[instantiate_tests(<BlsScalar>)]
    mod bls_scalar {}
}

#[generic_tests::define]
mod points_tests {
    use super::*;
    #[test]
    fn test_eval_and_commit<G: GroupElement>() {
        // test zero
        let p = Poly::<G::ScalarType>::zero();
        assert_eq!(p.eval(I10).value, G::ScalarType::zero());
        // test consistency
        let p = Poly::<G::ScalarType>::rand(5, &mut thread_rng());
        let e1 = p.eval(I10);
        let public_p = p.commit();
        let e2 = public_p.eval(I10);
        assert_eq!(e1.index, e2.index);
        assert_eq!(G::generator() * e1.value, e2.value);
        assert!(public_p.verify_share(e1.index, &e1.value).is_ok());
        // test simple poly
        let one = G::ScalarType::generator();
        let coeff = vec![one, one, one];
        let p = Poly::<G::ScalarType>::from(coeff);
        assert_eq!(p.degree(), 2);
        let s1 = p.eval(NonZeroU32::new(10).unwrap());
        let s2 = p.eval(NonZeroU32::new(20).unwrap());
        let s3 = p.eval(NonZeroU32::new(30).unwrap());
        let shares = vec![s1, s2, s3];
        assert_eq!(
            Poly::<G::ScalarType>::recover_c0(3, shares.iter()).unwrap(),
            one
        );
    }

    #[test]
    fn test_recover_c0_msm_errors<G: GroupElement + MultiScalarMul>() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = Poly::<G::ScalarType>::rand(4, &mut thread_rng());
        let poly_g = poly.commit();
        // insufficient shares gathered
        let shares = (1..threshold).map(|i| poly_g.eval(ShareIndex::new(i).unwrap()));
        Poly::<G>::recover_c0_msm(threshold, shares).unwrap_err();
        // duplications
        let shares = (1..threshold)
            .map(|i| poly_g.eval(ShareIndex::new(i).unwrap()))
            .chain(std::iter::once(poly_g.eval(ShareIndex::new(1).unwrap()))); // duplicate value 1
        Poly::<G>::recover_c0_msm(threshold, shares).unwrap_err();
    }

    #[test]
    fn test_recover_c0_msm<G: GroupElement + MultiScalarMul>() {
        let one = G::generator();
        let coeff = vec![one, one, one];
        let p = Poly::<G>::from(coeff);
        assert_eq!(p.degree(), 2);
        let s1 = p.eval(NonZeroU32::new(10).unwrap());
        let s2 = p.eval(NonZeroU32::new(20).unwrap());
        let s3 = p.eval(NonZeroU32::new(30).unwrap());
        let shares = vec![s1, s2, s3];
        assert_eq!(Poly::<G>::recover_c0_msm(3, shares.iter()).unwrap(), one);

        // and random tests
        let poly = Poly::<G::ScalarType>::rand(123, &mut thread_rng());
        let poly_g = poly.commit();
        // insufficient shares gathered
        let mut shares = (1..200)
            .map(|i| poly_g.eval(ShareIndex::new(i).unwrap()))
            .collect::<Vec<_>>();
        let c0 = poly_g.c0();
        for _ in 0..10 {
            shares.shuffle(&mut thread_rng());
            let used_shares = shares.iter().take(124);
            assert_eq!(c0, &Poly::<G>::recover_c0_msm(124, used_shares).unwrap());
        }
    }

    #[instantiate_tests(<RistrettoPoint>)]
    mod ristretto_point {}

    #[instantiate_tests(<G1Element>)]
    mod g1_element {}

    #[instantiate_tests(<G2Element>)]
    mod g2_element {}
}
