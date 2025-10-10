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
use std::iter;
use std::num::NonZeroU16;

const I10: NonZeroU16 = unsafe { NonZeroU16::new_unchecked(10) };

#[generic_tests::define]
mod scalar_tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn test_degree<S: Scalar>() {
        let s: usize = 5;
        let p = Poly::<S>::rand(s as u16, &mut thread_rng());
        assert_eq!(p.degree_bound(), s);
    }

    #[test]
    fn add<S: Scalar>() {
        let p1 = Poly::<S>::rand(3, &mut thread_rng());
        let p2 = Poly::<S>::zero();
        let mut res = p1.clone();
        res += &p2;
        assert_eq!(res, p1);

        let p1 = Poly::<S>::zero();
        let p2 = Poly::<S>::rand(3, &mut thread_rng());
        let mut res = p1;
        res += &p2;
        assert_eq!(res, p2);

        let p1 = Poly::<S>::rand(3, &mut thread_rng());
        let p2 = Poly::<S>::rand(5, &mut thread_rng());
        let mut p3 = p1.clone();
        p3 += &p2;
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

    #[test]
    fn test_interpolate_at_index<S: Scalar>() {
        let degree = 12;
        let threshold = degree + 1;
        let poly = Poly::<S>::rand(degree, &mut thread_rng());
        let mut shares = (1..50)
            .map(|i| poly.eval(ShareIndex::new(i).unwrap()))
            .collect::<Vec<_>>();
        for _ in 0..10 {
            shares.shuffle(&mut thread_rng());
            let index = ShareIndex::new(thread_rng().gen_range(300..600)).unwrap();
            let used_shares = shares
                .iter()
                .take(threshold as usize)
                .cloned()
                .collect_vec();
            let interpolated = Poly::interpolate_at_index(index, &used_shares).unwrap();
            assert_eq!(interpolated, poly.eval(index));
        }
    }

    #[test]
    fn test_interpolate_at_index_errors<S: Scalar>() {
        let degree = 4;
        let threshold = degree + 1;
        let poly = Poly::<S>::rand(4, &mut thread_rng());
        // duplicate indices
        let shares = (1..=threshold)
            .map(|i| poly.eval(ShareIndex::new(i).unwrap()))
            .chain(std::iter::once(poly.eval(ShareIndex::new(1).unwrap())))
            .collect_vec(); // duplicate value 1
        Poly::interpolate_at_index(ShareIndex::new(7).unwrap(), &shares).unwrap_err();
    }

    #[test]
    fn test_interpolate<S: Scalar>() {
        let degree = 12;
        let threshold = degree + 1;
        let poly = Poly::<S>::rand(degree, &mut thread_rng());
        let mut shares = (1..50)
            .map(|i| poly.eval(ShareIndex::new(i).unwrap()))
            .collect::<Vec<_>>();
        for _ in 0..10 {
            shares.shuffle(&mut thread_rng());
            let used_shares = shares
                .iter()
                .take(threshold as usize)
                .cloned()
                .collect_vec();
            let interpolated = Poly::interpolate(&used_shares).unwrap();
            assert_eq!(interpolated, poly);
        }

        // Using too few shares
        for _ in 0..10 {
            shares.shuffle(&mut thread_rng());
            let used_shares = shares
                .iter()
                .take(threshold as usize - 1)
                .cloned()
                .collect_vec();
            let interpolated = Poly::interpolate(&used_shares).unwrap();
            assert_ne!(interpolated, poly);
        }

        // Using duplicate shares should fail
        let mut shares = (1..=threshold)
            .map(|i| poly.eval(ShareIndex::new(i).unwrap()))
            .collect_vec(); // duplicate value 1
        shares.push(poly.eval(ShareIndex::new(1).unwrap()));
        Poly::interpolate(&shares).unwrap_err();
    }

    #[test]
    fn test_division<S: Scalar>() {
        let mut rng = thread_rng();
        let degree_a = 8;
        let degree_b = 5;
        let a = crate::polynomial::Poly::from(
            iter::from_fn(|| Some(S::rand(&mut rng)))
                .take(degree_a + 1)
                .collect_vec(),
        );
        let b = crate::polynomial::Poly::from(
            iter::from_fn(|| Some(S::rand(&mut rng)))
                .take(degree_b + 1)
                .collect_vec(),
        );

        let (q, r) = a.div_rem(&b).unwrap();
        assert!(r.degree() < b.degree());

        let mut lhs = &q * &b;
        lhs += &r;
        assert!(poly_eq(&lhs, &a));
    }

    #[test]
    fn test_extended_gcd<S: Scalar>() {
        let mut rng = thread_rng();
        let degree_a = 8;
        let degree_b = 5;
        let a = crate::polynomial::Poly::from(
            iter::from_fn(|| Some(S::rand(&mut rng)))
                .take(degree_a + 1)
                .collect_vec(),
        );
        let b = crate::polynomial::Poly::from(
            iter::from_fn(|| Some(S::rand(&mut rng)))
                .take(degree_b + 1)
                .collect_vec(),
        );

        let (g, x, y) = Poly::extended_gcd(&a, &b).unwrap();

        assert!(poly_eq(&(&x * &a + &(&y * &b)), &g));
    }

    #[instantiate_tests(<RistrettoScalar>)]
    mod ristretto_scalar {}

    #[instantiate_tests(<BlsScalar>)]
    mod bls_scalar {}
}

#[generic_tests::define]
mod points_tests {
    use super::*;
    use itertools::Either;

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
        assert_eq!(p.degree_bound(), 2);
        let s1 = p.eval(NonZeroU16::new(10).unwrap());
        let s2 = p.eval(NonZeroU16::new(20).unwrap());
        let s3 = p.eval(NonZeroU16::new(30).unwrap());
        let shares = [s1, s2, s3];
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
        assert_eq!(p.degree_bound(), 2);
        let s1 = p.eval(NonZeroU16::new(10).unwrap());
        let s2 = p.eval(NonZeroU16::new(20).unwrap());
        let s3 = p.eval(NonZeroU16::new(30).unwrap());
        let shares = [s1, s2, s3];
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

    #[test]
    fn test_fast_mult<G: GroupElement>() {
        let x = 1u128 << 109; // 110 bit set
        let y = 1u128 << 17; // 18 bit set
        assert!(Poly::<G::ScalarType>::fast_mult(x, y) == Either::Right(x * y));

        let x = 1u128 << 17;
        let y = 1u128 << 109;
        assert!(Poly::<G::ScalarType>::fast_mult(x, y) == Either::Right(x * y));

        let x = 1u128 << (109 - 1); // all 109 bits set
        let y = 1u128 << (19 - 1); // all 19 bits set
        assert!(Poly::<G::ScalarType>::fast_mult(x, y) == Either::Right(x * y));

        let x = 1u128 << 120;
        let y = 1u128 << 13;
        assert!(
            Poly::<G::ScalarType>::fast_mult(x, y) == Either::Left((G::ScalarType::from(x), y))
        );

        let x = 1u128 << 21;
        let y = 1u128 << 120;
        assert!(
            Poly::<G::ScalarType>::fast_mult(x, y) == Either::Left((G::ScalarType::from(x), y))
        );

        let x = u128::MAX;
        let y = 1u128;
        assert!(
            Poly::<G::ScalarType>::fast_mult(x, y) == Either::Left((G::ScalarType::from(x), y))
        );
    }

    #[instantiate_tests(<RistrettoPoint>)]
    mod ristretto_point {}

    #[instantiate_tests(<G1Element>)]
    mod g1_element {}

    #[instantiate_tests(<G2Element>)]
    mod g2_element {}
}
