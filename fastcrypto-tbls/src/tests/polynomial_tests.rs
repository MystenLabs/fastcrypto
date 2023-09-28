// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Most of the code below is based on code from https://github.com/celo-org/celo-threshold-bls-rs,
// modified for our needs.
//

use crate::polynomial::*;
use crate::types::ShareIndex;
use fastcrypto::groups::bls12381::G1Element;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::*;
use rand::prelude::*;
use std::num::NonZeroU32;

// TODO: add more tests & proptest tests.

#[test]
fn eval() {
    let s: usize = 5;

    let p = Poly::<RistrettoScalar>::rand(s as u32, &mut thread_rng());
    let e1 = p.eval(NonZeroU32::new(10).unwrap());

    let public_p: Poly<RistrettoPoint> = p.commit();
    assert!(public_p.is_valid_share(e1.index, &e1.value));
    let e2 = public_p.eval(NonZeroU32::new(10).unwrap());
    let e1 = RistrettoPoint::generator() * e1.value;
    assert_eq!(e1, e2.value);
}

#[test]
fn eval_regression() {
    let one = RistrettoScalar::generator();
    let coeff = vec![one, one, one];
    let p = Poly::<RistrettoScalar>::from(coeff);
    assert_eq!(p.degree(), 2);
    let s1 = p.eval(NonZeroU32::new(10).unwrap());
    let s2 = p.eval(NonZeroU32::new(20).unwrap());
    let s3 = p.eval(NonZeroU32::new(30).unwrap());
    let shares = vec![s1, s2, s3];
    assert_eq!(
        Poly::<RistrettoScalar>::recover_c0(3, &shares).unwrap(),
        one
    );
}

#[test]
fn poly_degree() {
    let s: u32 = 5;
    let p = Poly::<RistrettoScalar>::rand(s, &mut thread_rng());
    assert_eq!(p.degree(), s);
}

#[test]
fn add_zero() {
    let p1 = Poly::<RistrettoScalar>::rand(3, &mut thread_rng());
    let p2 = Poly::<RistrettoScalar>::zero();
    let mut res = p1.clone();
    res.add(&p2);
    assert_eq!(res, p1);

    let p1 = Poly::<RistrettoScalar>::zero();
    let p2 = Poly::<RistrettoScalar>::rand(3, &mut thread_rng());
    let mut res = p1;
    res.add(&p2);
    assert_eq!(res, p2);
}

#[test]
fn interpolation_insufficient_shares() {
    let degree = 4;
    let threshold = degree + 1;
    let poly = Poly::<RistrettoScalar>::rand(degree, &mut thread_rng());

    // insufficient shares gathered
    let shares = (1..threshold)
        .map(|i| poly.eval(ShareIndex::new(i).unwrap()))
        .collect::<Vec<_>>();

    Poly::<RistrettoScalar>::recover_c0(threshold, &shares).unwrap_err();
}

#[test]
fn eval_regression_msm() {
    let one = G1Element::generator();
    let coeff = vec![one, one, one];
    let p = Poly::<G1Element>::from(coeff);
    assert_eq!(p.degree(), 2);
    let s1 = p.eval(NonZeroU32::new(10).unwrap());
    let s2 = p.eval(NonZeroU32::new(20).unwrap());
    let s3 = p.eval(NonZeroU32::new(30).unwrap());
    let shares = vec![s1, s2, s3];
    assert_eq!(Poly::<G1Element>::recover_c0_msm(3, &shares).unwrap(), one);
}
