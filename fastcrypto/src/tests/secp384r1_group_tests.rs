// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::multiplier::windowed::WindowedScalarMultiplier;
use crate::groups::multiplier::ScalarMultiplier;
use crate::groups::secp384r1::{ProjectivePoint, Scalar};
use crate::groups::{secp384r1, Doubling, GroupElement, Scalar as ScalarTrait};
use crate::serde_helpers::ToFromByteArray;
use ark_ff::{BigInteger, PrimeField};
use ark_secp384r1::Fr;
use rand::thread_rng;

#[test]
fn test_to_from_byte_array() {
    let scalar = secp384r1::Scalar::rand(&mut thread_rng());
    let bytes = scalar.to_byte_array();
    let reconstructed = Scalar::from_byte_array(&bytes).unwrap();
    assert_eq!(scalar, reconstructed);
}

#[test]
fn test_arithmetic() {
    let p = ProjectivePoint::generator();
    let two_p = p + p;
    let s = Scalar::from(2);
    assert_eq!(two_p, p.double());
    assert_eq!(two_p, p * s);
    assert_eq!(p, two_p * (Scalar::generator() / s).unwrap());

    // Check that u128 is decoded correctly.
    let x: u128 = 2 << 66;
    let x_scalar = Scalar::from(x);
    let res = x_scalar / Scalar::from(8);
    assert_eq!(res.unwrap(), Scalar::from(2 << 63));
}

#[test]
fn test_scalar_multiplication() {
    let mut modulus_minus_one = Fr::MODULUS_MINUS_ONE_DIV_TWO;
    modulus_minus_one.mul2();
    let scalars = [
        Scalar::from(0),
        Scalar::from(1),
        Scalar::from(2),
        Scalar::from(1234),
        Scalar::from(123456),
        Scalar::from(123456789),
        Scalar::from(0xffffffffffffffff),
        Scalar(Fr::from(modulus_minus_one)),
    ];

    let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 256, 5>::new(
        ProjectivePoint::generator(),
        ProjectivePoint::zero(),
    );

    for scalar in scalars {
        let expected = ProjectivePoint::generator() * scalar;
        let actual = multiplier.mul(&scalar);
        assert_eq!(expected, actual);
    }
}

#[test]
fn test_double_mul() {
    let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, 256, 5>::new(
        ProjectivePoint::generator(),
        ProjectivePoint::zero(),
    );

    for _ in 0..10 {
        let other_point = ProjectivePoint::generator() * Scalar::rand(&mut thread_rng());
        let a = Scalar::rand(&mut thread_rng());
        let b = Scalar::rand(&mut thread_rng());
        let expected = ProjectivePoint::generator() * a + other_point * b;
        let actual = multiplier.two_scalar_mul(&a, &other_point, &b);
        assert_eq!(expected, actual);
    }

    // Edge cases.
    let p = ProjectivePoint::generator() * Scalar::rand(&mut thread_rng());
    let s = Scalar::rand(&mut thread_rng());
    assert_eq!(
        multiplier.two_scalar_mul(&Scalar::from(0), &p, &Scalar::from(0)),
        ProjectivePoint::zero()
    );
    assert_eq!(
        multiplier.two_scalar_mul(&s, &p, &Scalar::from(0)),
        ProjectivePoint::generator() * s
    );
    assert_eq!(multiplier.two_scalar_mul(&Scalar::from(0), &p, &s), p * s);
}
