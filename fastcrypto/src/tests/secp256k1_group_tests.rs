// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::{Doubling, GroupElement, HashToGroupElement, MultiScalarMul};
use std::ops::{Mul, Neg};

use crate::groups::secp256k1::{ProjectivePoint, Scalar};
use crate::groups::{secp256k1, Scalar as ScalarTrait};
use crate::serde_helpers::ToFromByteArray;
use rand::thread_rng;

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
fn test_serde() {
    let scalar = secp256k1::Scalar::rand(&mut thread_rng());
    let bytes = scalar.to_byte_array();
    let reconstructed = Scalar::from_byte_array(&bytes).unwrap();
    assert_eq!(scalar, reconstructed);

    let point = ProjectivePoint::generator() * scalar;
    let point_bytes = point.to_byte_array();
    let reconstructed_point = ProjectivePoint::from_byte_array(&point_bytes).unwrap();
    assert_eq!(point, reconstructed_point);
}

#[test]
fn test_regression() {
    let scalar = secp256k1::Scalar::from(7);
    assert_eq!(
        scalar.to_byte_array().to_vec(),
        hex::decode("0700000000000000000000000000000000000000000000000000000000000000").unwrap()
    );

    let point = ProjectivePoint::generator() * scalar;
    assert_eq!(
        point.to_byte_array().to_vec(),
        hex::decode("bcf9c4caeddd2be99ce330037e9b413d0e7aeaf265f398a3eab45d6e64f0bd5c00").unwrap()
    );

    let negate = point.neg();
    assert_eq!(
        negate.to_byte_array().to_vec(),
        hex::decode("bcf9c4caeddd2be99ce330037e9b413d0e7aeaf265f398a3eab45d6e64f0bd5c80").unwrap()
    );
}

#[test]
fn test_msm() {
    for l in 1..50 {
        let mut scalars = Vec::new();
        let mut points = Vec::new();
        let mut expected = ProjectivePoint::zero();
        for _ in 0..l {
            let s = Scalar::rand(&mut thread_rng());
            let e = Scalar::rand(&mut thread_rng());
            let g = ProjectivePoint::generator() * e;
            expected += g * s;
            scalars.push(s);
            points.push(g);
        }
        let actual = ProjectivePoint::multi_scalar_mul(&scalars, &points).unwrap();
        assert_eq!(expected, actual);
        assert!(ProjectivePoint::multi_scalar_mul(&scalars[1..], &points).is_err());
    }
}

#[test]
fn test_msm_edge_cases() {
    assert_eq!(
        ProjectivePoint::zero(),
        ProjectivePoint::multi_scalar_mul(&[], &[]).unwrap()
    );

    assert_eq!(
        ProjectivePoint::zero(),
        ProjectivePoint::multi_scalar_mul(&[Scalar::from(0)], &[ProjectivePoint::generator()])
            .unwrap()
    );

    assert_eq!(
        ProjectivePoint::generator(),
        ProjectivePoint::multi_scalar_mul(&[Scalar::from(1)], &[ProjectivePoint::generator()])
            .unwrap()
    );

    assert_eq!(
        ProjectivePoint::zero(),
        ProjectivePoint::multi_scalar_mul(
            &[Scalar::from(1).neg(), Scalar::from(1)],
            &[ProjectivePoint::generator(), ProjectivePoint::generator()]
        )
        .unwrap()
    );

    assert_eq!(
        ProjectivePoint::generator().mul(Scalar::from(2)),
        ProjectivePoint::multi_scalar_mul(
            &[Scalar::from(1), Scalar::from(1)],
            &[ProjectivePoint::generator(), ProjectivePoint::generator()]
        )
        .unwrap()
    );
}

#[test]
fn test_hash_to_group() {
    // Test that outputs are not equal for different inputs
    assert_ne!(
        ProjectivePoint::hash_to_group_element(b"Hello, world!"),
        ProjectivePoint::hash_to_group_element(b"Hello, world")
    );

    // Regression
    assert_eq!(
        ProjectivePoint::hash_to_group_element(b"Hello, world!")
            .to_byte_array()
            .to_vec(),
        hex::decode("01152edfc9b37a11548a9866a3f61d38a0d6d35a451385876929af08e59b8b2e80").unwrap()
    );

    // Hashing empty input
    assert_eq!(
        ProjectivePoint::hash_to_group_element(&[])
            .to_byte_array()
            .to_vec(),
        hex::decode("21673ed2d26a84ae6fea1cce285c70e229b3b959bbfc99aa90d93ef734d033b080").unwrap()
    );

    // Large input
    assert_eq!(
        ProjectivePoint::hash_to_group_element(&[0u8; 65537])
            .to_byte_array()
            .to_vec(),
        hex::decode("99a1b5a9a8d21a6897cff9f476601bfcc0395362e2ac7309ad8977e231197e5d80").unwrap()
    );
}

#[test]
fn test_point_conversion() {
    assert_eq!(
        ProjectivePoint::from(&(k256::ProjectivePoint::GENERATOR * k256::Scalar::from(7u64))),
        ProjectivePoint::generator() * Scalar::from(7)
    );
    assert_eq!(
        ProjectivePoint::from(&k256::ProjectivePoint::IDENTITY),
        ProjectivePoint::zero()
    );
}
