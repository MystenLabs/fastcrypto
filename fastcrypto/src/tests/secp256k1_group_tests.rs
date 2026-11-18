// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::{AdditiveGroup, Doubling, MultiScalarMul};
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
        hex::decode("0000000000000000000000000000000000000000000000000000000000000007").unwrap()
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

/// The secp256k1 field modulus p as 32 big-endian bytes.
const FIELD_MODULUS_BE: [u8; 32] =
    hex_literal::hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// Returns an x-coordinate (as 32 big-endian bytes) that is smaller than p but not on the curve.
fn x_not_on_curve() -> [u8; 32] {
    (0u8..)
        .map(|i| {
            let mut x = [0u8; 32];
            x[31] = i;
            x
        })
        .find(|x| ProjectivePoint::with_even_y_from_x_be_bytes(x).is_err())
        .unwrap()
}

#[test]
fn test_canonical_encoding() {
    // Canonical encodings round trip, including points where y > (p - 1) / 2 and the identity.
    let mut points = vec![ProjectivePoint::zero(), ProjectivePoint::generator()];
    points.extend((0..100).map(|_| ProjectivePoint::generator() * Scalar::rand(&mut thread_rng())));
    for point in &points {
        let bytes = point.to_byte_array();
        assert!(
            bytes[32] == 0x00
                || bytes[32] == 0x80
                || bytes == ProjectivePoint::zero().to_byte_array()
        );
        assert_eq!(ProjectivePoint::from_byte_array(&bytes).unwrap(), *point);
        assert_eq!(
            bcs::from_bytes::<ProjectivePoint>(&bcs::to_bytes(point).unwrap()).unwrap(),
            *point
        );
    }

    let mut identity = [0u8; 33];
    identity[32] = 0x40;
    assert_eq!(ProjectivePoint::zero().to_byte_array(), identity);

    // Arkworks ignores the six lowest bits of the flag byte. They must be zero.
    let g = ProjectivePoint::generator().to_byte_array();
    for bits in 1..0x40u8 {
        for sign in [0x00, 0x80] {
            let mut bytes = g;
            bytes[32] = sign | bits;
            assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
            assert!(bcs::from_bytes::<ProjectivePoint>(&bytes).is_err());
        }
        let mut bytes = identity;
        bytes[32] |= bits;
        assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
    }

    // Arkworks ignores the x-coordinate if the infinity flag is set. It must be zero.
    for i in 0..32 {
        let mut bytes = identity;
        bytes[i] = 1;
        assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
    }
    let mut bytes = g;
    bytes[32] = 0x40;
    assert!(ProjectivePoint::from_byte_array(&bytes).is_err());

    // Both the infinity flag and the sign flag.
    bytes[32] = 0xc0;
    assert!(ProjectivePoint::from_byte_array(&bytes).is_err());

    // x >= p and x not on the curve.
    let mut x_le = FIELD_MODULUS_BE;
    x_le.reverse();
    let mut bytes = [0u8; 33];
    bytes[..32].copy_from_slice(&x_le);
    assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
    let mut x_le = x_not_on_curve();
    x_le.reverse();
    bytes[..32].copy_from_slice(&x_le);
    assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
}

#[test]
fn test_sec1_encoding() {
    use rust_secp256k1::{PublicKey, SecretKey, SECP256K1};

    // Matches libsecp256k1 on random points, which have both even and odd y-coordinates.
    let mut odd = 0;
    for _ in 0..100 {
        let scalar = Scalar::rand(&mut thread_rng());
        let point = ProjectivePoint::generator() * scalar;
        let sk = SecretKey::from_slice(&scalar.to_byte_array()).unwrap();
        let expected = PublicKey::from_secret_key(SECP256K1, &sk).serialize();

        let bytes = point.to_sec1_bytes().unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(ProjectivePoint::from_sec1_bytes(&bytes).unwrap(), point);
        assert_eq!(bytes[1..], point.x_as_be_bytes().unwrap());
        assert_eq!(bytes[0] == 0x03, !point.has_even_y().unwrap());
        odd += (bytes[0] == 0x03) as usize;
    }
    assert!(odd > 0 && odd < 100);

    // Regression test: 7·G.
    assert_eq!(
        (ProjectivePoint::generator() * Scalar::from(7))
            .to_sec1_bytes()
            .unwrap()
            .to_vec(),
        hex::decode("025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc").unwrap()
    );

    // The identity has no 33-byte SEC1 encoding.
    assert!(ProjectivePoint::zero().to_sec1_bytes().is_err());

    // Only the compressed tags are accepted.
    let g = ProjectivePoint::generator().to_sec1_bytes().unwrap();
    for tag in [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
        let mut bytes = g;
        bytes[0] = tag;
        assert!(ProjectivePoint::from_sec1_bytes(&bytes).is_err());
    }

    // x >= p and x not on the curve.
    let mut bytes = [0x02u8; 33];
    bytes[1..].copy_from_slice(&FIELD_MODULUS_BE);
    assert!(ProjectivePoint::from_sec1_bytes(&bytes).is_err());
    bytes[1..].copy_from_slice(&x_not_on_curve());
    assert!(ProjectivePoint::from_sec1_bytes(&bytes).is_err());
}
