// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::groups::bls12381::{G1Element, G2Element, GTElement, Scalar};
use crate::groups::{GroupElement, HashToGroupElement, Pairing};

const MSG: &[u8] = b"test message";

// TODO: add regression tests with test vectors.

#[test]
fn test_g1_arithmetic() {
    // Test that different ways of computing [5]G gives the expected result
    let g = G1Element::generator();

    let p1 = g * Scalar::from(5);

    let p2 = g + g + g + g + g;
    assert_eq!(p1, p2);

    let mut p3 = G1Element::zero();
    p3 += p2;
    assert_eq!(p1, p3);

    let mut p4 = g;
    p4 *= Scalar::from(5);
    assert_eq!(p1, p4);

    let p5 = g * (Scalar::from(7) - Scalar::from(2));
    assert_eq!(p1, p5);

    let p6 = g * Scalar::zero();
    assert_eq!(G1Element::zero(), p6);

    assert_ne!(G1Element::zero(), g);
    assert_eq!(G1Element::zero(), g - g);
}

#[test]
fn test_g2_arithmetic() {
    // Test that different ways of computing [5]G gives the expected result
    let g = G2Element::generator();

    let p1 = g * Scalar::from(5);

    let p2 = g + g + g + g + g + g - g;
    assert_eq!(p1, p2);

    let mut p3 = G2Element::zero();
    p3 += p2;
    assert_eq!(p1, p3);

    let mut p4 = g;
    p4 *= Scalar::from(5);
    assert_eq!(p1, p4);

    let p5 = g * (Scalar::from(7) - Scalar::from(2));
    assert_eq!(p1, p5);

    let p6 = g * Scalar::zero();
    assert_eq!(G2Element::zero(), p6);

    assert_ne!(G2Element::zero(), g);
    assert_eq!(G2Element::zero(), g - g);
}

#[test]
fn test_gt_arithmetic() {
    // Test that different ways of computing [5]G gives the expected result
    let g = GTElement::generator();

    let p1 = g * Scalar::from(5);

    let p2 = g + g + g + g + g + g - g;
    assert_eq!(p1, p2);

    let mut p3 = GTElement::zero();
    p3 += p2;
    assert_eq!(p1, p3);

    let mut p4 = g;
    p4 *= Scalar::from(5);
    assert_eq!(p1, p4);

    let p5 = g * (Scalar::from(7) - Scalar::from(2));
    assert_eq!(p1, p5);

    let p6 = g * Scalar::zero();
    assert_eq!(GTElement::zero(), p6);

    assert_ne!(GTElement::zero(), g);
    assert_eq!(GTElement::zero(), g - g);
}

#[test]
fn test_pairing_and_hash_to_curve() {
    let e1 = G1Element::hash_to_group_element(MSG);
    let sk1 = Scalar::generator();
    let pk1 = G2Element::generator() * sk1;
    let sig1 = e1 * sk1;
    assert_eq!(e1.pair(&pk1), sig1.pair(&G2Element::generator()));

    let e2 = G2Element::hash_to_group_element(MSG);
    let sk2 = Scalar::generator();
    let pk2 = G1Element::generator() * sk2;
    let sig2 = e2 * sk2;
    assert_eq!(pk2.pair(&e2), G1Element::generator().pair(&sig2));
}

#[test]
fn test_g1_serialize_deserialize<'a>() {
    let p = G1Element::generator() * Scalar::from(7);
    let serialized = bincode::serialize(&p).unwrap();
    let deserialized: G1Element = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);
}

#[test]
fn test_g2_serialize_deserialize<'a>() {
    let p = G2Element::generator() * Scalar::from(7);
    let serialized = bincode::serialize(&p).unwrap();
    let deserialized: G2Element = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);
}
