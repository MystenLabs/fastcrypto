// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::min_pk::{BLS12381KeyPair, BLS12381Signature};
use crate::groups::bls12381::{
    G1Element, G2Element, GTElement, Scalar, G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH,
};
use crate::groups::{GroupElement, HashToGroupElement, Pairing};
use crate::traits::VerifyingKey;
use crate::traits::{KeyPair, ToFromBytes};
use rand::{rngs::StdRng, SeedableRng as _};
use signature::Signer;

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
    assert_eq!(e1.pairing(&pk1), sig1.pairing(&G2Element::generator()));

    let e2 = G2Element::hash_to_group_element(MSG);
    let sk2 = Scalar::generator();
    let pk2 = G1Element::generator() * sk2;
    let sig2 = e2 * sk2;
    assert_eq!(pk2.pairing(&e2), G1Element::generator().pairing(&sig2));
}

#[test]
fn test_g1_serialize_deserialize() {
    // Serialize and deserialize 7*G1
    let p = G1Element::generator() * Scalar::from(7);
    let serialized = bincode::serialize(&p).unwrap();
    assert_eq!(serialized.len(), G1_ELEMENT_BYTE_LENGTH);
    let deserialized: G1Element = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);

    // Serialize and deserialize O
    let p = G1Element::zero();
    let serialized = bincode::serialize(&p).unwrap();
    let deserialized: G1Element = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);
}

#[test]
fn test_g2_serialize_deserialize() {
    // Serialize and deserialize 7*G1
    let p = G2Element::generator() * Scalar::from(7);
    let serialized = bincode::serialize(&p).unwrap();
    assert_eq!(serialized.len(), G2_ELEMENT_BYTE_LENGTH);
    let deserialized: G2Element = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);

    // Serialize and deserialize O
    let p = G2Element::zero();
    let serialized = bincode::serialize(&p).unwrap();
    let deserialized: G2Element = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized, p);
}

#[test]
fn test_consistent_bls12381_serialization() {
    // Generate with BLS signature APIs.
    let pair = BLS12381KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let (pk1, sk1) = (pair.public().clone(), pair.private());
    let sig1 = sk1.sign(MSG); // encoded in G1.

    // Convert using serialized byte arrays.
    let pk2: G1Element = bincode::deserialize(pk1.as_ref()).unwrap();
    let sig2: G2Element = bincode::deserialize(sig1.as_ref()).unwrap();
    // Check signature with pk2, sig2.
    assert_eq!(
        pk2.pairing(&G2Element::hash_to_group_element(MSG)),
        G1Element::generator().pairing(&sig2)
    );

    // Convert back and check the resulting signature.
    let sig2_as_bytes = bincode::serialize(&sig2).unwrap();
    let sig3 = <BLS12381Signature as ToFromBytes>::from_bytes(sig2_as_bytes.as_slice()).unwrap();
    pk1.verify(MSG, &sig3).unwrap();
    assert_eq!(sig1, sig3);
}
