// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::min_pk::{BLS12381KeyPair, BLS12381Signature};
use crate::groups::bls12381::{G1Element, G2Element, GTElement, Scalar};
use crate::groups::{
    GroupElement, HashToGroupElement, MultiScalarMul, Pairing, Scalar as ScalarTrait,
};
use crate::test_helpers::verify_serialization;
use crate::groups::{GroupElement, HashToGroupElement, Pairing};
use crate::serde_helpers::ToFromByteArray;
use crate::traits::Signer;
use crate::traits::VerifyingKey;
use crate::traits::{KeyPair, ToFromBytes};
use rand::{rngs::StdRng, thread_rng, SeedableRng as _};

const MSG: &[u8] = b"test message";

// TODO: add test vectors.

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

    // Scalar::from_byte_array should not accept the order.
    let order =
        hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001").unwrap();
    assert!(Scalar::from_byte_array(<&[u8; 32]>::try_from(order.as_slice()).unwrap()).is_err());
}

#[test]
fn test_g1_msm() {
    let mut scalars = Vec::new();
    let mut points = Vec::new();
    let mut expected = G1Element::zero();
    for _ in 0..50 {
        let s = Scalar::rand(&mut thread_rng());
        let e = Scalar::rand(&mut thread_rng());
        let g = G1Element::generator() * e;
        expected += g * s;
        scalars.push(s);
        points.push(g);
    }
    let actual = G1Element::multi_scalar_mul(&scalars, &points).unwrap();
    assert_eq!(expected, actual);

    assert!(G1Element::multi_scalar_mul(&scalars[1..], &points).is_err());
    assert!(G1Element::multi_scalar_mul(&[], &[]).is_err());
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
fn test_g2_msm() {
    let mut scalars = Vec::new();
    let mut points = Vec::new();
    let mut expected = G2Element::zero();
    for _ in 0..50 {
        let s = Scalar::rand(&mut thread_rng());
        let e = Scalar::rand(&mut thread_rng());
        let g = G2Element::generator() * e;
        expected += g * s;
        scalars.push(s);
        points.push(g);
    }
    let actual = G2Element::multi_scalar_mul(&scalars, &points).unwrap();
    assert_eq!(expected, actual);

    assert!(G2Element::multi_scalar_mul(&scalars[1..], &points).is_err());
    assert!(G2Element::multi_scalar_mul(&[], &[]).is_err());
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
fn test_serde_and_regression() {
    let s1 = Scalar::from(1);
    let g1 = G1Element::generator();
    let g2 = G2Element::generator();
    let id1 = G1Element::zero();
    let id2 = G2Element::zero();

    verify_serialization(
        &s1,
        Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap()
                .as_slice(),
        ),
    );
    verify_serialization(&g1, Some(hex::decode("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb").unwrap().as_slice()));
    verify_serialization(&g2, Some(hex::decode("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8").unwrap().as_slice()));
    verify_serialization(&id1, Some(hex::decode("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
    verify_serialization(&id2, Some(hex::decode("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
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
