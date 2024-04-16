// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::min_pk::{BLS12381KeyPair, BLS12381Signature};
use crate::groups::bls12381::{reduce_mod_uniform_buffer, G1Element, G2Element, GTElement, Scalar};
use crate::groups::{
    FromTrustedByteArray, GroupElement, HashToGroupElement, MultiScalarMul, Pairing,
    Scalar as ScalarTrait,
};
use crate::serde_helpers::ToFromByteArray;
use crate::test_helpers::verify_serialization;
use crate::traits::Signer;
use crate::traits::VerifyingKey;
use crate::traits::{KeyPair, ToFromBytes};
use blst::{
    blst_p1_affine, blst_p1_affine_generator, blst_p1_affine_on_curve, blst_p1_affine_serialize,
    blst_p1_deserialize, blst_p2_affine, blst_p2_affine_generator, blst_p2_affine_on_curve,
    blst_p2_affine_serialize, blst_p2_deserialize, BLST_ERROR,
};
use rand::{rngs::StdRng, thread_rng, RngCore, SeedableRng as _};

const MSG: &[u8] = b"test message";

// TODO: add test vectors.

#[test]
fn test_scalar_arithmetic() {
    let zero = Scalar::zero();
    let one = Scalar::generator();

    assert_eq!(zero, zero - zero);
    assert_eq!(zero, -zero);

    let four = one + zero + one + one + one;
    assert_eq!(four, Scalar::from(4));

    let three = four - one;
    assert_eq!(three, one + one + one);

    let six = three * Scalar::from(2);
    assert_eq!(six, Scalar::from(6));

    let two = (six / three).unwrap();
    assert_eq!(two, Scalar::from(2));

    assert!((six / zero).is_err());

    let inv_two = two.inverse().unwrap();
    assert_eq!(inv_two * two, one);

    // Check that u128 is decoded correctly.
    let x: u128 = 2 << 66;
    let x_scalar = Scalar::from(x);
    let res = x_scalar / Scalar::from(8);
    assert_eq!(res.unwrap(), Scalar::from(2 << 63));
}

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

    let sc = Scalar::rand(&mut thread_rng());
    let p7 = g * sc;
    assert_eq!(p7 * Scalar::from(1), p7);

    assert_ne!(G1Element::zero(), g);
    assert_eq!(G1Element::zero(), g - g);

    assert!((G1Element::generator() / Scalar::zero()).is_err());
    assert_eq!((p5 / Scalar::from(5)).unwrap(), g);

    let identity = G1Element::zero();
    assert_eq!(identity, identity - identity);
    assert_eq!(identity, -identity);
}

#[test]
fn test_g1_msm() {
    for l in 1..50 {
        let mut scalars = Vec::new();
        let mut points = Vec::new();
        let mut expected = G1Element::zero();
        for _ in 0..l {
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
}

#[test]
fn test_g1_msm_single() {
    let actual =
        G1Element::multi_scalar_mul(&[Scalar::generator()], &[G1Element::generator()]).unwrap();
    assert_eq!(G1Element::generator(), actual);

    let r = Scalar::rand(&mut thread_rng());
    let actual = G1Element::multi_scalar_mul(&[r], &[G1Element::generator()]).unwrap();
    assert_eq!(G1Element::generator() * r, actual);

    let r = Scalar::rand(&mut thread_rng());
    let h = G1Element::generator() * Scalar::rand(&mut thread_rng());
    let actual = G1Element::multi_scalar_mul(&[r], &[h]).unwrap();
    assert_eq!(h * r, actual);
}

#[test]
fn test_g1_msm_identity() {
    let actual = G1Element::multi_scalar_mul(&[Scalar::zero()], &[G1Element::generator()]).unwrap();
    assert_eq!(G1Element::zero(), actual);

    let actual = G1Element::multi_scalar_mul(&[Scalar::generator()], &[G1Element::zero()]).unwrap();
    assert_eq!(G1Element::zero(), actual);

    let actual = G1Element::multi_scalar_mul(
        &[Scalar::zero(), Scalar::generator()],
        &[G1Element::generator(), G1Element::generator()],
    )
    .unwrap();
    assert_eq!(G1Element::generator(), actual);

    let h = G1Element::generator() * Scalar::rand(&mut thread_rng());
    let actual =
        G1Element::multi_scalar_mul(&[Scalar::generator(), Scalar::zero()], &[h, h]).unwrap();
    assert_eq!(h, actual);

    // since blst 0.3.11 this bug is triggered only for large inputs (after the fix
    // of https://github.com/supranational/blst/commit/168ff67ce74f2dbace619704bb75a865d0e6c913)
    (2..200).for_each(|l| {
        let ones = vec![Scalar::generator(); l];
        let mut points = vec![G1Element::generator(); l];
        let rand_index = thread_rng().next_u32() as usize % l;
        points[rand_index] = G1Element::zero();
        let actual = G1Element::multi_scalar_mul(&ones, &points).unwrap();
        assert_eq!(
            G1Element::generator() * Scalar::from((l - 1) as u128),
            actual
        );
    });
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

    let sc = Scalar::rand(&mut thread_rng());
    let p7 = g * sc;
    assert_eq!(p7 * Scalar::from(1), p7);

    assert!((G2Element::generator() / Scalar::zero()).is_err());
    assert_eq!((p5 / Scalar::from(5)).unwrap(), g);

    assert_ne!(G2Element::zero(), g);
    assert_eq!(G2Element::zero(), g - g);

    let identity = G2Element::zero();
    assert_eq!(identity, identity - identity);
    assert_eq!(identity, -identity);
}

#[test]
fn test_g2_msm() {
    for l in 1..50 {
        let mut scalars = Vec::new();
        let mut points = Vec::new();
        let mut expected = G2Element::zero();
        for _ in 0..l {
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
}

#[test]
fn test_g2_msm_single() {
    let actual =
        G2Element::multi_scalar_mul(&[Scalar::generator()], &[G2Element::generator()]).unwrap();
    assert_eq!(G2Element::generator(), actual);

    let r = Scalar::rand(&mut thread_rng());
    let actual = G2Element::multi_scalar_mul(&[r], &[G2Element::generator()]).unwrap();
    assert_eq!(G2Element::generator() * r, actual);

    let r = Scalar::rand(&mut thread_rng());
    let h = G2Element::generator() * Scalar::rand(&mut thread_rng());
    let actual = G2Element::multi_scalar_mul(&[r], &[h]).unwrap();
    assert_eq!(h * r, actual);
}

#[test]
fn test_g2_msm_identity() {
    let actual = G2Element::multi_scalar_mul(&[Scalar::zero()], &[G2Element::generator()]).unwrap();
    assert_eq!(G2Element::zero(), actual);

    let actual = G2Element::multi_scalar_mul(&[Scalar::generator()], &[G2Element::zero()]).unwrap();
    assert_eq!(G2Element::zero(), actual);

    let actual = G2Element::multi_scalar_mul(
        &[Scalar::zero(), Scalar::generator()],
        &[G2Element::generator(), G2Element::generator()],
    )
    .unwrap();
    assert_eq!(G2Element::generator(), actual);

    let h = G2Element::generator() * Scalar::rand(&mut thread_rng());
    let actual =
        G2Element::multi_scalar_mul(&[Scalar::generator(), Scalar::zero()], &[h, h]).unwrap();
    assert_eq!(h, actual);

    // since blst 0.3.11 this bug is triggered only for large inputs (after the fix
    // of https://github.com/supranational/blst/commit/168ff67ce74f2dbace619704bb75a865d0e6c913)
    (2..200).for_each(|l| {
        let ones = vec![Scalar::generator(); l];
        let mut points = vec![G2Element::generator(); l];
        let rand_index = thread_rng().next_u32() as usize % l;
        points[rand_index] = G2Element::zero();
        let actual = G2Element::multi_scalar_mul(&ones, &points).unwrap();
        assert_eq!(
            G2Element::generator() * Scalar::from((l - 1) as u128),
            actual
        );
    });
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

    let sc = Scalar::rand(&mut thread_rng());
    let p7 = g * sc;
    assert_eq!(p7 * Scalar::from(1), p7);

    assert_ne!(GTElement::zero(), g);
    assert_eq!(GTElement::zero(), g - g);
    assert_eq!(GTElement::zero(), GTElement::zero() - GTElement::zero());

    assert!((GTElement::generator() / Scalar::zero()).is_err());
    assert_eq!((p5 / Scalar::from(5)).unwrap(), g);
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

    assert_eq!(
        G1Element::zero().pairing(&G2Element::zero()),
        GTElement::zero()
    );
    assert_eq!(
        G1Element::zero().pairing(&G2Element::generator()),
        GTElement::zero()
    );
    assert_eq!(
        G1Element::generator().pairing(&G2Element::zero()),
        GTElement::zero()
    );

    // next should not fail
    let _ = G1Element::hash_to_group_element(&[]);
    let _ = G2Element::hash_to_group_element(&[]);
    let _ = G1Element::hash_to_group_element(&[1]);
    let _ = G2Element::hash_to_group_element(&[1]);

    // Test multi-pairing
    assert!(G1Element::multi_pairing(&[], &[pk1]).is_err());
    assert_eq!(
        G1Element::multi_pairing(&[], &[]).unwrap(),
        GTElement::zero()
    );
    assert_eq!(
        G1Element::multi_pairing(&[e1], &[pk1]).unwrap(),
        e1.pairing(&pk1)
    );
    assert_eq!(
        G1Element::multi_pairing(&[e1, pk2], &[pk1, e2]).unwrap(),
        e1.pairing(&pk1) + pk2.pairing(&e2)
    );
    assert_eq!(
        G1Element::multi_pairing(&[G1Element::zero()], &[G2Element::zero()]).unwrap(),
        GTElement::zero()
    );
    assert_eq!(
        G1Element::multi_pairing(
            &[G1Element::zero(), G1Element::zero()],
            &[G2Element::zero(), G2Element::zero()]
        )
        .unwrap(),
        GTElement::zero()
    );
    assert_eq!(
        G1Element::multi_pairing(&[G1Element::generator()], &[G2Element::zero()]).unwrap(),
        GTElement::zero()
    );
    assert_eq!(
        G1Element::multi_pairing(&[G1Element::zero()], &[G2Element::generator()]).unwrap(),
        GTElement::zero()
    );
}

#[test]
fn test_serde_and_regression() {
    let s1 = Scalar::generator();
    let g1 = G1Element::generator();
    let g2 = G2Element::generator();
    let gt = GTElement::generator();
    let id1 = G1Element::zero();
    let id2 = G2Element::zero();
    let id3 = GTElement::zero();
    let id4 = Scalar::zero();

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
    verify_serialization(&gt, Some(hex::decode("1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba5703350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a201b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b604c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631").unwrap().as_slice()));
    verify_serialization(&id1, Some(hex::decode("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
    verify_serialization(&id2, Some(hex::decode("c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
    verify_serialization(&id3, Some(hex::decode("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
    verify_serialization(
        &id4,
        Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        ),
    );
}

#[test]
fn test_consistent_bls12381_serialization() {
    // Generate with BLS signature APIs.
    let pair = BLS12381KeyPair::generate(&mut StdRng::from_seed([0; 32]));
    let (pk1, sk1) = (pair.public().clone(), pair.private());
    let sig1 = sk1.sign(MSG); // encoded in G2.

    // Convert using serialized byte arrays.
    let sk2: Scalar = bincode::deserialize(sk1.as_ref()).unwrap();
    let pk2: G1Element = bincode::deserialize(pk1.as_ref()).unwrap();
    // Sign using group ops.
    let sig2 = G2Element::hash_to_group_element(MSG) * sk2;
    // Check signature with pk2, sig2.
    assert_eq!(
        pk2.pairing(&G2Element::hash_to_group_element(MSG)),
        G1Element::generator().pairing(&sig2)
    );
    let sig2_from_bytes: G2Element = bincode::deserialize(sig1.as_ref()).unwrap();
    assert_eq!(sig2, sig2_from_bytes);

    // Convert back and check the resulting signature.
    let sig2_as_bytes = bincode::serialize(&sig2).unwrap();
    let sig3 = <BLS12381Signature as ToFromBytes>::from_bytes(sig2_as_bytes.as_slice()).unwrap();
    pk1.verify(MSG, &sig3).unwrap();
    assert_eq!(sig1, sig3);
}

#[test]
fn test_serialization_scalar() {
    let bytes = [0u8; 32];
    assert_eq!(Scalar::from_byte_array(&bytes).unwrap(), Scalar::zero());

    // Scalar::from_byte_array should not accept the order or above it.
    let order =
        hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001").unwrap();
    assert!(Scalar::from_byte_array(<&[u8; 32]>::try_from(order.as_slice()).unwrap()).is_err());
    let order =
        hex::decode("73eda753299d9d483339d80809a1d80553bda402fffe5bfeffffffff11000001").unwrap();
    assert!(Scalar::from_byte_array(<&[u8; 32]>::try_from(order.as_slice()).unwrap()).is_err());

    // Scalar::from_byte_array should accept the order - 1.
    let order_minus_one =
        hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000").unwrap();
    assert_eq!(
        Scalar::from_byte_array(<&[u8; 32]>::try_from(order_minus_one.as_slice()).unwrap())
            .unwrap(),
        Scalar::zero() - Scalar::generator()
    );

    for _ in 0..100 {
        let s = Scalar::rand(&mut thread_rng());
        let bytes = s.to_byte_array();
        assert_eq!(s, Scalar::from_byte_array(&bytes).unwrap());
    }
}

#[test]
fn test_serialization_g1() {
    let infinity_bit = 0x40;
    let compressed_bit = 0x80;

    // All zero serialization for G1 should fail.
    let mut bytes = [0u8; 48];
    assert!(G1Element::from_byte_array(&bytes).is_err());

    // Infinity w/o compressed byte should fail.
    bytes[0] |= infinity_bit;
    assert!(G1Element::from_byte_array(&bytes).is_err());

    // Valid infinity
    bytes[0] |= compressed_bit;
    assert_eq!(
        G1Element::zero(),
        G1Element::from_byte_array(&bytes).unwrap()
    );

    // to and from_byte_array should be inverses.
    let mut bytes = G1Element::generator().to_byte_array();
    assert_eq!(
        G1Element::generator(),
        G1Element::from_byte_array(&bytes).unwrap()
    );
    assert_ne!(bytes[0] & compressed_bit, 0);

    // Unsetting the compressed bit set, this should fail.
    bytes[0] ^= compressed_bit;
    assert!(G1Element::from_byte_array(&bytes).is_err());

    // Test correct uncompressed serialization of a point
    let mut uncompressed_bytes = [0u8; 96];
    unsafe {
        blst_p1_affine_serialize(uncompressed_bytes.as_mut_ptr(), blst_p1_affine_generator());
    }
    // This should fail because from_byte_array only accepts compressed format.
    assert!(G1Element::from_byte_array(&(uncompressed_bytes[0..48].try_into().unwrap())).is_err());

    // But if we set the uncompressed bit, it should work because the compressed format is just the first coordinate.
    uncompressed_bytes[0] |= 0x80;
    assert_eq!(
        G1Element::generator(),
        G1Element::from_byte_array(&(uncompressed_bytes[0..48].try_into().unwrap())).unwrap()
    );

    // Test FromTrustedByteArray.
    let mut bytes = G1Element::generator().to_byte_array();
    let g1 = G1Element::from_trusted_byte_array(&bytes).unwrap();
    assert_eq!(g1, G1Element::generator());
    // Also when the input is not a valid point.
    bytes[bytes.len() - 1] += 2;
    assert!(G1Element::from_trusted_byte_array(&bytes).is_ok());
    // Verify that this is a valid point on the curve.
    unsafe {
        let mut p: blst_p1_affine = blst_p1_affine::default();
        assert!(blst_p1_deserialize(&mut p, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
        assert!(blst_p1_affine_on_curve(&p));
    };
    assert!(G1Element::from_byte_array(&bytes).is_err());
}

#[test]
fn test_serialization_g2() {
    let infinity_bit = 0x40;
    let compressed_bit = 0x80;

    // All zero serialization for G2 should fail.
    let mut bytes = [0u8; 96];
    assert!(G2Element::from_byte_array(&bytes).is_err());

    // Infinity w/o compressed byte should fail.
    bytes[0] |= infinity_bit;
    assert!(G2Element::from_byte_array(&bytes).is_err());

    // Valid infinity when the right bits are set.
    bytes[0] |= compressed_bit;
    assert_eq!(
        G2Element::zero(),
        G2Element::from_byte_array(&bytes).unwrap()
    );

    // to and from_byte_array should be inverses.
    let mut bytes = G2Element::generator().to_byte_array();
    assert_eq!(
        G2Element::generator(),
        G2Element::from_byte_array(&bytes).unwrap()
    );
    assert_ne!(bytes[0] & compressed_bit, 0);

    // Unsetting the compressed bit set, this should fail.
    bytes[0] ^= compressed_bit;
    assert!(G2Element::from_byte_array(&bytes).is_err());

    // Test correct uncompressed serialization of a point
    let mut uncompressed_bytes = [0u8; 192];
    unsafe {
        blst_p2_affine_serialize(uncompressed_bytes.as_mut_ptr(), blst_p2_affine_generator());
    }
    // This should fail because from_byte_array only accepts compressed format.
    assert!(G2Element::from_byte_array(&(uncompressed_bytes[0..96].try_into().unwrap())).is_err());

    // But if we set the uncompressed bit, it should work because the compressed format is just the first coordinate.
    uncompressed_bytes[0] |= 0x80;
    assert_eq!(
        G2Element::generator(),
        G2Element::from_byte_array(&(uncompressed_bytes[0..96].try_into().unwrap())).unwrap()
    );

    // Test FromTrustedByteArray.
    let mut bytes = G2Element::generator().to_byte_array();
    let g2 = G2Element::from_trusted_byte_array(&bytes).unwrap();
    assert_eq!(g2, G2Element::generator());
    // Also when the input is not a valid point.
    bytes[bytes.len() - 1] += 2;
    assert!(G2Element::from_trusted_byte_array(&bytes).is_ok());
    // Verify that this is a valid point on the curve.
    unsafe {
        let mut p: blst_p2_affine = blst_p2_affine::default();
        assert!(blst_p2_deserialize(&mut p, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
        assert!(blst_p2_affine_on_curve(&p));
    };
    assert!(G2Element::from_byte_array(&bytes).is_err());
}

#[test]
fn test_reduce_mod_uniform_buffer() {
    // 9920230154395168010467440495232506909487652629574290093191912925556996116934135093887783048487593217824704573634359454220706793741831181736379748807477797
    let bytes = <[u8; 64]>::try_from(hex::decode("bd69132eca59d8eb6b2aeaab1bb0f4128ea2554a2a5fd5ed90cfa341311d63d2bddef3cf93ebbd3781dc09921ca8611e0db756164b297a90cff258c8138a0a25").unwrap()).unwrap();
    // This is the above bytes as a big-endian integer modulo the BLS scalar field size and then written as big-endian bytes.
    let expected =
        hex::decode("42326e5eb98173088355c38dace25686f73f8900c8af2da6480b34e2313c49c2").unwrap();
    assert_eq!(expected, reduce_mod_uniform_buffer(&bytes).to_byte_array());

    // 99202309022396765790443178473142775358161915835492099699231487822465101596204583014819121570129071631157073920534979728799457207703011355835025584728154395168010467440495232506909487652629574290093191912925556996116934135093887783048487593217824704573634359454220706793741831181736379748807477797
    let bytes = <[u8; 59]>::try_from(hex::decode("bd69132eca59d8eb6b2aeaab1bb0f4128ea2554a2a5fd5ed90cfa341311d63d2bddef3cf93ebbd3781dc09921ca8611e0db756164b297a90cff258").unwrap()).unwrap();
    let expected =
        hex::decode("21015212b5c7a44c04c39447bf7d2addc5035a9b118f07a29956bf00fa65bd74").unwrap();
    assert_eq!(expected, reduce_mod_uniform_buffer(&bytes).to_byte_array());
}

#[test]
fn test_serialization_gt() {
    // All zero serialization for GT should fail.
    let bytes = [0u8; 576];
    assert!(GTElement::from_byte_array(&bytes).is_err());

    // to and from_byte_array should be inverses.
    let bytes = GTElement::generator().to_byte_array();
    assert_eq!(
        GTElement::generator(),
        GTElement::from_byte_array(&bytes).unwrap()
    );

    // reject if one of the elements >= P
    let mut bytes = GTElement::generator().to_byte_array();
    let p = hex::decode("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab").unwrap();
    let mut carry = 0;
    let mut target = [0; 48];
    for i in (0..48).rev() {
        let sum = (bytes[i] as u16) + (p[i] as u16) + carry;
        target[i] = (sum % 256) as u8;
        carry = sum / 256;
    }
    assert_eq!(carry, 0);
    bytes[0..48].copy_from_slice(&target);
    assert!(GTElement::from_byte_array(&bytes).is_err());

    // Test FromTrustedByteArray.
    let mut bytes = GTElement::generator().to_byte_array();
    let gt = GTElement::from_trusted_byte_array(&bytes).unwrap();
    assert_eq!(gt, GTElement::generator());
    // Also when the input is not a valid point.
    bytes[bytes.len() - 1] += 2;
    assert!(GTElement::from_trusted_byte_array(&bytes).is_ok());
    assert!(GTElement::from_byte_array(&bytes).is_err());
}
