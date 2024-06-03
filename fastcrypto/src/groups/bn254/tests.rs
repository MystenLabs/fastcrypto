// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;

use crate::groups::bn254::G1Element;
use crate::groups::bn254::G2Element;
use crate::groups::bn254::GTElement;
use crate::groups::bn254::Scalar;
use crate::groups::{FromTrustedByteArray, GroupElement, Pairing, Scalar as ScalarTrait};
use crate::serde_helpers::ToFromByteArray;
use crate::test_helpers::verify_serialization;

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
fn test_pairing() {
    let a = Scalar::rand(&mut thread_rng());

    assert_eq!(
        G1Element::pairing(&(G1Element::generator() * a), &G2Element::generator()),
        G1Element::pairing(&G1Element::generator(), &(G2Element::generator() * a))
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
            hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        ),
    );
    verify_serialization(
        &g1,
        Some(
            hex::decode("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        ),
    );
    verify_serialization(&g2, Some(hex::decode("edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19").unwrap().as_slice()));
    verify_serialization(&gt, Some(hex::decode("950e879d73631f5eb5788589eb5f7ef8d63e0a28de1ba00dfe4ca9ed3f252b264a8afb8eb4349db466ed1809ea4d7c39bdab7938821f1b0a00a295c72c2de002e01dbdfd0254134efcb1ec877395d25f937719b344adb1a58d129be2d6f2a9132b16a16e8ab030b130e69c69bd20b4c45986e6744a98314b5c1a0f50faa90b04dbaf9ef8aeeee3f50be31c210b598f4752f073987f9d35be8f6770d83f2ffc0af0d18dd9d2dbcdf943825acc12a7a9ddca45e629d962c6bd64908c3930a5541cfe2924dcc5580d5cef7a4bfdec90a91b59926f850d4a7923c01a5a5dbf0f5c094a2b9fb9d415820fa6b40c59bb9eade9c953407b0fc11da350a9d872cad6d3142974ca385854afdf5f583c04231adc5957c8914b6b20dc89660ed7c3bbe7c01d972be2d53ecdb27a1bcc16ac610db95aa7d237c8ff55a898cb88645a0e32530b23d7ebf5dafdd79b0f9c2ac4ba07ce18d3d16cf36e47916c4cae5d08d3afa813972c769e8514533e380c9443b3e1ee5c96fa3a0a73f301b626454721527bf900").unwrap().as_slice()));
    verify_serialization(
        &id1,
        Some(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000040")
                .unwrap()
                .as_slice(),
        ),
    );
    verify_serialization(&id2, Some(hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040").unwrap().as_slice()));
    verify_serialization(&id3, Some(hex::decode("010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap().as_slice()));
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
fn test_serialization_scalar() {
    let bytes = [0u8; 32];
    assert_eq!(Scalar::from_byte_array(&bytes).unwrap(), Scalar::zero());

    // Scalar::from_byte_array should not accept the order or above it.
    let mut order =
        hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001").unwrap();
    order.reverse(); // Little-endian
    assert!(Scalar::from_byte_array(<&[u8; 32]>::try_from(order.as_slice()).unwrap()).is_err());

    // Scalar::from_byte_array should accept the order - 1.
    let mut order_minus_one =
        hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000").unwrap();
    order_minus_one.reverse(); // Little-endian
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

    // All zero serialization for G1 should fail.
    let mut bytes = [0u8; 32];
    assert!(G1Element::from_byte_array(&bytes).is_err());

    // Valid infinity
    bytes[31] |= infinity_bit;
    assert_eq!(
        G1Element::zero(),
        G1Element::from_byte_array(&bytes).unwrap()
    );

    // to and from_byte_array should be inverses.
    let bytes = G1Element::generator().to_byte_array();
    assert_eq!(
        G1Element::generator(),
        G1Element::from_byte_array(&bytes).unwrap()
    );

    // Test correct uncompressed serialization of a point
    let mut uncompressed_bytes = [0u8; 64];
    G1Affine::generator()
        .serialize_uncompressed(uncompressed_bytes.as_mut_slice())
        .unwrap();
    // This works because from_byte_array the compressed format is just the first coordinate.
    assert_eq!(
        G1Element::generator(),
        G1Element::from_byte_array(&(uncompressed_bytes[0..32].try_into().unwrap())).unwrap()
    );

    // Test FromTrustedByteArray.
    let mut bytes = G1Element::generator().to_byte_array();
    let g1 = G1Element::from_trusted_byte_array(&bytes).unwrap();
    assert_eq!(g1, G1Element::generator());
    // Also when the input is not a valid point.
    bytes[bytes.len() - 1] += 2;
    assert!(G1Element::from_trusted_byte_array(&bytes).is_ok());
}

#[test]
fn test_serialization_g2() {
    let infinity_bit = 0x40;

    // All zero serialization for G2 should fail.
    let mut bytes = [0u8; 64];
    assert!(G2Element::from_byte_array(&bytes).is_err());

    // Valid infinity when the right bits are set.
    bytes[63] |= infinity_bit;
    assert_eq!(
        G2Element::zero(),
        G2Element::from_byte_array(&bytes).unwrap()
    );

    // to and from_byte_array should be inverses.
    let bytes = G2Element::generator().to_byte_array();
    assert_eq!(
        G2Element::generator(),
        G2Element::from_byte_array(&bytes).unwrap()
    );

    // Test correct uncompressed serialization of a point
    let mut uncompressed_bytes = [0u8; 128];
    G2Affine::generator()
        .serialize_uncompressed(uncompressed_bytes.as_mut_slice())
        .unwrap();

    // This works because the compressed format is just the first coordinate.
    assert_eq!(
        G2Element::generator(),
        G2Element::from_byte_array(&(uncompressed_bytes[0..64].try_into().unwrap())).unwrap()
    );

    // Test FromTrustedByteArray.
    let mut bytes = G2Element::generator().to_byte_array();
    let g2 = G2Element::from_trusted_byte_array(&bytes).unwrap();
    assert_eq!(g2, G2Element::generator());
    // Also when the input is not a valid point.
    bytes[bytes.len() - 1] += 2;
    assert!(G2Element::from_trusted_byte_array(&bytes).is_ok());
    assert!(G2Element::from_byte_array(&bytes).is_err());
}

#[test]
fn test_serialization_gt() {
    // All zero serialization for GT should fail.
    let bytes = [0u8; 384];
    assert!(GTElement::from_byte_array(&bytes).is_err());

    // to and from_byte_array should be inverses.
    let bytes = GTElement::generator().to_byte_array();
    assert_eq!(
        GTElement::generator(),
        GTElement::from_byte_array(&bytes).unwrap()
    );

    // reject if one of the elements >= P
    let mut bytes = GTElement::generator().to_byte_array();
    let p =
        hex::decode("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47").unwrap();
    let mut carry = 0;
    let mut target = [0; 32];
    for i in (0..32).rev() {
        let sum = (bytes[i] as u16) + (p[i] as u16) + carry;
        target[i] = (sum % 256) as u8;
        carry = sum / 256;
    }
    assert_eq!(carry, 0);
    bytes[0..32].copy_from_slice(&target);
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
