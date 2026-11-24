// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::error::FastCryptoError;
use crate::groups::secp256k1::schnorr::{SchnorrPrivateKey, SchnorrPublicKey, SchnorrSignature};
use crate::groups::secp256k1::{ProjectivePoint, Scalar, POINT_SIZE_IN_BYTES};
use crate::groups::{
    Doubling, FiatShamirChallenge, GroupElement, MultiScalarMul, Scalar as ScalarTrait,
};
use crate::secp256r1_tests::add_small;
use crate::serde_helpers::ToFromByteArray;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use hex_literal::hex;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Field as _, PrimeField as _};
use k256::test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS};
use k256::{AffinePoint, EncodedPoint, U256};
use num_bigint::BigUint;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey, SECP256K1};

//
// Helper functions
//

/// The field modulus p, big-endian.
const FIELD_MODULUS: [u8; 32] =
    hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// The group order n, big-endian.
const GROUP_ORDER: [u8; 32] =
    hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

/// x = 5 is smaller than p but not the x-coordinate of a point on the curve.
const X_NOT_ON_CURVE: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000005");

/// x = 1 is the x-coordinate of a point on the curve, since 1 + 7 = 8 is a square modulo p.
const X_ONE: [u8; 32] = hex!("0000000000000000000000000000000000000000000000000000000000000001");

/// p + 1, big-endian: x = 1 not reduced modulo p. BIP-340 test vector 14 uses it as a public key.
const FIELD_MODULUS_PLUS_ONE: [u8; 32] =
    hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30");

/// p - 3, big-endian: the largest x-coordinate of a point on the curve.
const LARGEST_X: [u8; 32] =
    hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c");

/// The arkworks compressed encoding of the identity.
const IDENTITY_ENCODING: [u8; POINT_SIZE_IN_BYTES] =
    hex!("000000000000000000000000000000000000000000000000000000000000000040");

/// The arkworks flag bytes: y > (p - 1) / 2 and the identity.
const FLAG_Y_IS_LARGE: u8 = 0x80;
const FLAG_IDENTITY: u8 = 0x40;

/// Reverses the byte order, from big-endian to little-endian or back.
fn reversed(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes.reverse();
    bytes
}

fn minus_one() -> k256::Scalar {
    -k256::Scalar::ONE
}

/// 2^k modulo n.
fn two_to_the(k: usize) -> k256::Scalar {
    (0..k).fold(k256::Scalar::ONE, |x, _| x.double())
}

/// The big-endian integer reduced modulo n.
fn reduce(bytes: &[u8; 32]) -> k256::Scalar {
    <k256::Scalar as Reduce<U256>>::from_be_bytes_reduced((*bytes).into())
}

fn from_k256_scalar(scalar: &k256::Scalar) -> Scalar {
    Scalar::from_byte_array(&scalar.to_bytes().into()).unwrap()
}

fn to_k256_scalar(scalar: &Scalar) -> k256::Scalar {
    k256::Scalar::from_repr(scalar.to_byte_array().into()).unwrap()
}

/// The affine coordinates of a point, big-endian, or `None` for the identity.
fn affine_coordinates(point: &ProjectivePoint) -> Option<([u8; 32], [u8; 32])> {
    let affine = point.0.into_affine();
    let to_bytes = |x: Vec<u8>| <[u8; 32]>::try_from(x).unwrap();
    (!affine.infinity).then(|| {
        (
            to_bytes(affine.x.into_bigint().to_bytes_be()),
            to_bytes(affine.y.into_bigint().to_bytes_be()),
        )
    })
}

/// Converts a point to k256 through its affine coordinates, independently of the encodings under
/// test.
fn to_k256_point(point: &ProjectivePoint) -> k256::ProjectivePoint {
    match affine_coordinates(point) {
        None => k256::ProjectivePoint::IDENTITY,
        Some((x, y)) => {
            let encoded = EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
            AffinePoint::from_encoded_point(&encoded).unwrap().into()
        }
    }
}

/// The point k * G, computed by fastcrypto and by k256.
fn multiple_of_generator(k: &k256::Scalar) -> (ProjectivePoint, k256::ProjectivePoint) {
    (
        ProjectivePoint::generator() * from_k256_scalar(k),
        k256::ProjectivePoint::GENERATOR * k,
    )
}

/// The arkworks compressed encoding of a point, computed with k256: x little-endian followed by
/// [FLAG_Y_IS_LARGE] iff y > p - y, or [IDENTITY_ENCODING].
fn expected_encoding(point: &k256::ProjectivePoint) -> [u8; POINT_SIZE_IN_BYTES] {
    let encoded = point.to_affine().to_encoded_point(false);
    let (Some(x), Some(y)) = (encoded.x(), encoded.y()) else {
        return IDENTITY_ENCODING;
    };
    let y = U256::from_be_slice(y);
    let mut bytes = [0; POINT_SIZE_IN_BYTES];
    bytes[..32].copy_from_slice(&reversed((*x).into()));
    if y > U256::from_be_slice(&FIELD_MODULUS).wrapping_sub(&y) {
        bytes[32] = FLAG_Y_IS_LARGE;
    }
    bytes
}

/// The point that the arkworks compressed encoding `bytes` canonically encodes, if any, found
/// with k256 by decompressing x and comparing with [expected_encoding].
fn decode_with_k256(bytes: &[u8; POINT_SIZE_IN_BYTES]) -> Option<k256::ProjectivePoint> {
    if *bytes == IDENTITY_ENCODING {
        return Some(k256::ProjectivePoint::IDENTITY);
    }
    let mut sec1 = [0x02; 33];
    sec1[1..].copy_from_slice(&reversed(bytes[..32].try_into().unwrap()));
    let point = k256::ProjectivePoint::from(Option::<AffinePoint>::from(
        AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(sec1).unwrap()),
    )?);
    [point, -point]
        .into_iter()
        .find(|p| expected_encoding(p) == *bytes)
}

/// The arkworks compressed encoding with the given x-coordinate (big-endian) and flag byte.
fn arkworks_bytes(x: &[u8; 32], flag: u8) -> [u8; POINT_SIZE_IN_BYTES] {
    let mut bytes = [flag; POINT_SIZE_IN_BYTES];
    bytes[..32].copy_from_slice(&reversed(*x));
    bytes
}

/// The SEC1 compressed encoding with the given tag and x-coordinate.
fn sec1_bytes(tag: u8, x: &[u8; 32]) -> [u8; 33] {
    let mut bytes = [tag; 33];
    bytes[1..].copy_from_slice(x);
    bytes
}

/// Edge cases of scalars: 0, ±1, ±2, (n ± 1) / 2, 2^k and 2^k - 1 at limb and byte boundaries
/// (2^256 - 1 is reduced modulo n) and an arbitrary scalar.
fn edge_scalars() -> Vec<k256::Scalar> {
    let one = k256::Scalar::ONE;
    let half = minus_one() * k256::Scalar::from(2u64).invert().unwrap();
    let mut scalars = vec![
        k256::Scalar::ZERO,
        one,
        one.double(),
        minus_one(),
        minus_one() - one,
        half,
        half + one,
        reduce(&hex!(
            "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"
        )),
    ];
    for k in [8, 63, 64, 128, 255, 256] {
        scalars.push(two_to_the(k));
        scalars.push(two_to_the(k) - one);
    }
    scalars
}

/// The secret key and the x-only public key of a key pair, as libsecp256k1 computes them.
fn libsecp256k1_key_pair(secret: &[u8; 32]) -> (Keypair, XOnlyPublicKey) {
    let key_pair =
        Keypair::from_secret_key(SECP256K1, &SecretKey::from_byte_array(*secret).unwrap());
    let (public_key, _) = key_pair.x_only_public_key();
    (key_pair, public_key)
}

/// Whether libsecp256k1 accepts the BIP-340 signature on the message under the x-only key.
fn libsecp256k1_verifies(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    XOnlyPublicKey::from_byte_array(*public_key).is_ok_and(|pk| {
        SECP256K1
            .verify_schnorr(
                &secp256k1::schnorr::Signature::from_byte_array(*signature),
                message,
                &pk,
            )
            .is_ok()
    })
}

/// Whether fastcrypto decodes the key and the signature and accepts the signature on the message.
fn fastcrypto_verifies(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    match (
        SchnorrPublicKey::from_byte_array(public_key),
        SchnorrSignature::from_byte_array(signature),
    ) {
        (Ok(pk), Ok(sig)) => pk.verify(message, &sig).is_ok(),
        _ => false,
    }
}

/// `count` values drawn from a proptest strategy.
pub(crate) fn samples<S: Strategy>(
    strategy: S,
    count: usize,
    runner: &mut TestRunner,
) -> Vec<S::Value> {
    (0..count)
        .map(|_| strategy.new_tree(runner).unwrap().current())
        .collect()
}

/// The number of values that satisfy the predicate.
pub(crate) fn count<T>(values: &[T], predicate: impl Fn(&T) -> bool) -> usize {
    values.iter().filter(|v| predicate(v)).count()
}

//
// Arithmetic tests
//

#[test]
fn test_arithmetic() {
    let g = ProjectivePoint::generator();
    let zero = ProjectivePoint::zero();
    let two = Scalar::from(2);
    let minus_one = from_k256_scalar(&minus_one());
    assert_eq!(g + g, g.double());
    assert_eq!(g + g, g * two);
    assert_eq!(g, (g + g) * (Scalar::generator() / two).unwrap());
    assert_eq!(g, ((g + g) / two).unwrap());

    // The identity, ±G and n - 1.
    assert_eq!(g * Scalar::zero(), zero);
    assert_eq!(g * Scalar::generator(), g);
    assert_eq!(g * minus_one, -g);
    assert_eq!(g + -g, zero);
    assert_eq!(g - g, zero);
    assert_eq!(zero + g, g);
    assert_eq!(zero.double(), zero);
    assert_eq!(-zero, zero);
    assert_eq!(zero * two, zero);
    assert!(zero.is_zero() && !g.is_zero());
    assert_eq!(ProjectivePoint::default(), zero);
    assert_eq!(Scalar::default(), Scalar::zero());
    assert_eq!(Scalar::generator(), Scalar::from(1));
    assert_eq!(minus_one + Scalar::generator(), Scalar::zero());
    assert_eq!(minus_one * minus_one, Scalar::generator());
    assert_eq!(minus_one.inverse().unwrap(), minus_one);

    // Equality compares points, not their projective coordinates.
    let h = g.double() + g - g.double();
    assert_ne!(h.0.z, g.0.z);
    assert_eq!(h, g);

    // Check that u128 is decoded correctly.
    let x: u128 = 2 << 66;
    let x_scalar = Scalar::from(x);
    let res = x_scalar / Scalar::from(8);
    assert_eq!(res.unwrap(), Scalar::from(2 << 63));
    assert_eq!(
        Scalar::from(u128::MAX).to_byte_array(),
        hex!("00000000000000000000000000000000ffffffffffffffffffffffffffffffff")
    );
}

#[test]
fn test_division_by_zero() {
    let g = ProjectivePoint::generator();
    assert_eq!(Scalar::zero().inverse(), Err(FastCryptoError::InvalidInput));
    assert_eq!(
        Scalar::generator() / Scalar::zero(),
        Err(FastCryptoError::InvalidInput)
    );
    assert_eq!(g / Scalar::zero(), Err(FastCryptoError::InvalidInput));
    assert_eq!(
        ProjectivePoint::zero() / Scalar::zero(),
        Err(FastCryptoError::InvalidInput)
    );
}

#[test]
fn test_from_bytes_mod_order() {
    // Big-endian of any length, reduced modulo n. The empty input is zero.
    let n = BigUint::from_bytes_be(&GROUP_ORDER);
    let mut rng = StdRng::seed_from_u64(0);
    for length in [0, 1, 31, 32, 33, 47, 48, 64, 100] {
        for fill in [None, Some(0x00), Some(0xff)] {
            let mut bytes = vec![0; length];
            match fill {
                None => rng.fill_bytes(&mut bytes),
                Some(byte) => bytes.fill(byte),
            }
            let expected = BigUint::from_bytes_be(&bytes) % &n;
            let scalar = Scalar::from_bytes_mod_order(&bytes);
            assert_eq!(BigUint::from_bytes_be(&scalar.to_byte_array()), expected);
            if length >= 48 {
                assert_eq!(
                    Scalar::fiat_shamir_reduction_to_group_element(&bytes),
                    scalar
                );
            }
        }
    }
    assert_eq!(Scalar::from_bytes_mod_order(&GROUP_ORDER), Scalar::zero());
    assert_eq!(
        Scalar::from_bytes_mod_order(&add_small(&GROUP_ORDER, 1)),
        Scalar::generator()
    );
    assert_eq!(
        to_k256_scalar(&Scalar::from_bytes_mod_order(&[0xff; 32])),
        reduce(&[0xff; 32])
    );
}

#[test]
#[should_panic]
fn test_fiat_shamir_panics_on_short_input() {
    // At least 48 bytes are required to make the bias of the reduction negligible. Every caller
    // passes a hash output of fixed length.
    Scalar::fiat_shamir_reduction_to_group_element(&[0; 47]);
}

//
// Multi-scalar multiplication tests
//

#[test]
fn test_msm() {
    // Lengths around the window size changes of arkworks' msm, with the identity, ±G, repeated
    // points and edge-case scalars.
    let scalars = edge_scalars();
    let points = [k256::Scalar::ZERO, k256::Scalar::ONE, minus_one()]
        .into_iter()
        .chain(scalars.iter().copied())
        .map(|k| multiple_of_generator(&k))
        .collect::<Vec<_>>();
    for length in [1, 2, 3, 31, 32, 33] {
        let terms = (0..length)
            .map(|i| (scalars[i % scalars.len()], &points[(3 * i) % points.len()]))
            .collect::<Vec<_>>();
        let expected = terms
            .iter()
            .map(|(s, (_, p))| p * s)
            .sum::<k256::ProjectivePoint>();
        let scalars = terms
            .iter()
            .map(|(s, _)| from_k256_scalar(s))
            .collect::<Vec<_>>();
        let points = terms.iter().map(|(_, (p, _))| *p).collect::<Vec<_>>();
        let actual = ProjectivePoint::multi_scalar_mul(&scalars, &points).unwrap();
        assert_eq!(to_k256_point(&actual), expected);
        assert!(ProjectivePoint::multi_scalar_mul(&scalars[1..], &points).is_err());
        assert!(ProjectivePoint::multi_scalar_mul(&scalars, &points[1..]).is_err());
    }
}

#[test]
fn test_msm_edge_cases() {
    let g = ProjectivePoint::generator();
    let zero = ProjectivePoint::zero();
    let one = Scalar::generator();
    let msm = |scalars: &[Scalar], points: &[ProjectivePoint]| {
        ProjectivePoint::multi_scalar_mul(scalars, points).unwrap()
    };
    assert_eq!(msm(&[], &[]), zero);
    assert_eq!(msm(&[Scalar::zero()], &[g]), zero);
    assert_eq!(msm(&[one], &[zero]), zero);
    assert_eq!(msm(&[one], &[g]), g);
    assert_eq!(msm(&[-one, one], &[g, g]), zero);
    assert_eq!(msm(&[one, one], &[g, -g]), zero);
    assert_eq!(msm(&[one, one], &[g, g]), g * Scalar::from(2));
    assert_eq!(msm(&[-one], &[g]), -g);
    assert_eq!(
        msm(&[one, Scalar::from(5)], &[zero, g]),
        g * Scalar::from(5)
    );
    assert_eq!(
        ProjectivePoint::multi_scalar_mul(&[one], &[]),
        Err(FastCryptoError::InvalidInput)
    );
    assert_eq!(
        ProjectivePoint::multi_scalar_mul(&[], &[g]),
        Err(FastCryptoError::InvalidInput)
    );
}

//
// Serialization tests
//

#[test]
fn test_serde() {
    // Scalars are 32 big-endian bytes, and decoding accepts exactly the values below n.
    let n_minus_one = add_small(&GROUP_ORDER, -1);
    for bytes in [[0; 32], X_ONE, n_minus_one] {
        let scalar = Scalar::from_byte_array(&bytes).unwrap();
        assert_eq!(scalar.to_byte_array(), bytes);
        assert_eq!(bcs::to_bytes(&scalar).unwrap(), bytes);
        assert_eq!(bcs::from_bytes::<Scalar>(&bytes).unwrap(), scalar);
        let json = serde_json::to_string(&scalar).unwrap();
        assert_eq!(serde_json::from_str::<Scalar>(&json).unwrap(), scalar);
    }
    assert_eq!(
        to_k256_scalar(&Scalar::from_byte_array(&n_minus_one).unwrap()),
        minus_one()
    );
    for bytes in [GROUP_ORDER, add_small(&GROUP_ORDER, 1), [0xff; 32]] {
        assert_eq!(
            Scalar::from_byte_array(&bytes),
            Err(FastCryptoError::InvalidInput)
        );
        assert!(bcs::from_bytes::<Scalar>(&bytes).is_err());
    }
    assert!(bcs::from_bytes::<Scalar>(&[0; 31]).is_err());
    assert!(bcs::from_bytes::<Scalar>(&[0; 33]).is_err());
    assert!(serde_json::from_str::<Scalar>("\"AAAA\"").is_err());

    // Points round trip through bytes, BCS and JSON.
    let mut rng = StdRng::seed_from_u64(0);
    let scalar = Scalar::rand(&mut rng);
    for point in [
        ProjectivePoint::zero(),
        ProjectivePoint::generator() * scalar,
    ] {
        let bytes = point.to_byte_array();
        assert_eq!(ProjectivePoint::from_byte_array(&bytes).unwrap(), point);
        assert_eq!(bcs::to_bytes(&point).unwrap(), bytes);
        assert_eq!(bcs::from_bytes::<ProjectivePoint>(&bytes).unwrap(), point);
        let json = serde_json::to_string(&point).unwrap();
        assert_eq!(
            serde_json::from_str::<ProjectivePoint>(&json).unwrap(),
            point
        );
    }
    assert!(bcs::from_bytes::<ProjectivePoint>(&[0; 32]).is_err());
}

#[test]
fn test_regression() {
    let scalar = Scalar::from(7);
    assert_eq!(
        scalar.to_byte_array(),
        hex!("0000000000000000000000000000000000000000000000000000000000000007")
    );
    assert_eq!(
        serde_json::to_string(&scalar).unwrap(),
        "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc=\""
    );

    // 7 * G has a small y. The arkworks encoding is x little-endian and a flag byte.
    let point = ProjectivePoint::generator() * scalar;
    assert_eq!(
        point.to_byte_array(),
        hex!("bcf9c4caeddd2be99ce330037e9b413d0e7aeaf265f398a3eab45d6e64f0bd5c00")
    );
    assert_eq!(
        (-point).to_byte_array(),
        hex!("bcf9c4caeddd2be99ce330037e9b413d0e7aeaf265f398a3eab45d6e64f0bd5c80")
    );
    assert_eq!(
        serde_json::to_string(&point).unwrap(),
        "\"vPnEyu3dK+mc4zADfptBPQ566vJl85ij6rRdbmTwvVwA\""
    );

    // The SEC1 encoding of 7 * G: its y is even.
    assert_eq!(
        point.to_sec1_bytes().unwrap(),
        hex!("025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc")
    );
}

#[test]
fn test_canonical_encoding() {
    // Canonical encodings round trip, including points where y > (p - 1) / 2 and the identity.
    let mut rng = StdRng::seed_from_u64(0);
    let mut points = vec![ProjectivePoint::zero(), ProjectivePoint::generator()];
    points.extend((0..20).map(|_| ProjectivePoint::generator() * Scalar::rand(&mut rng)));
    for point in &points {
        let bytes = point.to_byte_array();
        assert_eq!(bytes, expected_encoding(&to_k256_point(point)));
        assert_eq!(ProjectivePoint::from_byte_array(&bytes).unwrap(), *point);
        assert_eq!(
            bcs::from_bytes::<ProjectivePoint>(&bcs::to_bytes(point).unwrap()).unwrap(),
            *point
        );
    }
    assert_eq!(ProjectivePoint::zero().to_byte_array(), IDENTITY_ENCODING);

    // Arkworks ignores the six lowest bits of the flag byte. They must be zero.
    let g = ProjectivePoint::generator().to_byte_array();
    for bits in 1..FLAG_IDENTITY {
        for sign in [0x00, FLAG_Y_IS_LARGE] {
            let mut bytes = g;
            bytes[32] = sign | bits;
            assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
            assert!(bcs::from_bytes::<ProjectivePoint>(&bytes).is_err());
        }
        let mut bytes = IDENTITY_ENCODING;
        bytes[32] |= bits;
        assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
    }

    // Arkworks ignores the x-coordinate if the infinity flag is set. It must be zero.
    for i in 0..32 {
        let mut bytes = IDENTITY_ENCODING;
        bytes[i] = 1;
        assert!(ProjectivePoint::from_byte_array(&bytes).is_err());
    }
    let mut bytes = g;
    bytes[32] = FLAG_IDENTITY;
    assert!(ProjectivePoint::from_byte_array(&bytes).is_err());

    // Both the infinity flag and the sign flag.
    bytes[32] = FLAG_IDENTITY | FLAG_Y_IS_LARGE;
    assert!(ProjectivePoint::from_byte_array(&bytes).is_err());

    // x >= p, p + 1 (an alias of x = 1, which is on the curve) and x not on the curve are
    // rejected with both flags. x = 1 and the largest x, p - 3, are accepted with both.
    for flag in [0x00, FLAG_Y_IS_LARGE] {
        for x in [
            FIELD_MODULUS,
            FIELD_MODULUS_PLUS_ONE,
            X_NOT_ON_CURVE,
            [0xff; 32],
        ] {
            assert!(ProjectivePoint::from_byte_array(&arkworks_bytes(&x, flag)).is_err());
        }
        for x in [X_ONE, LARGEST_X] {
            let bytes = arkworks_bytes(&x, flag);
            let point = ProjectivePoint::from_byte_array(&bytes).unwrap();
            assert_eq!(point.x_as_be_bytes().unwrap(), x);
            assert_eq!(to_k256_point(&point), decode_with_k256(&bytes).unwrap());
        }
    }
}

#[test]
fn test_sec1_encoding() {
    // Matches libsecp256k1 on random points, which have both even and odd y-coordinates.
    let mut rng = StdRng::seed_from_u64(0);
    let mut odd = 0;
    for _ in 0..20 {
        let scalar = Scalar::rand(&mut rng);
        let point = ProjectivePoint::generator() * scalar;
        let sk = SecretKey::from_byte_array(scalar.to_byte_array()).unwrap();
        let expected = PublicKey::from_secret_key(SECP256K1, &sk).serialize();

        let bytes = point.to_sec1_bytes().unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(ProjectivePoint::from_sec1_bytes(&bytes).unwrap(), point);
        assert_eq!(bytes[1..], point.x_as_be_bytes().unwrap());
        assert_eq!(bytes[0] == 0x03, !point.has_even_y().unwrap());
        odd += (bytes[0] == 0x03) as usize;
    }
    assert!(odd > 0 && odd < 20);

    // The identity has no 33-byte SEC1 encoding.
    assert_eq!(
        ProjectivePoint::zero().to_sec1_bytes(),
        Err(FastCryptoError::InvalidInput)
    );

    // Only the compressed tags are accepted.
    let g = ProjectivePoint::generator().to_sec1_bytes().unwrap();
    for tag in [0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
        let mut bytes = g;
        bytes[0] = tag;
        assert!(ProjectivePoint::from_sec1_bytes(&bytes).is_err());
    }

    // x >= p, p + 1 (an alias of x = 1) and x not on the curve are rejected with both tags, as by
    // libsecp256k1. x = 1 and the largest x, p - 3, are accepted.
    for tag in [0x02, 0x03] {
        for x in [
            FIELD_MODULUS,
            FIELD_MODULUS_PLUS_ONE,
            X_NOT_ON_CURVE,
            [0xff; 32],
        ] {
            let bytes = sec1_bytes(tag, &x);
            assert!(ProjectivePoint::from_sec1_bytes(&bytes).is_err());
            assert!(PublicKey::from_byte_array_compressed(bytes).is_err());
        }
        for x in [X_ONE, LARGEST_X] {
            let bytes = sec1_bytes(tag, &x);
            let point = ProjectivePoint::from_sec1_bytes(&bytes).unwrap();
            assert_eq!(point.to_sec1_bytes().unwrap(), bytes);
            assert_eq!(
                PublicKey::from_byte_array_compressed(bytes)
                    .unwrap()
                    .serialize(),
                bytes
            );
        }
    }
}

#[test]
fn test_x_only_encoding() {
    // Lifting x gives the point with an even y. The identity has no x-coordinate.
    let g = ProjectivePoint::generator();
    let odd_y = g * Scalar::from(13);
    assert!(!odd_y.has_even_y().unwrap());
    let x = odd_y.x_as_be_bytes().unwrap();
    assert_eq!(
        ProjectivePoint::with_even_y_from_x_be_bytes(&x).unwrap(),
        -odd_y
    );
    assert_eq!(
        ProjectivePoint::zero().x_as_be_bytes(),
        Err(FastCryptoError::InvalidInput)
    );
    assert_eq!(
        ProjectivePoint::zero().has_even_y(),
        Err(FastCryptoError::InvalidInput)
    );

    // The same accepted set as libsecp256k1.
    for x in [X_ONE, LARGEST_X] {
        let point = ProjectivePoint::with_even_y_from_x_be_bytes(&x).unwrap();
        assert!(point.has_even_y().unwrap());
        assert_eq!(point.x_as_be_bytes().unwrap(), x);
        assert_eq!(XOnlyPublicKey::from_byte_array(x).unwrap().serialize(), x);
    }
    for x in [
        [0; 32],
        X_NOT_ON_CURVE,
        FIELD_MODULUS,
        FIELD_MODULUS_PLUS_ONE,
        [0xff; 32],
    ] {
        assert_eq!(
            ProjectivePoint::with_even_y_from_x_be_bytes(&x),
            Err(FastCryptoError::InvalidInput)
        );
        assert!(XOnlyPublicKey::from_byte_array(x).is_err());
    }
}

//
// BIP-340 tests
//

#[test]
fn test_generator() {
    let x_bytes = hex!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

    // Test that the generator is aligned with the specs.
    assert_eq!(
        x_bytes,
        ProjectivePoint::generator().x_as_be_bytes().unwrap()
    );
    assert!(ProjectivePoint::generator().has_even_y().unwrap());
    assert_eq!(
        ProjectivePoint::with_even_y_from_x_be_bytes(&x_bytes).unwrap(),
        ProjectivePoint::generator()
    );
}

#[test]
fn test_bip340_test_vectors() {
    // https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv, also in k256 0.13
    // src/schnorr.rs. Vectors with a secret key are signing vectors.
    struct TestVector {
        index: usize,
        secret_key: Option<&'static str>,
        public_key: &'static str,
        aux_rand: Option<&'static str>,
        message: &'static str,
        signature: &'static str,
        valid: bool,
    }
    let test_vectors = [
        TestVector {
            index: 0,
            secret_key: Some("0000000000000000000000000000000000000000000000000000000000000003"),
            public_key: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            aux_rand: Some("0000000000000000000000000000000000000000000000000000000000000000"),
            message: "0000000000000000000000000000000000000000000000000000000000000000",
            signature: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            valid: true,
        },
        TestVector {
            index: 1,
            secret_key: Some("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"),
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: Some("0000000000000000000000000000000000000000000000000000000000000001"),
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            valid: true,
        },
        TestVector {
            index: 2,
            secret_key: Some("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"),
            public_key: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            aux_rand: Some("C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"),
            message: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            signature: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            valid: true,
        },
        // Fails if the message is reduced modulo p or n.
        TestVector {
            index: 3,
            secret_key: Some("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"),
            public_key: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            aux_rand: Some("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            message: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            signature: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            valid: true,
        },
        TestVector {
            index: 4,
            secret_key: None,
            public_key: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
            aux_rand: None,
            message: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
            signature: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
            valid: true,
        },
        // The public key is not on the curve.
        TestVector {
            index: 5,
            secret_key: None,
            public_key: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
        },
        // has_even_y(R) is false.
        TestVector {
            index: 6,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
            valid: false,
        },
        // Negated message.
        TestVector {
            index: 7,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
            valid: false,
        },
        // Negated s.
        TestVector {
            index: 8,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
            valid: false,
        },
        // sG - eP is the identity, with r = 0, the x-coordinate of the identity in some
        // implementations. x = 0 is not on the curve.
        TestVector {
            index: 9,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
            valid: false,
        },
        // sG - eP is the identity, with r = 1, the x-coordinate of the identity in other
        // implementations. x = 1 is on the curve.
        TestVector {
            index: 10,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
            valid: false,
        },
        // r is not the x-coordinate of a point on the curve.
        TestVector {
            index: 11,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
        },
        // r = p.
        TestVector {
            index: 12,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
        },
        // s = n.
        TestVector {
            index: 13,
            secret_key: None,
            public_key: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            valid: false,
        },
        // The public key is p + 1, x = 1 not reduced modulo p.
        TestVector {
            index: 14,
            secret_key: None,
            public_key: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            aux_rand: None,
            message: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            signature: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
        },
        // Messages of 0, 1, 17 and 100 bytes.
        TestVector {
            index: 15,
            secret_key: Some("0340034003400340034003400340034003400340034003400340034003400340"),
            public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux_rand: Some("0000000000000000000000000000000000000000000000000000000000000000"),
            message: "",
            signature: "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
            valid: true,
        },
        TestVector {
            index: 16,
            secret_key: Some("0340034003400340034003400340034003400340034003400340034003400340"),
            public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux_rand: Some("0000000000000000000000000000000000000000000000000000000000000000"),
            message: "11",
            signature: "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
            valid: true,
        },
        TestVector {
            index: 17,
            secret_key: Some("0340034003400340034003400340034003400340034003400340034003400340"),
            public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux_rand: Some("0000000000000000000000000000000000000000000000000000000000000000"),
            message: "0102030405060708090A0B0C0D0E0F1011",
            signature: "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
            valid: true,
        },
        TestVector {
            index: 18,
            secret_key: Some("0340034003400340034003400340034003400340034003400340034003400340"),
            public_key: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux_rand: Some("0000000000000000000000000000000000000000000000000000000000000000"),
            message: "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
            signature: "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
            valid: true,
        },
    ];
    // fastcrypto rejects these when decoding the public key or the signature; BIP-340 only
    // requires r < p and s < n when decoding, so the others fail at verification.
    const REJECTED_WHEN_DECODING: [usize; 6] = [5, 9, 11, 12, 13, 14];

    for v in test_vectors {
        let public_key: [u8; 32] = hex::decode(v.public_key).unwrap().try_into().unwrap();
        let message = hex::decode(v.message).unwrap();
        let signature: [u8; 64] = hex::decode(v.signature).unwrap().try_into().unwrap();
        assert_eq!(
            fastcrypto_verifies(&public_key, &message, &signature),
            v.valid,
            "vector {}",
            v.index
        );
        assert_eq!(
            libsecp256k1_verifies(&public_key, &message, &signature),
            v.valid
        );
        match (
            SchnorrPublicKey::from_byte_array(&public_key),
            SchnorrSignature::from_byte_array(&signature),
        ) {
            (Ok(pk), Ok(sig)) => {
                assert!(!REJECTED_WHEN_DECODING.contains(&v.index));
                // Vector 10 fails because R is the identity.
                let expected = if v.valid {
                    Ok(())
                } else {
                    Err(FastCryptoError::InvalidSignature)
                };
                assert_eq!(pk.verify(&message, &sig), expected);
            }
            _ => assert!(REJECTED_WHEN_DECODING.contains(&v.index)),
        }

        if let (Some(secret_key), Some(aux_rand)) = (v.secret_key, v.aux_rand) {
            let secret_key: [u8; 32] = hex::decode(secret_key).unwrap().try_into().unwrap();
            let sk = SchnorrPrivateKey::from_byte_array(&secret_key).unwrap();
            assert_eq!(SchnorrPublicKey::from(&sk).to_byte_array(), public_key);
            let aux_rand = hex::decode(aux_rand).unwrap();
            assert_eq!(
                sk.sign(&message, &aux_rand).unwrap().to_byte_array(),
                signature,
                "vector {}",
                v.index
            );
        }
    }
}

#[test]
fn test_schnorr_keys() {
    let g = ProjectivePoint::generator();
    let n_minus_one = add_small(&GROUP_ORDER, -1);

    // Private keys are non-zero scalars below n. A key d whose public key d * G has an odd y is
    // replaced by n - d, so (n - 1) * G = -G gives the key 1.
    for bytes in [[0; 32], GROUP_ORDER, [0xff; 32]] {
        assert!(SchnorrPrivateKey::from_byte_array(&bytes).is_err());
        assert!(bcs::from_bytes::<SchnorrPrivateKey>(&bytes).is_err());
    }
    assert!(SchnorrPrivateKey::try_from(Scalar::zero()).is_err());
    let sk = SchnorrPrivateKey::from_byte_array(&n_minus_one).unwrap();
    assert_eq!(sk.to_byte_array(), X_ONE);
    assert_eq!(*SchnorrPublicKey::from(&sk).as_point(), g);
    let sk = SchnorrPrivateKey::from_byte_array(&X_ONE).unwrap();
    assert_eq!(sk.to_byte_array(), X_ONE);
    assert_eq!(bcs::to_bytes(&sk).unwrap(), X_ONE);
    assert_eq!(
        bcs::from_bytes::<SchnorrPrivateKey>(&n_minus_one)
            .unwrap()
            .to_byte_array(),
        X_ONE
    );

    // A public key from a point is the point with an even y, so P and -P give the same key.
    let odd_y = g * Scalar::from(13);
    for point in [odd_y, -odd_y] {
        let pk = SchnorrPublicKey::try_from(&point).unwrap();
        assert_eq!(*pk.as_point(), -odd_y);
        assert_eq!(pk.to_byte_array(), odd_y.x_as_be_bytes().unwrap());
    }
    assert!(SchnorrPublicKey::try_from(&ProjectivePoint::zero()).is_err());

    // Public keys are x-only and round trip through BCS and JSON.
    let pk = SchnorrPublicKey::try_from(&odd_y).unwrap();
    let bytes = pk.to_byte_array();
    assert_eq!(bcs::to_bytes(&pk).unwrap(), bytes);
    let decoded = bcs::from_bytes::<SchnorrPublicKey>(&bytes).unwrap();
    assert_eq!(decoded.as_point(), pk.as_point());
    let json = serde_json::to_string(&pk).unwrap();
    let decoded = serde_json::from_str::<SchnorrPublicKey>(&json).unwrap();
    assert_eq!(decoded.as_point(), pk.as_point());
    for bytes in [FIELD_MODULUS_PLUS_ONE, X_NOT_ON_CURVE] {
        assert!(SchnorrPublicKey::from_byte_array(&bytes).is_err());
        assert!(bcs::from_bytes::<SchnorrPublicKey>(&bytes).is_err());
    }
}

#[test]
fn test_schnorr_signature_encoding() {
    let sk = SchnorrPrivateKey::from_byte_array(&X_ONE).unwrap();
    let pk = SchnorrPublicKey::from(&sk);
    let signature = sk.sign(b"message", &[0; 32]).unwrap();
    let bytes = signature.to_byte_array();

    // r is the x-coordinate of R and s is a scalar, both big-endian.
    let r = ProjectivePoint::with_even_y_from_x_be_bytes(&signature.r).unwrap();
    assert_eq!(bytes[..32], r.x_as_be_bytes().unwrap());
    assert_eq!(bytes[32..], signature.s.to_byte_array());
    assert_eq!(bcs::to_bytes(&signature).unwrap(), bytes);
    let json = serde_json::to_string(&signature).unwrap();
    for decoded in [
        SchnorrSignature::from_byte_array(&bytes).unwrap(),
        bcs::from_bytes::<SchnorrSignature>(&bytes).unwrap(),
        serde_json::from_str::<SchnorrSignature>(&json).unwrap(),
    ] {
        assert_eq!(decoded.to_byte_array(), bytes);
        assert!(pk.verify(b"message", &decoded).is_ok());
    }
    assert_eq!(
        pk.verify(b"other message", &signature),
        Err(FastCryptoError::InvalidSignature)
    );

    // Decoding rejects s = 0 and s >= n, and an r that is not the x-coordinate of a point on the
    // curve, including x >= p.
    let with = |r: &[u8; 32], s: &[u8; 32]| {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(r);
        bytes[32..].copy_from_slice(s);
        bytes
    };
    for s in [[0; 32], GROUP_ORDER, [0xff; 32]] {
        assert!(SchnorrSignature::from_byte_array(&with(&signature.r, &s)).is_err());
    }
    for r in [
        [0; 32],
        X_NOT_ON_CURVE,
        FIELD_MODULUS,
        FIELD_MODULUS_PLUS_ONE,
    ] {
        let bytes = with(&r, &signature.s.to_byte_array());
        assert!(SchnorrSignature::from_byte_array(&bytes).is_err());
        assert!(bcs::from_bytes::<SchnorrSignature>(&bytes).is_err());
    }
    assert!(SchnorrSignature::from_byte_array(&with(&LARGEST_X, &X_ONE)).is_ok());

    // A signature built from a point and a scalar takes the x-coordinate of the point. It may have
    // s = 0, and then its bytes do not decode.
    assert!(SchnorrSignature::try_from((ProjectivePoint::zero(), Scalar::generator())).is_err());
    let signature = SchnorrSignature::try_from((-r, signature.s)).unwrap();
    assert_eq!(signature.to_byte_array(), bytes);
    let zero_s = SchnorrSignature::try_from((r, Scalar::zero())).unwrap();
    assert!(SchnorrSignature::from_byte_array(&zero_s.to_byte_array()).is_err());
    assert_eq!(
        pk.verify(b"message", &zero_s),
        Err(FastCryptoError::InvalidSignature)
    );
}

#[test]
fn test_bitcoin_alignment_sign() {
    // Signatures are those of libsecp256k1, for messages of any length. Auxiliary data of another
    // length than 32 bytes, which BIP-340 does not allow, is hashed like 32 bytes.
    let mut rng = StdRng::seed_from_u64(0);
    for message_length in [0, 1, 32, 100] {
        let scalar = Scalar::rand(&mut rng);
        let sk = SchnorrPrivateKey::try_from(scalar).unwrap();
        let (key_pair, public_key) = libsecp256k1_key_pair(&scalar.to_byte_array());
        assert_eq!(
            SchnorrPublicKey::from(&sk).to_byte_array(),
            public_key.serialize()
        );
        let mut message = vec![0; message_length];
        rng.fill_bytes(&mut message);
        let mut aux_rand = [0; 32];
        rng.fill_bytes(&mut aux_rand);

        let signature = sk.sign(&message, &aux_rand).unwrap();
        let expected = SECP256K1.sign_schnorr_with_aux_rand(&message, &key_pair, &aux_rand);
        assert_eq!(signature.to_byte_array(), expected.to_byte_array());
        assert!(libsecp256k1_verifies(
            &public_key.serialize(),
            &message,
            &signature.to_byte_array()
        ));
        assert!(!libsecp256k1_verifies(
            &public_key.serialize(),
            b"other message",
            &signature.to_byte_array()
        ));

        for aux_rand in [&aux_rand[..31], &[]] {
            let signature = sk.sign(&message, aux_rand).unwrap();
            assert_ne!(signature.to_byte_array(), expected.to_byte_array());
            assert!(libsecp256k1_verifies(
                &public_key.serialize(),
                &message,
                &signature.to_byte_array()
            ));
        }
    }
}

#[test]
fn test_bitcoin_alignment_verify() {
    // Signatures by libsecp256k1 verify, also for keys whose y is odd.
    let mut rng = StdRng::seed_from_u64(0);
    let mut odd = 0;
    for message_length in [0, 1, 32, 100] {
        let scalar = Scalar::rand(&mut rng);
        odd += !(ProjectivePoint::generator() * scalar)
            .has_even_y()
            .unwrap() as usize;
        let (key_pair, public_key) = libsecp256k1_key_pair(&scalar.to_byte_array());
        let mut message = vec![0; message_length];
        rng.fill_bytes(&mut message);
        let signature = SECP256K1
            .sign_schnorr_no_aux_rand(&message, &key_pair)
            .to_byte_array();

        let pk = SchnorrPublicKey::from(&SchnorrPrivateKey::try_from(scalar).unwrap());
        assert_eq!(pk.to_byte_array(), public_key.serialize());
        let signature = SchnorrSignature::from_byte_array(&signature).unwrap();
        assert!(pk.verify(&message, &signature).is_ok());
        assert!(pk.verify(b"other message", &signature).is_err());
    }
    assert!(odd > 0);
}

//
// Test vectors
//

#[test]
fn test_vectors_multiples_of_generator() {
    // From k256's test-vectors feature: k * G for k = 1..=20 and for larger k.
    let k_and_coordinates = ADD_TEST_VECTORS
        .iter()
        .enumerate()
        .map(|(i, (x, y))| (k256::Scalar::from(i as u64 + 1), x, y))
        .chain(
            MUL_TEST_VECTORS
                .iter()
                .map(|(k, x, y)| (k256::Scalar::from_repr((*k).into()).unwrap(), x, y)),
        );
    let g = ProjectivePoint::generator();
    let mut sum = ProjectivePoint::zero();
    for (i, (k, x, y)) in k_and_coordinates.enumerate() {
        let k = from_k256_scalar(&k);
        let expected = Some((*x, *y));
        assert_eq!(affine_coordinates(&(g * k)), expected);
        assert_eq!(
            affine_coordinates(&ProjectivePoint::multi_scalar_mul(&[k], &[g]).unwrap()),
            expected
        );
        if i < ADD_TEST_VECTORS.len() {
            sum += g;
            assert_eq!(affine_coordinates(&sum), expected);
        }
    }
}

//
// Proptests
//

/// Scalars, biased towards edge cases: 0, ±1, [edge_scalars], 2^k and 2^k - 1 for every k,
/// scalars below 2^64 and arbitrary scalars.
fn arb_scalar() -> impl Strategy<Value = k256::Scalar> {
    prop_oneof![
        prop_oneof![
            Just(k256::Scalar::ZERO),
            Just(k256::Scalar::ONE),
            Just(minus_one())
        ],
        prop::sample::select(edge_scalars()),
        (0usize..=256).prop_map(two_to_the),
        (0usize..=256).prop_map(|k| two_to_the(k) - k256::Scalar::ONE),
        any::<u64>().prop_map(k256::Scalar::from),
        any::<[u8; 32]>().prop_map(|bytes| reduce(&bytes)),
    ]
}

/// Discrete logarithms to the generator: the identity and ±G often, and multiples by
/// [arb_scalar].
fn arb_point_log() -> impl Strategy<Value = k256::Scalar> {
    prop_oneof![
        1 => Just(k256::Scalar::ZERO),
        1 => prop_oneof![Just(k256::Scalar::ONE), Just(minus_one())],
        4 => arb_scalar(),
    ]
}

/// 32-byte big-endian integers: arbitrary ones, those near 0, n, p and 2^256, those that start
/// like n or p (just below or above them), x-coordinates on the curve with their aliases x + p,
/// and encodings of [arb_scalar] and of x-coordinates of [arb_point_log].
fn arb_big_endian_bytes() -> impl Strategy<Value = [u8; 32]> {
    let near = prop_oneof![
        Just([0; 32]),
        Just(GROUP_ORDER),
        Just(FIELD_MODULUS),
        Just(LARGEST_X),
        Just([0xff; 32])
    ];
    let prefix_of = prop_oneof![Just(GROUP_ORDER), Just(FIELD_MODULUS)];
    prop_oneof![
        any::<[u8; 32]>(),
        (near, -3i64..=3).prop_map(|(bytes, delta)| add_small(&bytes, delta)),
        (prefix_of, 0..=32usize, any::<[u8; 32]>()).prop_map(|(start, prefix, mut bytes)| {
            bytes[..prefix].copy_from_slice(&start[..prefix]);
            bytes
        }),
        (
            prop_oneof![Just(X_ONE), Just(X_NOT_ON_CURVE)],
            any::<bool>()
        )
            .prop_map(|(x, plus_p)| match plus_p {
                true => add_small(&FIELD_MODULUS, i64::from(x[31])),
                false => x,
            }),
        arb_scalar().prop_map(|scalar| scalar.to_bytes().into()),
        arb_point_log().prop_map(|k| {
            let encoded = (k256::ProjectivePoint::GENERATOR * k)
                .to_affine()
                .to_encoded_point(true);
            encoded.x().map(|x| (*x).into()).unwrap_or([0; 32])
        }),
    ]
}

/// 33-byte arkworks encodings: canonical encodings of [arb_point_log] and x-coordinates from
/// [arb_big_endian_bytes], with any of the four high flag combinations or an arbitrary flag
/// byte.
fn arb_point_bytes() -> impl Strategy<Value = [u8; POINT_SIZE_IN_BYTES]> {
    let flag = prop_oneof![
        Just(0x00),
        Just(FLAG_Y_IS_LARGE),
        Just(FLAG_IDENTITY),
        Just(FLAG_IDENTITY | FLAG_Y_IS_LARGE),
        any::<u8>(),
    ];
    prop_oneof![
        arb_point_log().prop_map(|k| expected_encoding(&(k256::ProjectivePoint::GENERATOR * k))),
        (arb_big_endian_bytes(), flag).prop_map(|(x, flag)| arkworks_bytes(&x, flag)),
    ]
}

/// A change to an honest BIP-340 signature, public key or message.
#[derive(Debug, Clone)]
enum Bip340Mutation {
    None,
    FlipBit(usize),
    R([u8; 32]),
    S([u8; 32]),
    PublicKey([u8; 32]),
    Message(Vec<u8>),
    NegateS,
    SPlusOrder,
}

fn arb_bip340_mutation() -> impl Strategy<Value = Bip340Mutation> {
    prop_oneof![
        Just(Bip340Mutation::None),
        (0..512usize).prop_map(Bip340Mutation::FlipBit),
        arb_big_endian_bytes().prop_map(Bip340Mutation::R),
        arb_big_endian_bytes().prop_map(Bip340Mutation::S),
        arb_big_endian_bytes().prop_map(Bip340Mutation::PublicKey),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Bip340Mutation::Message),
        Just(Bip340Mutation::NegateS),
        Just(Bip340Mutation::SPlusOrder),
    ]
}

/// An honest BIP-340 signature by a non-zero secret key from [arb_scalar] on a message of 0 to 99
/// bytes, then changed by [arb_bip340_mutation]: (public key, message, signature).
fn arb_bip340_input() -> impl Strategy<Value = ([u8; 32], Vec<u8>, [u8; 64])> {
    (
        // The zero key is replaced by 1.
        arb_scalar().prop_map(|s| {
            if bool::from(s.is_zero()) {
                k256::Scalar::ONE
            } else {
                s
            }
        }),
        prop::collection::vec(any::<u8>(), 0..100),
        any::<[u8; 32]>(),
        arb_bip340_mutation(),
    )
        .prop_map(|(secret, mut message, aux_rand, mutation)| {
            let sk = SchnorrPrivateKey::try_from(from_k256_scalar(&secret)).unwrap();
            let mut public_key = SchnorrPublicKey::from(&sk).to_byte_array();
            let mut signature = sk.sign(&message, &aux_rand).unwrap().to_byte_array();
            match mutation {
                Bip340Mutation::None => {}
                Bip340Mutation::FlipBit(bit) => signature[bit / 8] ^= 1 << (bit % 8),
                Bip340Mutation::R(r) => signature[..32].copy_from_slice(&r),
                Bip340Mutation::S(s) => signature[32..].copy_from_slice(&s),
                Bip340Mutation::PublicKey(pk) => public_key = pk,
                Bip340Mutation::Message(m) => message = m,
                Bip340Mutation::NegateS => {
                    let s = Scalar::from_byte_array(&signature[32..].try_into().unwrap()).unwrap();
                    signature[32..].copy_from_slice(&(-s).to_byte_array());
                }
                Bip340Mutation::SPlusOrder => {
                    // s + n, if it fits in 32 bytes.
                    let sum = BigUint::from_bytes_be(&signature[32..])
                        + BigUint::from_bytes_be(&GROUP_ORDER);
                    let sum = sum.to_bytes_be();
                    if sum.len() == 32 {
                        signature[32..].copy_from_slice(&sum);
                    }
                }
            }
            (public_key, message, signature)
        })
}

proptest! {
    #[test]
    fn test_decode_adversarial_scalars(bytes in arb_big_endian_bytes()) {
        // Decoding accepts exactly the big-endian encodings of the values below n, the same set as
        // k256, and BCS agrees. Private keys are the non-zero ones.
        let expected = Option::<k256::Scalar>::from(k256::Scalar::from_repr(bytes.into()));
        let decoded = Scalar::from_byte_array(&bytes);
        prop_assert_eq!(decoded.is_ok(), expected.is_some());
        prop_assert_eq!(bcs::from_bytes::<Scalar>(&bytes).ok(), decoded.clone().ok());
        prop_assert_eq!(to_k256_scalar(&Scalar::from_bytes_mod_order(&bytes)), reduce(&bytes));
        if let (Ok(scalar), Some(expected)) = (decoded, expected) {
            prop_assert_eq!(to_k256_scalar(&scalar), expected);
            prop_assert_eq!(scalar.to_byte_array(), bytes);
        }
        let sk = SchnorrPrivateKey::from_byte_array(&bytes);
        prop_assert_eq!(sk.is_ok(), SecretKey::from_byte_array(bytes).is_ok());
        if let Ok(sk) = sk {
            prop_assert_eq!(
                SchnorrPublicKey::from(&sk).to_byte_array(),
                libsecp256k1_key_pair(&bytes).1.serialize()
            );
        }
    }

    #[test]
    fn test_decode_adversarial_points(bytes in arb_point_bytes()) {
        // The arkworks encoding: exactly the canonical encodings decode, to the same point as
        // k256 finds, and BCS agrees.
        let decoded = ProjectivePoint::from_byte_array(&bytes);
        let expected = decode_with_k256(&bytes);
        prop_assert_eq!(decoded.is_ok(), expected.is_some());
        prop_assert_eq!(bcs::from_bytes::<ProjectivePoint>(&bytes).ok(), decoded.clone().ok());
        if let (Ok(point), Some(expected)) = (decoded, expected) {
            prop_assert_eq!(to_k256_point(&point), expected);
            prop_assert_eq!(point.to_byte_array(), bytes);
        }
    }

    #[test]
    fn test_decode_adversarial_x_coordinates(
        x in arb_big_endian_bytes(),
        tag in prop_oneof![Just(0x02u8), Just(0x03), any::<u8>()],
    ) {
        // SEC1 and x-only encodings accept the same sets as libsecp256k1, and the x-only point is
        // the SEC1 point with tag 0x02.
        let bytes = sec1_bytes(tag, &x);
        let decoded = ProjectivePoint::from_sec1_bytes(&bytes);
        let expected = PublicKey::from_byte_array_compressed(bytes);
        prop_assert_eq!(decoded.is_ok(), expected.is_ok());
        if let Ok(point) = decoded {
            prop_assert_eq!(point.to_sec1_bytes().unwrap(), bytes);
        }

        let lifted = ProjectivePoint::with_even_y_from_x_be_bytes(&x);
        prop_assert_eq!(lifted.is_ok(), XOnlyPublicKey::from_byte_array(x).is_ok());
        prop_assert_eq!(
            lifted.clone().ok(),
            ProjectivePoint::from_sec1_bytes(&sec1_bytes(0x02, &x)).ok()
        );
        let pk = SchnorrPublicKey::from_byte_array(&x);
        prop_assert_eq!(pk.as_ref().ok().map(|pk| *pk.as_point()), lifted.ok());
        if let Ok(pk) = pk {
            prop_assert_eq!(pk.to_byte_array(), x);
        }
    }

    #[test]
    fn test_scalar_arithmetic(a in arb_scalar(), b in arb_scalar()) {
        let (x, y) = (from_k256_scalar(&a), from_k256_scalar(&b));
        prop_assert_eq!(to_k256_scalar(&(x + y)), a + b);
        prop_assert_eq!(to_k256_scalar(&(x - y)), a - b);
        prop_assert_eq!(to_k256_scalar(&(x * y)), a * b);
        prop_assert_eq!(to_k256_scalar(&-x), -a);
        let inverse = Option::<k256::Scalar>::from(b.invert());
        prop_assert_eq!(y.inverse().ok().map(|s| to_k256_scalar(&s)), inverse);
        prop_assert_eq!((x / y).ok().map(|s| to_k256_scalar(&s)), inverse.map(|i| a * i));
    }

    #[test]
    fn test_group_law(p in arb_point_log(), q in arb_point_log(), s in arb_scalar()) {
        let (x, expected_x) = multiple_of_generator(&p);
        let (y, expected_y) = multiple_of_generator(&q);
        prop_assert_eq!(to_k256_point(&x), expected_x);
        prop_assert_eq!(to_k256_point(&(x + y)), expected_x + expected_y);
        prop_assert_eq!(to_k256_point(&(x - y)), expected_x - expected_y);
        prop_assert_eq!(to_k256_point(&-x), -expected_x);
        prop_assert_eq!(to_k256_point(&x.double()), expected_x.double());
        prop_assert_eq!(to_k256_point(&(x * from_k256_scalar(&s))), expected_x * s);
        // Division fails exactly for s = 0.
        let quotient = (x / from_k256_scalar(&s)).ok().map(|q| to_k256_point(&q));
        let inverse = Option::<k256::Scalar>::from(s.invert());
        prop_assert_eq!(quotient, inverse.map(|i| expected_x * i));
        prop_assert_eq!(x == y, expected_x == expected_y);

        // The encodings agree with k256's coordinates.
        prop_assert_eq!(x.to_byte_array(), expected_encoding(&expected_x));
        let sec1 = expected_x.to_affine().to_encoded_point(true);
        match sec1.x() {
            None => {
                prop_assert!(x.to_sec1_bytes().is_err());
                prop_assert!(x.x_as_be_bytes().is_err());
                prop_assert!(x.has_even_y().is_err());
            }
            Some(expected) => {
                prop_assert_eq!(&x.to_sec1_bytes().unwrap()[..], sec1.as_bytes());
                prop_assert_eq!(&x.x_as_be_bytes().unwrap()[..], &expected[..]);
                prop_assert_eq!(x.has_even_y().unwrap(), sec1.as_bytes()[0] == 0x02);
            }
        }
    }
}

proptest! {
    // Each case does several 256-bit scalar multiplications.
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn test_multi_scalar_mul(terms in prop::collection::vec((arb_scalar(), arb_point_log()), 0..8)) {
        let expected = terms
            .iter()
            .map(|(s, k)| k256::ProjectivePoint::GENERATOR * k * s)
            .sum::<k256::ProjectivePoint>();
        let scalars = terms.iter().map(|(s, _)| from_k256_scalar(s)).collect::<Vec<_>>();
        let points = terms
            .iter()
            .map(|(_, k)| multiple_of_generator(k).0)
            .collect::<Vec<_>>();
        let actual = ProjectivePoint::multi_scalar_mul(&scalars, &points).unwrap();
        prop_assert_eq!(to_k256_point(&actual), expected);
    }

    #[test]
    fn test_bip340_verify_adversarial((public_key, message, signature) in arb_bip340_input()) {
        // decode + verify accepts exactly what libsecp256k1 accepts.
        prop_assert_eq!(
            fastcrypto_verifies(&public_key, &message, &signature),
            libsecp256k1_verifies(&public_key, &message, &signature)
        );
    }
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // The strategies hit the edge cases often enough for the 64 cases of the slower proptests.
    const SAMPLES: usize = 1000;
    let mut runner = TestRunner::deterministic();
    let scalars = samples(arb_scalar(), SAMPLES, &mut runner);
    let zero = count(&scalars, |s| bool::from(s.is_zero()));
    let plus_minus_one = count(&scalars, |s| *s == k256::Scalar::ONE || *s == minus_one());
    let logs = samples(arb_point_log(), SAMPLES, &mut runner);
    let identity = count(&logs, |k| bool::from(k.is_zero()));

    let bytes = samples(arb_big_endian_bytes(), SAMPLES, &mut runner);
    let decoded_scalar = count(&bytes, |b| Scalar::from_byte_array(b).is_ok());
    let near_order = count(&bytes, |b| {
        (-3..=3).any(|delta| *b == add_small(&GROUP_ORDER, delta))
    });
    let on_curve = count(&bytes, |x| {
        ProjectivePoint::with_even_y_from_x_be_bytes(x).is_ok()
    });
    let x_at_least_p = count(&bytes, |x| *x >= FIELD_MODULUS);

    let point_bytes = samples(arb_point_bytes(), SAMPLES, &mut runner);
    let decoded_point = count(&point_bytes, |b| {
        ProjectivePoint::from_byte_array(b).is_ok()
    });
    let decoded_identity = count(&point_bytes, |b| *b == IDENTITY_ENCODING);

    // Signing is slow in debug builds, so fewer signatures are sampled.
    let inputs = samples(arb_bip340_input(), SAMPLES / 10, &mut runner);
    let valid_signature = count(&inputs, |(pk, message, signature)| {
        fastcrypto_verifies(pk, message, signature)
    });

    println!(
        "scalars: zero {zero}, ±1 {plus_minus_one}; points: identity {identity}; 32 bytes: \
         scalar {decoded_scalar}, n - 3..n + 3 {near_order}, x on curve {on_curve}, \
         x >= p {x_at_least_p}; 33 bytes: point {decoded_point}, identity {decoded_identity}; \
         valid signatures {valid_signature} of {}",
        SAMPLES / 10
    );
    assert!(zero >= SAMPLES / 40, "{zero}");
    assert!(plus_minus_one >= SAMPLES / 20, "{plus_minus_one}");
    assert!(identity >= SAMPLES / 10, "{identity}");
    assert!(
        decoded_scalar > SAMPLES / 2 && decoded_scalar < SAMPLES * 9 / 10,
        "{decoded_scalar}"
    );
    assert!(near_order >= SAMPLES / 40, "{near_order}");
    assert!(
        on_curve > SAMPLES / 4 && on_curve < SAMPLES * 3 / 4,
        "{on_curve}"
    );
    assert!(x_at_least_p >= SAMPLES / 20, "{x_at_least_p}");
    assert!(
        decoded_point > SAMPLES / 4 && decoded_point < SAMPLES * 3 / 4,
        "{decoded_point}"
    );
    assert!(decoded_identity >= SAMPLES / 40, "{decoded_identity}");
    assert!(
        valid_signature > SAMPLES / 100 && valid_signature < SAMPLES / 20,
        "{valid_signature}"
    );
}
