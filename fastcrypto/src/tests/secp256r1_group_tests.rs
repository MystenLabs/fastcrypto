// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use crate::groups::multiplier::windowed::{multi_scalar_mul, WindowedScalarMultiplier};
use crate::groups::multiplier::ScalarMultiplier;
use crate::groups::secp256r1::{ProjectivePoint, Scalar, SCALAR_SIZE_IN_BYTES};
use crate::groups::{Doubling, GroupElement, Scalar as ScalarTrait};
use crate::secp256r1::conversion::{
    affine_pt_arkworks_to_p256, affine_pt_p256_to_projective_arkworks, arkworks_fq_to_fr,
    fq_arkworks_to_p256, fr_arkworks_to_p256, fr_p256_to_arkworks, get_affine_x_coordinate,
    reduce_bytes,
};
use crate::secp256r1::{PRECOMPUTED_POINTS, SLIDING_WINDOW_WIDTH};
use crate::secp256r1_tests::{add_small, FIELD_MODULUS, GROUP_ORDER, X_ZERO_COMPRESSED};
use crate::serde_helpers::ToFromByteArray;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use hex_literal::hex;
use once_cell::sync::Lazy;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field as _, Group as _, PrimeField as _};
use p256::test_vectors::group::{ADD_TEST_VECTORS, MUL_TEST_VECTORS};
use p256::{AffinePoint, EncodedPoint, U256};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use std::collections::HashMap;

//
// Helper functions
//

/// The multiplier that ECDSA signing, verification and recovery in [crate::secp256r1] use.
type EcdsaMultiplier =
    WindowedScalarMultiplier<ProjectivePoint, Scalar, PRECOMPUTED_POINTS, SLIDING_WINDOW_WIDTH>;

static ECDSA_MULTIPLIER: Lazy<EcdsaMultiplier> =
    Lazy::new(|| EcdsaMultiplier::new(ProjectivePoint::generator(), ProjectivePoint::zero()));

/// The multiplier with the smallest cache and sliding window: 1-bit windows for both scalars of
/// `two_scalar_mul`.
static SMALLEST_MULTIPLIER: Lazy<WindowedScalarMultiplier<ProjectivePoint, Scalar, 2, 1>> =
    Lazy::new(|| {
        WindowedScalarMultiplier::new(ProjectivePoint::generator(), ProjectivePoint::zero())
    });

/// The compressed encoding of a point with x = n + 3, the smallest x-coordinate on the curve that
/// is at least n. Verification reduces such an x modulo n.
const X_ORDER_PLUS_THREE_COMPRESSED: [u8; 33] =
    hex!("02ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632554");

/// The compressed encoding of a point with x = p - 3, the largest x-coordinate on the curve.
const X_FIELD_MODULUS_MINUS_THREE_COMPRESSED: [u8; 33] =
    hex!("03ffffffff00000001000000000000000000000000fffffffffffffffffffffffc");

/// p - 1 - n, big-endian: p - 1 reduced modulo n.
const FIELD_MODULUS_MINUS_ORDER_MINUS_ONE: [u8; 32] =
    hex!("000000000000000000000000000000004319055358e8617b0c46353d039cdaad");

/// The secret key of RFC 6979, A.2.5, as an arbitrary fixed scalar.
const ARBITRARY_SCALAR: [u8; 32] =
    hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");

fn minus_one() -> p256::Scalar {
    -p256::Scalar::ONE
}

/// 2^k modulo n.
fn two_to_the(k: usize) -> p256::Scalar {
    (0..k).fold(p256::Scalar::ONE, |x, _| x.double())
}

/// The big-endian integer reduced modulo n.
fn reduce(bytes: &[u8; 32]) -> p256::Scalar {
    <p256::Scalar as Reduce<U256>>::reduce_bytes(bytes.into())
}

/// Reverses the byte order, from big-endian to little-endian or back.
fn reversed(mut bytes: [u8; SCALAR_SIZE_IN_BYTES]) -> [u8; SCALAR_SIZE_IN_BYTES] {
    bytes.reverse();
    bytes
}

/// Converts a p256 scalar to a fastcrypto scalar, which is encoded little-endian.
fn from_p256_scalar(scalar: &p256::Scalar) -> Scalar {
    Scalar::from_byte_array(&reversed(scalar.to_bytes().into())).unwrap()
}

fn to_p256_scalar(scalar: &Scalar) -> p256::Scalar {
    p256::Scalar::from_repr(reversed(scalar.to_byte_array()).into()).unwrap()
}

/// The affine coordinates of a point, big-endian, or `None` for the identity.
fn affine_coordinates(point: &ProjectivePoint) -> Option<(Vec<u8>, Vec<u8>)> {
    let affine = point.0.into_affine();
    (!affine.infinity).then(|| {
        (
            affine.x.into_bigint().to_bytes_be(),
            affine.y.into_bigint().to_bytes_be(),
        )
    })
}

/// Converts a fastcrypto point to a p256 point through its affine coordinates, independently of
/// [crate::secp256r1::conversion].
fn to_p256_point(point: &ProjectivePoint) -> p256::ProjectivePoint {
    match affine_coordinates(point) {
        None => p256::ProjectivePoint::IDENTITY,
        Some((x, y)) => {
            let encoded = EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            AffinePoint::from_encoded_point(&encoded).unwrap().into()
        }
    }
}

/// The point k * G, computed by fastcrypto and by p256.
fn multiple_of_generator(k: &p256::Scalar) -> (ProjectivePoint, p256::ProjectivePoint) {
    (
        ProjectivePoint::generator() * from_p256_scalar(k),
        p256::ProjectivePoint::GENERATOR * k,
    )
}

fn decode_point(bytes: &[u8]) -> AffinePoint {
    AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(bytes).unwrap()).unwrap()
}

/// Edge cases of the scalars u1 = z / s and u2 = r / s of ECDSA verification, which the signer
/// controls independently: 0, ±1, ±2, (n ± 1) / 2, 2^k and 2^k - 1 at window and byte boundaries
/// (2^256 - 1 is reduced modulo n), repeated bytes and an arbitrary scalar.
fn edge_scalars() -> Vec<p256::Scalar> {
    let one = p256::Scalar::ONE;
    let half = minus_one() * p256::Scalar::from(2u64).invert().unwrap();
    let mut scalars = vec![
        p256::Scalar::ZERO,
        one,
        one.double(),
        minus_one(),
        minus_one() - one,
        half,
        half + one,
    ];
    for k in [1, 4, 5, 7, 8, 9, 63, 64, 128, 224, 252, 255, 256] {
        scalars.push(two_to_the(k));
        scalars.push(two_to_the(k) - one);
    }
    scalars.push(reduce(&[0x55; 32]));
    scalars.push(reduce(&[0xaa; 32]));
    scalars.push(reduce(&ARBITRARY_SCALAR));
    scalars
}

/// Discrete logarithms to the generator of edge cases of the point Q in u1 * G + u2 * Q: the
/// identity, ±G, ±2G, 3G and an arbitrary point.
fn edge_point_logs() -> Vec<p256::Scalar> {
    let one = p256::Scalar::ONE;
    vec![
        p256::Scalar::ZERO,
        one,
        minus_one(),
        one.double(),
        -one.double(),
        p256::Scalar::from(3u64),
        reduce(&ARBITRARY_SCALAR),
    ]
}

/// The points that the conversions treat specially: the identity, the generator, and points with
/// x = 0, x = n + 3 and x = p - 3, with both y-coordinates.
fn edge_points() -> Vec<AffinePoint> {
    let mut points = vec![AffinePoint::IDENTITY];
    for point in [
        AffinePoint::GENERATOR,
        decode_point(&X_ZERO_COMPRESSED),
        decode_point(&X_ORDER_PLUS_THREE_COMPRESSED),
        decode_point(&X_FIELD_MODULUS_MINUS_THREE_COMPRESSED),
    ] {
        points.push(point);
        points.push(-point);
    }
    points
}

/// Checks `mul` of a multiplier with the given cache size against the expected results. Each case
/// is a base with pairs (scalar, scalar * base).
fn check_mul<const CACHE_SIZE: usize>(
    cases: &[(ProjectivePoint, Vec<(Scalar, p256::ProjectivePoint)>)],
) {
    for (base, products) in cases {
        let multiplier = WindowedScalarMultiplier::<ProjectivePoint, Scalar, CACHE_SIZE, 2>::new(
            *base,
            ProjectivePoint::zero(),
        );
        for (scalar, expected) in products {
            assert_eq!(
                to_p256_point(&multiplier.mul(scalar)),
                *expected,
                "cache size {CACHE_SIZE}, base {base:?}, scalar {scalar:?}"
            );
        }
    }
}

/// Checks `two_scalar_mul` of a multiplier with the given parameters against the expected results.
/// Each case is (u1, Q, u2, u1 * G + u2 * Q).
fn check_two_scalar_mul<const CACHE_SIZE: usize, const SLIDING_WINDOW: usize>(
    cases: &[(Scalar, ProjectivePoint, Scalar, p256::ProjectivePoint)],
) {
    let multiplier =
        WindowedScalarMultiplier::<ProjectivePoint, Scalar, CACHE_SIZE, SLIDING_WINDOW>::new(
            ProjectivePoint::generator(),
            ProjectivePoint::zero(),
        );
    for (u1, q, u2, expected) in cases {
        assert_eq!(
            to_p256_point(&multiplier.two_scalar_mul(u1, q, u2)),
            *expected,
            "cache size {CACHE_SIZE}, sliding window {SLIDING_WINDOW}, u1 {u1:?}, u2 {u2:?}"
        );
    }
}

/// The table that `multi_scalar_mul` expects for a point with a window of the given width:
/// 2^(width - 1) * point, ..., (2^width - 1) * point.
fn precomputed_multiples(point: &ProjectivePoint, width: usize) -> Vec<ProjectivePoint> {
    let mut multiples = vec![point.repeated_doubling(width as u64 - 1)];
    for _ in 1..1 << (width - 1) {
        multiples.push(*multiples.last().unwrap() + point);
    }
    multiples
}

//
// Arithmetic tests
//

#[test]
fn test_arithmetic() {
    let g = ProjectivePoint::generator();
    let o = ProjectivePoint::zero();
    let two = Scalar::from(2);
    let minus_one = from_p256_scalar(&minus_one());

    assert_eq!(g + g, g.double());
    assert_eq!(g * two, g.double());
    assert_eq!(g.double() * (Scalar::generator() / two).unwrap(), g);
    // u128 is converted correctly.
    assert_eq!(
        Scalar::from(2 << 66) / Scalar::from(8),
        Ok(Scalar::from(2 << 63))
    );

    // The identity, inverses, and the scalars 0, 1 and n - 1.
    assert_eq!(ProjectivePoint::default(), o);
    assert_eq!(g * Scalar::zero(), o);
    assert_eq!(g * Scalar::generator(), g);
    assert_eq!(g * minus_one, -g);
    // n * G = (n - 1) * G + G is the identity.
    assert_eq!(g * minus_one + g, o);
    assert_eq!(g + -g, o);
    assert_eq!(g - g, o);
    assert_eq!(o.double(), o);
    assert_eq!(-o, o);
    assert_eq!(o + g, g);
    assert_eq!(g + o, g);
    assert_eq!(o * minus_one, o);
    assert_eq!(ProjectivePoint::sum([g, g, -g].into_iter()), g);

    // Equality does not depend on the projective coordinates.
    let three_g = g.double() + g;
    let also_three_g = g + g.double();
    assert_ne!(three_g.0.z, also_three_g.0.z);
    assert_eq!(three_g, also_three_g);
    assert_eq!(
        to_p256_point(&three_g),
        p256::ProjectivePoint::GENERATOR * p256::Scalar::from(3u64)
    );

    assert_eq!(Scalar::default(), Scalar::zero());
    assert_eq!(Scalar::generator(), Scalar::from(1));
    assert_eq!(minus_one + Scalar::generator(), Scalar::zero());
    assert_eq!(minus_one * minus_one, Scalar::generator());
    assert_eq!(minus_one.inverse().unwrap(), minus_one);
    assert_eq!(-Scalar::zero(), Scalar::zero());
}

#[test]
fn test_division_by_zero() {
    // An error, not a panic.
    let error = FastCryptoError::InvalidInput;
    assert_eq!(Scalar::zero().inverse(), Err(error.clone()));
    assert_eq!(Scalar::generator() / Scalar::zero(), Err(error.clone()));
    assert_eq!(Scalar::zero() / Scalar::zero(), Err(error.clone()));
    assert_eq!(
        ProjectivePoint::generator() / Scalar::zero(),
        Err(error.clone())
    );
    assert_eq!(ProjectivePoint::zero() / Scalar::zero(), Err(error));
    assert_eq!(
        ProjectivePoint::zero() / Scalar::generator(),
        Ok(ProjectivePoint::zero())
    );
}

//
// Serialization tests
//

#[test]
fn test_to_from_byte_array() {
    let scalar = Scalar::rand(&mut StdRng::from_seed([0; 32]));
    assert_eq!(Scalar::from_byte_array(&scalar.to_byte_array()), Ok(scalar));

    // Little-endian, unlike SEC1 and p256.
    let mut seven = [0; SCALAR_SIZE_IN_BYTES];
    seven[0] = 7;
    assert_eq!(Scalar::from(7).to_byte_array(), seven);
    let mut u128_max = [0; SCALAR_SIZE_IN_BYTES];
    u128_max[..16].copy_from_slice(&[0xff; 16]);
    assert_eq!(Scalar::from(u128::MAX).to_byte_array(), u128_max);

    // Exactly the values below n are accepted.
    let order_minus_one = reversed(add_small(&GROUP_ORDER, -1));
    assert_eq!(
        Scalar::from_byte_array(&order_minus_one).unwrap(),
        from_p256_scalar(&minus_one())
    );
    assert_eq!(Scalar::from_byte_array(&[0; 32]).unwrap(), Scalar::zero());
    for rejected in [
        GROUP_ORDER,
        add_small(&GROUP_ORDER, 1),
        FIELD_MODULUS,
        [0xff; 32],
    ] {
        assert_eq!(
            Scalar::from_byte_array(&reversed(rejected)),
            Err(FastCryptoError::InvalidInput)
        );
        assert!(bcs::from_bytes::<Scalar>(&reversed(rejected)).is_err());
    }

    // BCS is the 32 bytes without a length prefix, JSON is their Base64 encoding.
    assert_eq!(bcs::to_bytes(&Scalar::from(7)).unwrap(), seven);
    assert_eq!(bcs::from_bytes::<Scalar>(&seven).unwrap(), Scalar::from(7));
    assert_eq!(
        serde_json::to_string(&Scalar::from(7)).unwrap(),
        "\"BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\""
    );
    assert_eq!(
        serde_json::from_str::<Scalar>("\"BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"").unwrap(),
        Scalar::from(7)
    );
    for length in [0, 31, 33] {
        assert!(bcs::from_bytes::<Scalar>(&vec![0; length]).is_err());
        let json = serde_json::to_string(&Base64::encode(vec![0; length]));
        assert!(serde_json::from_str::<Scalar>(&json.unwrap()).is_err());
    }
}

//
// Multiplier tests
//

#[test]
fn test_mul_with_every_cache_size() {
    // The generator, its negation and the identity as the base, with every window width from 1 to
    // 10 bits.
    let cases = [p256::Scalar::ONE, minus_one(), p256::Scalar::ZERO]
        .iter()
        .map(|log| {
            let (base, expected_base) = multiple_of_generator(log);
            let products = edge_scalars()
                .iter()
                .map(|scalar| (from_p256_scalar(scalar), expected_base * scalar))
                .collect();
            (base, products)
        })
        .collect::<Vec<_>>();
    check_mul::<2>(&cases);
    check_mul::<4>(&cases);
    check_mul::<8>(&cases);
    check_mul::<16>(&cases);
    check_mul::<32>(&cases);
    check_mul::<64>(&cases);
    check_mul::<128>(&cases);
    check_mul::<PRECOMPUTED_POINTS>(&cases);
    check_mul::<512>(&cases);
    check_mul::<1024>(&cases);
}

#[test]
fn test_two_scalar_mul_on_edge_cases() {
    // ECDSA verification computes u1 * G + u2 * Q, where the signer chooses u1, u2 and the public
    // key Q, and recovery computes the same with Q = R. Include the identity as a result
    // (Q = -G and u1 = u2, or Q = G and u1 = -u2), u1 or u2 equal to 0, Q equal to the base point,
    // and scalars with leading zero windows.
    let scalars = edge_scalars();
    let short = two_to_the(128) - p256::Scalar::ONE;
    let mut pairs = vec![
        (p256::Scalar::ZERO, p256::Scalar::ZERO),
        (p256::Scalar::ZERO, short),
        (short, p256::Scalar::ZERO),
        (short, short),
        (short, -short),
    ];
    for i in (0..scalars.len()).step_by(4) {
        pairs.push((scalars[i], scalars[(7 * i + 3) % scalars.len()]));
    }
    let cases = edge_point_logs()
        .iter()
        .flat_map(|log| {
            let (q, expected_q) = multiple_of_generator(log);
            pairs.iter().map(move |(u1, u2)| {
                (
                    from_p256_scalar(u1),
                    q,
                    from_p256_scalar(u2),
                    p256::ProjectivePoint::GENERATOR * u1 + expected_q * u2,
                )
            })
        })
        .collect::<Vec<_>>();
    assert!(cases
        .iter()
        .any(|(_, _, _, expected)| *expected == p256::ProjectivePoint::IDENTITY));

    // Window widths 1 to 10 for G, and 1 to 9 for Q.
    check_two_scalar_mul::<2, 1>(&cases);
    check_two_scalar_mul::<4, 2>(&cases);
    check_two_scalar_mul::<8, 3>(&cases);
    check_two_scalar_mul::<16, 4>(&cases);
    check_two_scalar_mul::<64, 6>(&cases);
    check_two_scalar_mul::<PRECOMPUTED_POINTS, 1>(&cases);
    check_two_scalar_mul::<PRECOMPUTED_POINTS, SLIDING_WINDOW_WIDTH>(&cases);
    check_two_scalar_mul::<512, 9>(&cases);
    check_two_scalar_mul::<1024, 8>(&cases);
}

#[test]
fn test_multi_scalar_mul() {
    let zero = ProjectivePoint::zero();
    assert_eq!(
        multi_scalar_mul::<ProjectivePoint, Scalar, 0>(&[], &[], &HashMap::new(), 2, zero),
        zero
    );

    // Repeated, negated and zero points, with and without precomputed tables.
    let (q, expected_q) = multiple_of_generator(&reduce(&ARBITRARY_SCALAR));
    let g = ProjectivePoint::generator();
    let expected_g = p256::ProjectivePoint::GENERATOR;
    let element_sets = [
        ([g, q, -q], [expected_g, expected_q, -expected_q]),
        (
            [q, q, zero],
            [expected_q, expected_q, p256::ProjectivePoint::IDENTITY],
        ),
    ];
    let scalars = edge_scalars();
    for (i, (elements, expected_elements)) in element_sets.iter().enumerate() {
        for width in 1..=8 {
            let s = [
                scalars[(5 * width + i) % scalars.len()],
                scalars[(3 * width + 1) % scalars.len()],
                scalars[(7 * width + 2) % scalars.len()],
            ];
            let expected = expected_elements[0] * s[0]
                + expected_elements[1] * s[1]
                + expected_elements[2] * s[2];
            let s = s.map(|s| from_p256_scalar(&s));
            let tables = [
                HashMap::new(),
                HashMap::from([(1, precomputed_multiples(&elements[1], width))]),
                HashMap::from([
                    (0, precomputed_multiples(&elements[0], 1)),
                    (2, precomputed_multiples(&elements[2], 10 - width)),
                ]),
            ];
            for table in &tables {
                assert_eq!(
                    to_p256_point(&multi_scalar_mul(&s, elements, table, width, zero)),
                    expected,
                    "width {width}"
                );
            }
        }
    }
}

//
// Conversion tests
//

#[test]
fn test_scalar_conversions() {
    for scalar in edge_scalars() {
        let converted = fr_p256_to_arkworks(&scalar);
        assert_eq!(Scalar(converted), from_p256_scalar(&scalar));
        assert_eq!(fr_arkworks_to_p256(&converted), scalar);
    }

    // Hashes are reduced modulo n, like p256 does.
    for bytes in [
        [0; 32],
        add_small(&GROUP_ORDER, -1),
        GROUP_ORDER,
        add_small(&GROUP_ORDER, 1),
        FIELD_MODULUS,
        [0xff; 32],
        ARBITRARY_SCALAR,
    ] {
        assert_eq!(fr_arkworks_to_p256(&reduce_bytes(&bytes)), reduce(&bytes));
    }
}

#[test]
fn test_field_element_to_scalar() {
    // Verification compares r with x(R) mod n, and signing flags x(R) >= n in the recovery id.
    let order_minus_one = add_small(&GROUP_ORDER, -1);
    for (x, expected, is_reduced) in [
        ([0; 32], [0; 32], false),
        (order_minus_one, order_minus_one, false),
        (GROUP_ORDER, [0; 32], true),
        (add_small(&GROUP_ORDER, 1), add_small(&[0; 32], 1), true),
        (
            add_small(&FIELD_MODULUS, -1),
            FIELD_MODULUS_MINUS_ORDER_MINUS_ONE,
            true,
        ),
    ] {
        let field_element = ark_secp256r1::Fq::from_be_bytes_mod_order(&x);
        assert_eq!(fq_arkworks_to_p256(&field_element).as_slice(), x);
        let (scalar, reduced) = arkworks_fq_to_fr(&field_element);
        assert_eq!(fr_arkworks_to_p256(&scalar).to_bytes().as_slice(), expected);
        assert_eq!(reduced, is_reduced);
    }
}

#[test]
fn test_point_conversions() {
    // x = p - 3 is the largest x-coordinate on the curve.
    for x in [add_small(&FIELD_MODULUS, -1), add_small(&FIELD_MODULUS, -2)] {
        let mut compressed = [2; 33];
        compressed[1..].copy_from_slice(&x);
        assert!(bool::from(
            AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(compressed).unwrap())
                .is_none()
        ));
    }

    for point in edge_points() {
        let converted = affine_pt_p256_to_projective_arkworks(&point);
        assert_eq!(to_p256_point(&ProjectivePoint(converted)), point.into());
        assert_eq!(affine_pt_arkworks_to_p256(&converted.into_affine()), point);
        let x = get_affine_x_coordinate(&converted).map(|x| fq_arkworks_to_p256(&x));
        assert_eq!(x.as_ref(), point.to_encoded_point(false).x());
    }

    // The x-coordinate of a point whose projective coordinates are not normalized.
    let three_g = ProjectivePoint::generator().double() + ProjectivePoint::generator();
    assert_eq!(
        fq_arkworks_to_p256(&get_affine_x_coordinate(&three_g.0).unwrap()).as_slice(),
        affine_coordinates(&three_g).unwrap().0
    );
}

//
// Test vectors
//

#[test]
fn test_vectors_multiples_of_generator() {
    // The NIST known answers for k * G that p256 ships: k = 1, ..., 20, then 32 more values of k,
    // including n - 3, n - 2 and n - 1.
    let vectors = ADD_TEST_VECTORS
        .iter()
        .enumerate()
        .map(|(i, (x, y))| (Scalar::from(i as u128 + 1), x, y))
        .chain(
            MUL_TEST_VECTORS
                .iter()
                .map(|(k, x, y)| (Scalar::from_byte_array(&reversed(*k)).unwrap(), x, y)),
        );
    let g = ProjectivePoint::generator();
    for (k, x, y) in vectors {
        let expected = Some((x.to_vec(), y.to_vec()));
        assert_eq!(affine_coordinates(&(g * k)), expected);
        assert_eq!(affine_coordinates(&ECDSA_MULTIPLIER.mul(&k)), expected);
        assert_eq!(
            affine_coordinates(&ECDSA_MULTIPLIER.two_scalar_mul(&k, &g, &Scalar::zero())),
            expected
        );
        assert_eq!(
            affine_coordinates(&ECDSA_MULTIPLIER.two_scalar_mul(&Scalar::zero(), &g, &k)),
            expected
        );
        assert_eq!(
            affine_coordinates(&ECDSA_MULTIPLIER.two_scalar_mul(
                &(k - Scalar::generator()),
                &-g,
                &-Scalar::generator()
            )),
            expected
        );
    }
}

//
// Proptests
//

/// Scalars, biased towards edge cases: 0, ±1, [edge_scalars], 2^k and 2^k - 1 for every k,
/// scalars below 2^64 (leading zero windows) and arbitrary scalars.
fn arb_scalar() -> impl Strategy<Value = p256::Scalar> {
    prop_oneof![
        prop_oneof![
            Just(p256::Scalar::ZERO),
            Just(p256::Scalar::ONE),
            Just(minus_one())
        ],
        prop::sample::select(edge_scalars()),
        (0usize..=256).prop_map(two_to_the),
        (0usize..=256).prop_map(|k| two_to_the(k) - p256::Scalar::ONE),
        any::<u64>().prop_map(p256::Scalar::from),
        any::<[u8; 32]>().prop_map(|bytes| reduce(&bytes)),
    ]
}

/// Discrete logarithms to the generator: the identity, ±G and [edge_point_logs] often, and
/// multiples by [arb_scalar].
fn arb_point_log() -> impl Strategy<Value = p256::Scalar> {
    prop_oneof![
        1 => Just(p256::Scalar::ZERO),
        1 => prop_oneof![Just(p256::Scalar::ONE), Just(minus_one())],
        1 => prop::sample::select(edge_point_logs()),
        3 => arb_scalar(),
    ]
}

/// 32-byte big-endian integers: arbitrary ones, those near 0, n and 2^256, those that start like n
/// (just below or above it) and encodings of [arb_scalar].
fn arb_big_endian_bytes() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![
        any::<[u8; 32]>(),
        (
            prop_oneof![Just([0; 32]), Just(GROUP_ORDER), Just([0xff; 32])],
            -3i64..=3
        )
            .prop_map(|(bytes, delta)| add_small(&bytes, delta)),
        (0..=32usize, any::<[u8; 32]>()).prop_map(|(prefix, mut bytes)| {
            bytes[..prefix].copy_from_slice(&GROUP_ORDER[..prefix]);
            bytes
        }),
        arb_scalar().prop_map(|scalar| scalar.to_bytes().into()),
    ]
}

/// Points to convert: multiples of the generator by [arb_point_log], and [edge_points].
fn arb_affine_point() -> impl Strategy<Value = AffinePoint> {
    prop_oneof![
        arb_point_log().prop_map(|k| (p256::ProjectivePoint::GENERATOR * k).to_affine()),
        prop::sample::select(edge_points()),
    ]
}

proptest! {
    #[test]
    fn test_decode_adversarial_scalars(big_endian in arb_big_endian_bytes()) {
        // Decoding accepts exactly the little-endian encodings of the values below n, the same set
        // as p256 with big-endian encodings, and BCS agrees.
        let bytes = reversed(big_endian);
        let expected = Option::<p256::Scalar>::from(p256::Scalar::from_repr(big_endian.into()));
        let decoded = Scalar::from_byte_array(&bytes);
        prop_assert_eq!(decoded.is_ok(), expected.is_some());
        prop_assert_eq!(bcs::from_bytes::<Scalar>(&bytes).ok(), decoded.clone().ok());
        if let (Ok(scalar), Some(expected)) = (decoded, expected) {
            prop_assert_eq!(to_p256_scalar(&scalar), expected);
            prop_assert_eq!(scalar.to_byte_array(), bytes);
        }
    }

    #[test]
    fn test_scalar_arithmetic(a in arb_scalar(), b in arb_scalar()) {
        let (x, y) = (from_p256_scalar(&a), from_p256_scalar(&b));
        prop_assert_eq!(to_p256_scalar(&(x + y)), a + b);
        prop_assert_eq!(to_p256_scalar(&(x - y)), a - b);
        prop_assert_eq!(to_p256_scalar(&(x * y)), a * b);
        prop_assert_eq!(to_p256_scalar(&-x), -a);
        let inverse = Option::<p256::Scalar>::from(b.invert());
        prop_assert_eq!(y.inverse().ok().map(|s| to_p256_scalar(&s)), inverse);
        prop_assert_eq!((x / y).ok().map(|s| to_p256_scalar(&s)), inverse.map(|i| a * i));
    }

    #[test]
    fn test_group_law(p in arb_point_log(), q in arb_point_log(), s in arb_scalar()) {
        let (x, expected_x) = multiple_of_generator(&p);
        let (y, expected_y) = multiple_of_generator(&q);
        prop_assert_eq!(to_p256_point(&x), expected_x);
        prop_assert_eq!(to_p256_point(&(x + y)), expected_x + expected_y);
        prop_assert_eq!(to_p256_point(&(x - y)), expected_x - expected_y);
        prop_assert_eq!(to_p256_point(&-x), -expected_x);
        prop_assert_eq!(to_p256_point(&x.double()), expected_x.double());
        prop_assert_eq!(to_p256_point(&(x * from_p256_scalar(&s))), expected_x * s);
        // Division fails exactly for s = 0.
        let quotient = (x / from_p256_scalar(&s)).ok().map(|q| to_p256_point(&q));
        let inverse = Option::<p256::Scalar>::from(s.invert());
        prop_assert_eq!(quotient, inverse.map(|i| expected_x * i));
        prop_assert_eq!(x == y, expected_x == expected_y);
    }

    #[test]
    fn test_conversions(
        scalar in arb_scalar(),
        bytes in arb_big_endian_bytes(),
        point in arb_affine_point()
    ) {
        prop_assert_eq!(fr_arkworks_to_p256(&fr_p256_to_arkworks(&scalar)), scalar);
        prop_assert_eq!(fr_arkworks_to_p256(&reduce_bytes(&bytes)), reduce(&bytes));

        let converted = affine_pt_p256_to_projective_arkworks(&point);
        prop_assert_eq!(to_p256_point(&ProjectivePoint(converted)), point.into());
        prop_assert_eq!(affine_pt_arkworks_to_p256(&converted.into_affine()), point);
        let encoded = point.to_encoded_point(false);
        match (get_affine_x_coordinate(&converted), encoded.x()) {
            (None, None) => {}
            (Some(x), Some(expected)) => {
                // x and x mod n, with the flag of x >= n.
                let x_bytes = fq_arkworks_to_p256(&x);
                prop_assert_eq!(&x_bytes, expected);
                let (reduced, is_reduced) = arkworks_fq_to_fr(&x);
                prop_assert_eq!(fr_arkworks_to_p256(&reduced), reduce(&x_bytes.into()));
                prop_assert_eq!(
                    is_reduced,
                    U256::from_be_slice(&x_bytes) >= U256::from_be_slice(&GROUP_ORDER)
                );
            }
            _ => prop_assert!(false, "x-coordinates differ"),
        }
    }
}

proptest! {
    // Each case does several 256-bit scalar multiplications.
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn test_multipliers(u1 in arb_scalar(), q in arb_point_log(), u2 in arb_scalar()) {
        // The ECDSA multiplier and the one with the smallest windows, on an adversarial
        // u1 * G + u2 * Q.
        let (point, expected_q) = multiple_of_generator(&q);
        let expected = p256::ProjectivePoint::GENERATOR * u1 + expected_q * u2;
        let (u1, u2) = (from_p256_scalar(&u1), from_p256_scalar(&u2));
        for result in [
            ECDSA_MULTIPLIER.two_scalar_mul(&u1, &point, &u2),
            SMALLEST_MULTIPLIER.two_scalar_mul(&u1, &point, &u2),
        ] {
            prop_assert_eq!(to_p256_point(&result), expected);
        }
        prop_assert_eq!(ECDSA_MULTIPLIER.mul(&u1), ProjectivePoint::generator() * u1);
    }

    #[test]
    fn test_multi_scalar_mul_with_tables(
        terms in prop::array::uniform3((arb_scalar(), arb_point_log())),
        width in 1usize..=8,
        table_width in 1usize..=8,
        table_index in 0usize..3,
    ) {
        let expected = terms
            .iter()
            .map(|(s, k)| p256::ProjectivePoint::GENERATOR * k * s)
            .sum::<p256::ProjectivePoint>();
        let scalars = terms.map(|(s, _)| from_p256_scalar(&s));
        let elements = terms.map(|(_, k)| multiple_of_generator(&k).0);
        let zero = ProjectivePoint::zero();
        for table in [
            HashMap::new(),
            HashMap::from([(
                table_index,
                precomputed_multiples(&elements[table_index], table_width),
            )]),
        ] {
            prop_assert_eq!(
                to_p256_point(&multi_scalar_mul(&scalars, &elements, &table, width, zero)),
                expected
            );
        }
    }
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // The strategies hit the edge cases often enough for the 64 cases of `test_multipliers`.
    const SAMPLES: usize = 1000;
    let mut runner = TestRunner::deterministic();
    let scalars = (0..SAMPLES)
        .map(|_| arb_scalar().new_tree(&mut runner).unwrap().current())
        .collect::<Vec<_>>();
    let zero = scalars.iter().filter(|s| bool::from(s.is_zero())).count();
    let plus_minus_one = scalars
        .iter()
        .filter(|s| **s == p256::Scalar::ONE || **s == minus_one())
        .count();
    let short = scalars
        .iter()
        .filter(|s| !bool::from(s.is_zero()) && s.to_bytes()[..24] == [0; 24])
        .count();
    let logs = (0..SAMPLES)
        .map(|_| arb_point_log().new_tree(&mut runner).unwrap().current())
        .collect::<Vec<_>>();
    let identity = logs.iter().filter(|k| bool::from(k.is_zero())).count();
    let plus_minus_g = logs
        .iter()
        .filter(|k| **k == p256::Scalar::ONE || **k == minus_one())
        .count();
    let decoded = (0..SAMPLES)
        .filter(|_| {
            let bytes = arb_big_endian_bytes()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            Scalar::from_byte_array(&reversed(bytes)).is_ok()
        })
        .count();
    let near_order = (0..SAMPLES)
        .filter(|_| {
            let bytes = arb_big_endian_bytes()
                .new_tree(&mut runner)
                .unwrap()
                .current();
            (-3..=3).any(|delta| bytes == add_small(&GROUP_ORDER, delta))
        })
        .count();
    println!(
        "scalars: zero {zero}, ±1 {plus_minus_one}, below 2^64 {short}; points: identity \
         {identity}, ±G {plus_minus_g}; bytes: decoded {decoded}, n - 3..n + 3 {near_order}"
    );
    assert!(zero >= SAMPLES / 40, "{zero}");
    assert!(plus_minus_one >= SAMPLES / 20, "{plus_minus_one}");
    assert!(short >= SAMPLES / 10, "{short}");
    assert!(identity >= SAMPLES / 10, "{identity}");
    assert!(plus_minus_g >= SAMPLES / 10, "{plus_minus_g}");
    assert!(
        decoded > SAMPLES / 2 && decoded < SAMPLES * 9 / 10,
        "{decoded}"
    );
    assert!(near_order >= SAMPLES / 40, "{near_order}");
}
