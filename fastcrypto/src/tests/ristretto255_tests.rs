// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::encoding::{Base64, Encoding};
use crate::error::FastCryptoError;
use crate::groups::ristretto255::{MixedMsmStrategy, RistrettoPoint, RistrettoScalar};
use crate::groups::{
    Doubling, FiatShamirChallenge, FromTrustedByteArray, GroupElement, HashToGroupElement,
    MixedMultiScalarMul, MultiScalarMul, PrecomputableMultiScalarMul, Scalar,
};
use crate::hash::{HashFunction, Sha512};
use crate::ristretto255_reference::{
    self as reference, add_small, concat, FIELD_MODULUS, GROUP_ORDER,
};
use crate::secp256k1_group_tests::{count, samples};
use crate::serde_helpers::ToFromByteArray;
use ark_ff::{Field, One, Zero};
use hex_literal::hex;
use itertools::Itertools;
use once_cell::sync::Lazy;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::ops::RangeInclusive;
use zeroize::Zeroize;

//
// Helper functions
//

/// l - 1, little-endian.
pub(crate) const GROUP_ORDER_MINUS_ONE: [u8; 32] =
    hex!("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");

/// The identity is encoded as s = 0.
const IDENTITY_ENCODING: [u8; 32] = [0; 32];

/// The smallest encoding after the identity, s = 4, and the largest one, s = p - 3.
const SMALLEST_ENCODING: [u8; 32] =
    hex!("0400000000000000000000000000000000000000000000000000000000000000");
const LARGEST_ENCODING: [u8; 32] =
    hex!("eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

/// The generator, from RFC 9496, appendix A.1.
const GENERATOR_ENCODING: [u8; 32] =
    hex!("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76");

/// 2^k for k < 256, little-endian.
fn power_of_two(k: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[k / 8] = 1 << (k % 8);
    bytes
}

fn from_reference_scalar(scalar: &reference::Scalar) -> RistrettoScalar {
    RistrettoScalar::from_byte_array(&reference::encode_scalar(scalar)).unwrap()
}

/// The point k * G, computed by fastcrypto and by the reference.
fn multiple_of_generator(k: &reference::Scalar) -> (RistrettoPoint, reference::Point) {
    (
        RistrettoPoint::generator() * from_reference_scalar(k),
        reference::Point::generator() * *k,
    )
}

/// The identity with each of its four representatives on the curve: k * G minus the decoding of the
/// encoding of k * G, for values of k that give different ones.
static IDENTITY_REPRESENTATIVES: Lazy<[(RistrettoPoint, reference::Point); 4]> = Lazy::new(|| {
    [3u64, 5, 1, 8].map(|k| {
        let (point, expected) = multiple_of_generator(&k.into());
        let decoded = RistrettoPoint::from_byte_array(&point.to_byte_array()).unwrap();
        let expected_decoded = reference::Point::decode(&expected.encode()).unwrap();
        (point - decoded, expected - expected_decoded)
    })
});

/// G, 2G, 3G, ..., with additions only, since multiplications are slow in debug builds.
fn consecutive_multiples(count: usize) -> Vec<RistrettoPoint> {
    let g = RistrettoPoint::generator();
    std::iter::successors(Some(g), |p| Some(*p + g))
        .take(count)
        .collect()
}

fn random_scalars(count: usize, rng: &mut StdRng) -> Vec<RistrettoScalar> {
    (0..count).map(|_| RistrettoScalar::rand(rng)).collect()
}

/// The multi-scalar multiplication with the points of [consecutive_multiples], with a single
/// multiplication.
fn msm_with_consecutive_multiples(scalars: &[RistrettoScalar]) -> RistrettoPoint {
    let terms = (1u64..)
        .zip(scalars)
        .map(|(k, s)| *s * RistrettoScalar::from(k));
    RistrettoPoint::generator() * RistrettoScalar::sum(terms)
}

/// Every decoder of a type: `from_byte_array` after checking that BCS, bincode and JSON agree.
fn decode_all<T>(bytes: &[u8; 32]) -> Option<T>
where
    T: ToFromByteArray<32> + DeserializeOwned + PartialEq + Debug,
{
    let decoded = T::from_byte_array(bytes);
    assert!(matches!(
        decoded,
        Ok(_) | Err(FastCryptoError::InvalidInput)
    ));
    let decoded = decoded.ok();
    assert_eq!(bcs::from_bytes::<T>(bytes).ok(), decoded);
    assert_eq!(bincode::deserialize::<T>(bytes).ok(), decoded);
    let json = serde_json::to_string(&Base64::encode(bytes)).unwrap();
    assert_eq!(serde_json::from_str::<T>(&json).ok(), decoded);
    decoded
}

/// Decodes a scalar, checking that every decoder accepts the same values as the reference and that
/// the reductions modulo l agree with it.
fn check_scalar(bytes: &[u8; 32]) -> Option<RistrettoScalar> {
    let decoded = decode_all::<RistrettoScalar>(bytes);
    assert_eq!(decoded.is_some(), reference::decode_scalar(bytes).is_some());
    assert!(decoded.is_none_or(|s| s.to_byte_array() == *bytes));
    let reduced = from_reference_scalar(&reference::reduce_scalar(bytes));
    assert_eq!(RistrettoScalar::from_bytes_mod_order(bytes), reduced);
    assert_eq!(
        RistrettoScalar::from_trusted_byte_array(bytes).unwrap(),
        reduced
    );
    decoded
}

/// Decodes a point, checking that every decoder accepts the same encodings as the reference and
/// decodes to the same point.
fn check_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    let decoded = decode_all::<RistrettoPoint>(bytes);
    assert_eq!(RistrettoPoint::from_trusted_byte_array(bytes).ok(), decoded);
    let expected = reference::Point::decode(bytes);
    assert_eq!(decoded.is_some(), expected.is_some());
    if let (Some(point), Some(expected)) = (decoded, expected) {
        assert_eq!(point.to_byte_array(), *bytes);
        let expected_sum = expected + reference::Point::generator();
        let sum = point + RistrettoPoint::generator();
        assert_eq!(sum.to_byte_array(), expected_sum.encode());
    }
    decoded
}

/// The values of k in the range for which base + k is the encoding of a point.
fn encodings_near(base: &[u8; 32], range: RangeInclusive<i64>) -> Vec<i64> {
    range
        .filter(|k| check_point(&add_small(base, *k)).is_some())
        .collect()
}

/// Checks the encodings of a value, as the given bytes and as their Base64 in JSON, and that only
/// inputs of the right length decode.
fn check_serde<T>(value: T, bytes: &[u8; 32])
where
    T: ToFromByteArray<32> + Serialize + DeserializeOwned + PartialEq + Debug,
{
    assert_eq!(value.to_byte_array(), *bytes);
    assert_eq!(bcs::to_bytes(&value).unwrap(), bytes);
    assert_eq!(bincode::serialize(&value).unwrap(), bytes);
    let json = format!("\"{}\"", Base64::encode(bytes));
    assert_eq!(serde_json::to_string(&value).unwrap(), json);
    assert_eq!(decode_all(bytes), Some(value));
    for wrong_length in [&[], &bytes[..31], &[bytes, [0].as_slice()].concat()] {
        assert!(bcs::from_bytes::<T>(wrong_length).is_err());
        let json = serde_json::to_string(&Base64::encode(wrong_length)).unwrap();
        assert!(serde_json::from_str::<T>(&json).is_err());
    }
}

//
// Arithmetic tests
//

#[test]
fn test_arithmetic() {
    // Different ways of computing 5G. The encoding is from RFC 9496, appendix A.1.
    let g = RistrettoPoint::generator();
    let five_g = RistrettoPoint::from_byte_array(&hex!(
        "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e"
    ))
    .unwrap();
    let five = RistrettoScalar::from(5u64);
    let four = RistrettoScalar::from(4u64);
    assert_eq!(g * five, five_g);
    assert_eq!(g + g + g + g + g + g - g, five_g);
    assert_eq!(g.double().double() + g, five_g);
    assert_eq!(g.repeated_doubling(3) - (g + g.double()), five_g);
    assert_eq!(
        g * (RistrettoScalar::from(7u64) - RistrettoScalar::from(2u64)),
        five_g
    );
    assert_eq!(RistrettoPoint::sum([g; 5].into_iter()), five_g);
    assert_eq!(
        RistrettoPoint::inner_product([g, g], [four, 1u64.into()]),
        five_g
    );
    assert_ne!(g, five_g);

    // The operators on references.
    let (g_ref, five_ref) = (&g, &five);
    assert_eq!(g * five_ref, five_g);
    assert_eq!(g_ref * five, five_g);
    assert_eq!(g_ref * five_ref, five_g);
    assert_eq!(g * four + g_ref, five_g);
    assert_eq!(five_g - g_ref, g * four);
    assert_eq!(-g_ref, -g);
    let mut p = RistrettoPoint::zero();
    p += five_g;
    p -= g;
    p += g_ref;
    p *= five;
    assert_eq!((p / five).unwrap(), five_g);
    let mut s = five - four;
    s += &four;
    s -= four;
    s *= five;
    assert_eq!(s, five);

    // The identity, -G and l - 1.
    let zero = RistrettoPoint::zero();
    let minus_one = RistrettoScalar::from_byte_array(&GROUP_ORDER_MINUS_ONE).unwrap();
    assert_eq!(RistrettoPoint::default(), zero);
    for p in [g, -g, five_g, zero] {
        assert_eq!(p + zero, p);
        assert_eq!(zero - p, -p);
        assert_eq!(p - p, zero);
        assert_eq!(p * RistrettoScalar::zero(), zero);
        assert_eq!(p * RistrettoScalar::generator(), p);
        assert_eq!(p * minus_one, -p);
        assert_eq!(p.repeated_doubling(0), p);
    }
    assert_eq!(zero.double(), zero);
    assert_eq!(minus_one, -RistrettoScalar::generator());
    assert_eq!(
        minus_one + RistrettoScalar::generator(),
        RistrettoScalar::zero()
    );
    assert_eq!(minus_one * minus_one, RistrettoScalar::generator());
    assert_eq!(minus_one.inverse().unwrap(), minus_one);
    assert_eq!(
        RistrettoScalar::product([five, minus_one].into_iter()),
        -five
    );

    assert_eq!(
        RistrettoScalar::from(1u128 << 67) / RistrettoScalar::from(8u64),
        Ok(RistrettoScalar::from(1u128 << 64))
    );

    // Division by zero.
    let zero_scalar = RistrettoScalar::zero();
    let err = FastCryptoError::InvalidInput;
    assert_eq!(zero_scalar.inverse(), Err(err.clone()));
    assert_eq!(five / zero_scalar, Err(err.clone()));
    assert_eq!(g / zero_scalar, Err(err));
}

#[test]
fn test_scalars_from_integers() {
    // Integers, little-endian.
    for x in [0, 1, 2 << 66, u64::MAX as u128, u128::MAX] {
        let mut expected = [0; 32];
        expected[..16].copy_from_slice(&x.to_le_bytes());
        assert_eq!(RistrettoScalar::from(x).to_byte_array(), expected);
        if let Ok(x) = u64::try_from(x) {
            assert_eq!(RistrettoScalar::from(x).to_byte_array(), expected);
        }
    }

    // Reduction modulo l of 32 and 64 little-endian bytes, computed with Python: 2^256 - 1, l * 2^256,
    // 2^256 and 2^512 - 1.
    let zero = [0; 32];
    assert_eq!(
        RistrettoScalar::from_bytes_mod_order(&[0xff; 32]).to_byte_array(),
        hex!("1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f")
    );
    for (bytes, expected) in [
        (concat(&zero, &GROUP_ORDER), zero),
        (
            concat(&zero, &power_of_two(0)),
            hex!("1d95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f"),
        ),
        (
            [0xff; 64],
            hex!("000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903"),
        ),
    ] {
        assert_eq!(
            RistrettoScalar::from_bytes_mod_order_wide(&bytes).to_byte_array(),
            expected
        );
    }

    // Random scalars are 64 random bytes reduced modulo l.
    let mut bytes = [0; 64];
    StdRng::seed_from_u64(0).fill_bytes(&mut bytes);
    assert_eq!(
        RistrettoScalar::rand(&mut StdRng::seed_from_u64(0)),
        RistrettoScalar::from_bytes_mod_order_wide(&bytes)
    );

    let mut scalar = RistrettoScalar::from(5u64);
    scalar.zeroize();
    assert_eq!(scalar, RistrettoScalar::zero());
}

#[test]
fn test_representatives() {
    // The four points on the curve that represent the identity are equal and have one encoding.
    // The reference, which does the same computation, confirms that they are four different points.
    // The proptests compare the operations on every representative of other elements.
    for (zero, expected) in IDENTITY_REPRESENTATIVES.iter() {
        assert_eq!(*zero, RistrettoPoint::zero());
        assert_eq!(zero.to_byte_array(), IDENTITY_ENCODING);
        assert!(*expected == reference::Point::identity());
        let same = |point: &&reference::Point| point.is_same_representative(expected);
        assert_eq!(
            reference::Point::torsion_points()
                .iter()
                .filter(same)
                .count(),
            1
        );
        let representatives = IDENTITY_REPRESENTATIVES.iter().map(|(_, point)| point);
        assert_eq!(representatives.filter(same).count(), 1);
    }
}

//
// Multi-scalar multiplication tests
//

#[test]
fn test_multiscalar_mul() {
    // Lengths around the algorithm and window size changes of curve25519-dalek, including zero.
    let mut rng = StdRng::seed_from_u64(0);
    let points = consecutive_multiples(802);
    for length in [0, 1, 2, 3, 189, 190, 191, 499, 500, 800, 801] {
        let scalars = random_scalars(length, &mut rng);
        assert_eq!(
            RistrettoPoint::multi_scalar_mul(&scalars, &points[..length]).unwrap(),
            msm_with_consecutive_multiples(&scalars)
        );
        assert_eq!(
            RistrettoPoint::multi_scalar_mul(&scalars, &points[..length + 1]),
            Err(FastCryptoError::InvalidInput)
        );
        if length > 0 {
            assert_eq!(
                RistrettoPoint::multi_scalar_mul(&scalars, &points[..length - 1]),
                Err(FastCryptoError::InvalidInput)
            );
        }
    }
    let g = RistrettoPoint::generator();
    assert_eq!(
        RistrettoPoint::multi_scalar_mul(&[1u64, 2, 3].map(RistrettoScalar::from), &[g; 3])
            .unwrap(),
        g * RistrettoScalar::from(6u64)
    );
    // The identity, repeated and negated points, and the scalars 0, 1, l - 1 and 2^252.
    let one = RistrettoScalar::generator();
    let two_to_252 = RistrettoScalar::from_byte_array(&power_of_two(252)).unwrap();
    let (scalars, points): (Vec<_>, Vec<_>) = [RistrettoScalar::zero(), one, -one, two_to_252]
        .into_iter()
        .cartesian_product([RistrettoPoint::zero(), g, -g, g, g.double()])
        .unzip();
    let products = scalars.iter().zip(&points).map(|(s, p)| *p * s);
    assert_eq!(
        RistrettoPoint::multi_scalar_mul(&scalars, &points).unwrap(),
        RistrettoPoint::sum(products)
    );
}

#[test]
fn test_precomputed_multiscalar_mul() {
    let mut rng = StdRng::seed_from_u64(0);
    let default = MixedMsmStrategy::default();
    let strategy = |max_weighted_points, dynamic_point_weight| MixedMsmStrategy {
        max_weighted_points,
        dynamic_point_weight,
    };
    let points = consecutive_multiples(default.max_weighted_points + 5);

    // The numbers of static and dynamic points are on both sides of the bound of each strategy.
    for (strategy, num_static, num_dynamic) in [
        // The default strategy: no points, only static points, only dynamic points and both.
        (default, 0, 0),
        (default, 5, 0),
        (default, 0, 3),
        (default, 5, 3),
        // The default bound, and one point more, so that the tables are not built.
        (default, default.max_weighted_points, 0),
        (default, default.max_weighted_points + 1, 0),
        (default, default.max_weighted_points + 1, 3),
        // Over the default bound because of the dynamic points: the tables are built, but not used.
        (
            default,
            5,
            default.max_weighted_points / default.dynamic_point_weight,
        ),
        // Tables for more points than the default bound.
        (strategy(usize::MAX, 0), default.max_weighted_points + 1, 3),
        // Never use tables.
        (strategy(0, 0), 5, 3),
        // The tables are built, but not used with this many dynamic points.
        (strategy(11, 2), 5, 4),
        // The weighted number of points saturates, below or at the bound.
        (strategy(usize::MAX - 1, usize::MAX), 5, 2),
        (strategy(usize::MAX, usize::MAX), 5, 2),
    ] {
        let (static_points, rest) = points.split_at(num_static);
        // `precompute` uses the default strategy.
        let precomputation = if strategy == default {
            RistrettoPoint::precompute(static_points)
        } else {
            RistrettoPoint::precompute_with_strategy(static_points, strategy)
        }
        .unwrap();
        assert_eq!(precomputation.strategy(), strategy);
        assert_eq!(precomputation.num_static_points(), num_static);

        // The sum with the given numbers of static and dynamic scalars and dynamic points.
        let scalars = random_scalars(num_static + num_dynamic + 1, &mut rng);
        let msm = |static_scalars: usize, dynamic_scalars: usize, dynamic_points: usize| {
            precomputation.mixed_multi_scalar_mul(
                &scalars[..static_scalars],
                &scalars[static_scalars..static_scalars + dynamic_scalars],
                &rest[..dynamic_points],
            )
        };
        assert_eq!(
            msm(num_static, num_dynamic, num_dynamic).unwrap(),
            msm_with_consecutive_multiples(&scalars[..num_static + num_dynamic])
        );

        // Mismatched lengths, also where the total numbers of scalars and points agree.
        for (da, db, dc) in [
            (1, 0, 0),
            (1, 0, 1),
            (-1, 0, 0),
            (-1, 1, 0),
            (0, 1, 0),
            (0, 0, 1),
        ] {
            if let Some(static_scalars) = num_static.checked_add_signed(da) {
                assert_eq!(
                    msm(static_scalars, num_dynamic + db, num_dynamic + dc),
                    Err(FastCryptoError::InvalidInput)
                );
            }
        }
    }
}

//
// Serialization tests
//

#[test]
fn test_serde() {
    // Scalars are 32 little-endian bytes and points are encoded as in RFC 9496.
    check_serde(RistrettoScalar::generator(), &power_of_two(0));
    check_serde(-RistrettoScalar::generator(), &GROUP_ORDER_MINUS_ONE);
    check_serde(RistrettoPoint::zero(), &IDENTITY_ENCODING);
    check_serde(RistrettoPoint::generator(), &GENERATOR_ENCODING);
    check_serde(
        RistrettoPoint::generator().double(),
        &hex!("6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"),
    );
    assert_eq!(
        serde_json::to_string(&RistrettoScalar::generator()).unwrap(),
        "\"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\""
    );
}

#[test]
fn test_canonical_scalars() {
    // Exactly the values below l decode.
    for bytes in [
        [0; 32],
        power_of_two(0),
        power_of_two(252),
        add_small(&GROUP_ORDER, -2),
        GROUP_ORDER_MINUS_ONE,
    ] {
        assert!(check_scalar(&bytes).is_some());
    }
    for bytes in [
        GROUP_ORDER,
        add_small(&GROUP_ORDER, 1),
        // 2l
        hex!("daa7ebb934c624b0ac39ef45bdf3bd2900000000000000000000000000000020"),
        power_of_two(253),
        power_of_two(254),
        // 0, 1 and l - 1 with the top bit set.
        power_of_two(255),
        add_small(&power_of_two(255), 1),
        hex!("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000090"),
        [0xff; 32],
    ] {
        assert!(check_scalar(&bytes).is_none());
    }
}

#[test]
fn test_canonical_points() {
    // Every encoding near 0, p and the largest 255- and 256-bit integers. The values that decode
    // are from a Python implementation of RFC 9496. There are none from p to 2^255 - 1 (which
    // includes p, p + 4 and p + 6, the encodings 0, 4 and 6 not reduced modulo p), and none of the
    // odd values (which includes p - 4, the negation of 4).
    assert_eq!(
        encodings_near(&IDENTITY_ENCODING, 0..=40),
        [0, 4, 6, 20, 22, 30]
    );
    assert_eq!(encodings_near(&FIELD_MODULUS, -40..=18), [-37, -21, -9, -3]);
    assert_eq!(add_small(&FIELD_MODULUS, -3), LARGEST_ENCODING);
    assert_eq!(encodings_near(&[0xff; 32], -40..=0), [0; 0]);

    // The top bit must be zero.
    for mut bytes in [
        IDENTITY_ENCODING,
        SMALLEST_ENCODING,
        LARGEST_ENCODING,
        GENERATOR_ENCODING,
    ] {
        assert!(check_point(&bytes).is_some());
        bytes[31] |= 0x80;
        assert!(check_point(&bytes).is_none());
    }
}

//
// Hashing tests
//

#[test]
fn hash_regression_tests() {
    // Computed with a Python implementation of RFC 9496: the SHA-512 hash of the input, mapped to a
    // point with the element derivation of RFC 9496, section 4.3.4, or reduced modulo l. The last
    // two inputs give the generator h of Contra's twisted_elgamal.move, which its SDK also derives
    // with @noble/curves, and Hashi's fallback encryption key.
    for (input, point, scalar) in [
        (
            b"Random numbers should not be generated with a method chosen at random".as_slice(),
            hex!("baf5aa3b987469509a11b22d069be0731904af04889790cc6bd54d77afbf871d"),
            hex!("9f07ae34b44b42539e3c45be1da015e10369a454b3ffaec9a7bbe1086b6d170d"),
        ),
        (
            b"fastcrypto-blinding-gen-01",
            hex!("34ce1477c14558178089500a39c864e0f607b3c1f41ab398400e4a9de6d2c446"),
            hex!("b2db737e84539db7d25a5f9c700ae354889bc171e4f4b29ac2f1ba1077f4cf0a"),
        ),
        (
            b"hashi",
            hex!("506167f3b3a9dc97aa59903809275a748f171daeef789f75bd2748ebc626d961"),
            hex!("214f2036daaac404098e98991801c872d8e594d405127ad889d19fc6d8d99f09"),
        ),
    ] {
        assert_eq!(
            RistrettoPoint::hash_to_group_element(input).to_byte_array(),
            point
        );
        assert_eq!(
            RistrettoScalar::hash_to_group_element(input).to_byte_array(),
            scalar
        );
    }
}

#[test]
fn test_hash_to_point() {
    // Test vectors from @noble/curves using the ristretto255_XMD:SHA-512_R255MAP_RO_ suite
    let q128 = [b"q128_".as_slice(), &[b'q'; 127]].concat();
    let a512 = [b"a512_".as_slice(), &[b'a'; 512]].concat();
    for (msg, expected) in [
        (
            b"".as_slice(),
            hex!("d2ef0e42a21c1b4221350ac82ad8669a18a0994df551ac07597a704a23d36436"),
        ),
        (
            b"abc",
            hex!("76a44d9dbe1079e8ca0637f69161de4b76e66d9604fc759c48e13bc5b30adc44"),
        ),
        (
            b"abcdef0123456789",
            hex!("086575a167ff6b9c0bbb90ef9a6c7498838188051f7f1f44db0d492b25b9db02"),
        ),
        (
            &q128,
            hex!("446e5de27a26ea681258dfb38af2ca7ce64aa832768375386372da7a1f92cd24"),
        ),
        (
            &a512,
            hex!("bae7b0ae7e4e19d166ba57965ae3968d09a92c029befe7f96626dbdcdbadce18"),
        ),
    ] {
        assert_eq!(
            RistrettoPoint::hash_to_ristretto255(msg).to_byte_array(),
            expected
        );
    }

    // Other domain separation tags for the message "abc": empty (which RFC 9380 doesn't allow), the
    // longest one that is used as is, and the shortest one that is hashed. Computed with a Python
    // implementation of RFC 9380 and RFC 9496.
    for (dst_length, expected) in [
        (
            0,
            hex!("82f7698fc29fee47d55f3bd6a108884b86311988ef4d31c016152540708e2f20"),
        ),
        (
            255,
            hex!("149921cd3986d4829e2bc32a4c57a6a23387bf7aa811d089d98cea1bc0cd2666"),
        ),
        (
            256,
            hex!("c0924ab5377602af2e9790d3b9b3ac8453482594aa80bb7b077f507ea84ab343"),
        ),
    ] {
        assert_eq!(
            RistrettoPoint::hash_to_ristretto255_with_dst(&[b"abc"], &vec![b'a'; dst_length])
                .to_byte_array(),
            expected
        );
    }
}

#[test]
fn test_fiat_shamir() {
    // The constants of the tests of Contra's Move (nizk.move) and TypeScript (nizk.test.ts) code: the
    // BCS serialization of a list of byte strings, where the points are multiples of G.
    let bytes = |length: u8| (0..length).collect::<Vec<_>>();
    let point = |k: u64| {
        let point = RistrettoPoint::generator() * RistrettoScalar::from(k);
        point.to_byte_array().to_vec()
    };
    for (inputs, expected) in [
        (
            vec![bytes(21), bytes(32)],
            hex!("af00c4976049ed81805c76d3c5ba7cfaeb1550e44f5978cffb12b285a5e25a00"),
        ),
        (
            std::iter::once(bytes(21))
                .chain((1..=6).map(|i| point(11 * i)))
                .collect(),
            hex!("b5baa7c858c0eb740d9c38cc273f2062998dad57a798fa00e78cc33b4ba54200"),
        ),
    ] {
        let msg = bcs::to_bytes(&inputs).unwrap();
        let challenge = RistrettoScalar::fiat_shamir_reduction_to_group_element(&msg);
        assert_eq!(challenge.to_byte_array(), expected);
    }
}

//
// Test vectors
//

#[test]
fn test_vectors() {
    // Test vectors for ristretto255 from RFC 9496 (https://www.rfc-editor.org/rfc/rfc9496.html),
    // which supersedes draft-irtf-cfrg-ristretto255-decaf448-03:
    // - VEC_MULGEN:  Appendix A.1 (multiples of the generator)
    // - VEC_INVALID: Appendix A.2 (invalid encodings)
    // - VEC_MAP:     Appendix A.3 (group elements from uniform byte strings, i.e. from_uniform_bytes)
    const VEC_MULGEN: [[u8; 32]; 16] = [
        hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        hex!("e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"),
        hex!("6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"),
        hex!("94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259"),
        hex!("da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57"),
        hex!("e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e"),
        hex!("f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403"),
        hex!("44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d"),
        hex!("903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c"),
        hex!("02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031"),
        hex!("20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f"),
        hex!("bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42"),
        hex!("e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460"),
        hex!("aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f"),
        hex!("46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e"),
        hex!("e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e"),
    ];

    for (i, expected) in VEC_MULGEN.iter().enumerate() {
        let actual = RistrettoPoint::generator() * RistrettoScalar::from(i as u64);
        assert_eq!(actual.to_byte_array(), *expected);
        assert_eq!(check_point(expected), Some(actual));
        let reference = reference::Point::generator() * reference::Scalar::from(i as u64);
        assert_eq!(reference.encode(), *expected);
        assert!(reference::Point::decode(expected).unwrap() == reference);
    }

    const VEC_INVALID: [[u8; 32]; 29] = [
        // Non-canonical field encodings.
        hex!("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        // Negative field elements.
        hex!("0100000000000000000000000000000000000000000000000000000000000000"),
        hex!("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hex!("ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20"),
        hex!("c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562"),
        hex!("c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78"),
        hex!("47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24"),
        hex!("f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72"),
        hex!("87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309"),
        // Non-square x^2.
        hex!("26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371"),
        hex!("4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f"),
        hex!("de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b"),
        hex!("bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042"),
        hex!("2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08"),
        hex!("f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22"),
        hex!("8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731"),
        hex!("2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b"),
        // Negative xy value.
        hex!("3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e"),
        hex!("a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220"),
        hex!("d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e"),
        hex!("8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32"),
        hex!("32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b"),
        hex!("227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165"),
        hex!("5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e"),
        hex!("445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b"),
        // s = -1, which causes y = 0.
        hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ];

    for bytes in VEC_INVALID.iter() {
        assert!(check_point(bytes).is_none());
    }

    const VEC_MAP: [([u8; 64], [u8; 32]); 11] = [
        (hex!("5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6"),
            hex!("3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46")),
        (hex!("f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38"),
            hex!("f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b")),
        (hex!("8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c"),
            hex!("006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826")),
        (hex!("ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf"),
            hex!("f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a")),
        (hex!("165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413"),
            hex!("ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179")),
        (hex!("a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c"),
            hex!("e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628")),
        (hex!("2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982"),
            hex!("80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065")),
        (hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1200000000000000000000000000000000000000000000000000000000000000"),
            hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f")),
        (hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f")),
        (hex!("0000000000000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f")),
        (hex!("00000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000080"),
            hex!("304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f")),
        ];

    for (bytes, expected) in VEC_MAP.iter() {
        assert_eq!(
            RistrettoPoint::from_uniform_bytes(bytes).to_byte_array(),
            *expected
        );
        assert_eq!(
            reference::Point::from_uniform_bytes(bytes).encode(),
            *expected
        );
    }
    // Zero maps to the identity.
    assert_eq!(
        RistrettoPoint::from_uniform_bytes(&[0; 64]),
        RistrettoPoint::zero()
    );
}

//
// Proptests
//

/// 32-byte little-endian integers: arbitrary ones, even ones below 2^255 (one in four encodes a
/// point), those below 2^252 < l, those near 0, l, p, 2^255 and 2^256, those whose most significant
/// bytes are those of l or p, and encodings of points, unchanged, negated (p - s, which is odd for
/// s != 0), with the top bit set or with another bit flipped.
fn arb_bytes() -> impl Strategy<Value = [u8; 32]> {
    let near = prop_oneof![
        Just([0; 32]),
        Just(GROUP_ORDER),
        Just(FIELD_MODULUS),
        Just(power_of_two(255)),
    ];
    let suffix_of = prop_oneof![Just(GROUP_ORDER), Just(FIELD_MODULUS)];
    // Multiples of G and the encodings on the edges.
    let encodings = consecutive_multiples(16)
        .iter()
        .map(|p| p.to_byte_array())
        .chain([IDENTITY_ENCODING, SMALLEST_ENCODING, LARGEST_ENCODING])
        .collect::<Vec<_>>();
    let encoding = prop::sample::select(encodings);
    prop_oneof![
        any::<[u8; 32]>(),
        any::<[u8; 32]>().prop_map(|mut bytes| {
            bytes[0] &= 0xfe;
            bytes[31] &= 0x7f;
            bytes
        }),
        any::<[u8; 32]>().prop_map(|mut bytes| {
            bytes[31] &= 0x0f;
            bytes
        }),
        (near, -20i64..=20).prop_map(|(bytes, delta)| add_small(&bytes, delta)),
        (suffix_of, 0..=32usize, any::<[u8; 32]>()).prop_map(|(end, length, mut bytes)| {
            bytes[32 - length..].copy_from_slice(&end[32 - length..]);
            bytes
        }),
        encoding.clone(),
        encoding
            .clone()
            .prop_map(|bytes| reference::negate_field_element(&bytes).unwrap()),
        (encoding, prop_oneof![Just(255usize), 0..256usize]).prop_map(|(mut bytes, bit)| {
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        }),
    ]
}

/// Scalars, biased towards edge cases: 0, ±1, 2^k and 2^k - 1 for every k, l - 1, ..., l - 20,
/// integers below 2^64 and arbitrary scalars.
fn arb_scalar() -> impl Strategy<Value = reference::Scalar> {
    let one = reference::Scalar::one();
    prop_oneof![
        prop_oneof![Just(reference::Scalar::zero()), Just(one), Just(-one)],
        (0usize..256).prop_map(|k| reference::reduce_scalar(&power_of_two(k))),
        (0usize..256).prop_map(move |k| reference::reduce_scalar(&power_of_two(k)) - one),
        (1u64..=20).prop_map(|k| -reference::Scalar::from(k)),
        any::<u64>().prop_map(reference::Scalar::from),
        any::<[u8; 32]>().prop_map(|bytes| reference::reduce_scalar(&bytes)),
    ]
}

/// Points, in fastcrypto and in the reference: the identity, ±G, multiples of G by [arb_scalar] and
/// outputs of the one-way map, with any of the four representatives on the curve.
fn arb_point() -> impl Strategy<Value = (RistrettoPoint, reference::Point)> {
    let g = (RistrettoPoint::generator(), reference::Point::generator());
    let point = prop_oneof![
        1 => Just((RistrettoPoint::zero(), reference::Point::identity())),
        1 => prop_oneof![Just(g), Just((-g.0, -g.1))],
        2 => arb_scalar().prop_map(|k| multiple_of_generator(&k)),
        2 => any::<([u8; 32], [u8; 32])>().prop_map(|(a, b)| {
            let bytes = concat(&a, &b);
            (
                RistrettoPoint::from_uniform_bytes(&bytes),
                reference::Point::from_uniform_bytes(&bytes),
            )
        }),
    ];
    (point, 0..4usize).prop_map(|((point, expected), i)| {
        let (zero, expected_zero) = IDENTITY_REPRESENTATIVES[i];
        (point + zero, expected + expected_zero)
    })
}

/// Strategies with bounds around small numbers of points, and the extreme values.
fn arb_strategy() -> impl Strategy<Value = MixedMsmStrategy> {
    (
        prop_oneof![4 => 0..10usize, 1 => Just(usize::MAX)],
        prop_oneof![4 => 0..4usize, 1 => Just(usize::MAX)],
    )
        .prop_map(
            |(max_weighted_points, dynamic_point_weight)| MixedMsmStrategy {
                max_weighted_points,
                dynamic_point_weight,
            },
        )
}

proptest! {
    #[test]
    fn test_decode_adversarial(bytes in arb_bytes(), high in arb_bytes()) {
        check_scalar(&bytes);
        check_point(&bytes);
        let wide = concat(&bytes, &high);
        prop_assert_eq!(
            RistrettoScalar::from_bytes_mod_order_wide(&wide).to_byte_array(),
            reference::encode_scalar(&reference::reduce_scalar(&wide))
        );
    }

    #[test]
    fn test_hashing(
        bytes in arb_bytes(),
        high in arb_bytes(),
        msgs in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..150), 0..4),
        dst in prop_oneof![
            prop::collection::vec(any::<u8>(), 0..40),
            prop::collection::vec(any::<u8>(), 250..260),
        ],
    ) {
        let wide = concat(&bytes, &high);
        prop_assert_eq!(
            RistrettoPoint::from_uniform_bytes(&wide).to_byte_array(),
            reference::Point::from_uniform_bytes(&wide).encode()
        );

        let msg = msgs.concat();
        let slices = msgs.iter().map(|m| m.as_slice()).collect::<Vec<_>>();
        prop_assert_eq!(
            RistrettoPoint::hash_to_ristretto255_with_dst(&slices, &dst).to_byte_array(),
            reference::hash_to_point(&msg, &dst).encode()
        );

        let digest = Sha512::digest(&msg).digest;
        prop_assert_eq!(
            RistrettoPoint::hash_to_group_element(&msg).to_byte_array(),
            reference::Point::from_uniform_bytes(&digest).encode()
        );
        prop_assert_eq!(
            RistrettoScalar::hash_to_group_element(&msg).to_byte_array(),
            reference::encode_scalar(&reference::reduce_scalar(&digest))
        );
        // Challenges are below 2^248.
        let challenge = RistrettoScalar::fiat_shamir_reduction_to_group_element(&msg);
        prop_assert_eq!(challenge.to_byte_array()[31], 0);
    }

    #[test]
    fn test_scalar_arithmetic(a in arb_scalar(), b in arb_scalar()) {
        let (x, y) = (from_reference_scalar(&a), from_reference_scalar(&b));
        let encode = |s: reference::Scalar| reference::encode_scalar(&s);
        prop_assert_eq!((x + y).to_byte_array(), encode(a + b));
        prop_assert_eq!((x - y).to_byte_array(), encode(a - b));
        prop_assert_eq!((x * y).to_byte_array(), encode(a * b));
        prop_assert_eq!((-x).to_byte_array(), encode(-a));
        prop_assert_eq!(x == y, a == b);
        // Inversion and division fail exactly for zero.
        let inverse = b.inverse();
        prop_assert_eq!(y.inverse().ok().map(|s| s.to_byte_array()), inverse.map(encode));
        prop_assert_eq!(
            (x / y).ok().map(|s| s.to_byte_array()),
            inverse.map(|i| encode(a * i))
        );
    }
}

proptest! {
    // Each case does several scalar multiplications.
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn test_group_law((p, expected_p) in arb_point(), (q, expected_q) in arb_point(), s in arb_scalar()) {
        prop_assert_eq!(p.to_byte_array(), expected_p.encode());
        prop_assert_eq!((p + q).to_byte_array(), (expected_p + expected_q).encode());
        prop_assert_eq!((p - q).to_byte_array(), (expected_p - expected_q).encode());
        prop_assert_eq!((-p).to_byte_array(), (-expected_p).encode());
        prop_assert_eq!(p.double().to_byte_array(), (expected_p + expected_p).encode());
        let scalar = from_reference_scalar(&s);
        prop_assert_eq!((p * scalar).to_byte_array(), (expected_p * s).encode());
        // Division fails exactly for s = 0.
        prop_assert_eq!(
            (p / scalar).ok().map(|quotient| quotient.to_byte_array()),
            s.inverse().map(|inverse| (expected_p * inverse).encode())
        );
        // Equality is equality of the encodings, for any representatives.
        for (zero, _) in IDENTITY_REPRESENTATIVES.iter() {
            prop_assert_eq!(p, p + zero);
        }
        prop_assert_eq!(p == q, expected_p == expected_q);
        prop_assert_eq!(p == q, p.to_byte_array() == q.to_byte_array());
        prop_assert_eq!(check_point(&p.to_byte_array()), Some(p));
    }

    #[test]
    fn test_multi_scalar_mul_proptest(
        terms in prop::collection::vec((arb_scalar(), arb_point()), 0..8),
        split in 0..8usize,
        strategy in arb_strategy(),
    ) {
        let expected = terms
            .iter()
            .fold(reference::Point::identity(), |acc, (s, (_, p))| acc + *p * *s)
            .encode();
        let scalars = terms.iter().map(|(s, _)| from_reference_scalar(s)).collect::<Vec<_>>();
        let points = terms.iter().map(|(_, (p, _))| *p).collect::<Vec<_>>();
        let actual = RistrettoPoint::multi_scalar_mul(&scalars, &points).unwrap();
        prop_assert_eq!(actual.to_byte_array(), expected);

        let split = split.min(terms.len());
        let precomputation =
            RistrettoPoint::precompute_with_strategy(&points[..split], strategy).unwrap();
        let actual = precomputation
            .mixed_multi_scalar_mul(&scalars[..split], &scalars[split..], &points[split..])
            .unwrap();
        prop_assert_eq!(actual.to_byte_array(), expected);
    }
}

#[test]
fn test_proptest_strategies_are_not_vacuous() {
    // The strategies hit the edge cases often enough for the 64 cases of the slower proptests.
    const SAMPLES: usize = 1000;
    let mut runner = TestRunner::deterministic();
    let bytes = samples(arb_bytes(), SAMPLES, &mut runner);
    let decoded_scalar = count(&bytes, |b| reference::decode_scalar(b).is_some());
    let near_order = count(&bytes, |b| {
        (-3..=3).any(|delta| *b == add_small(&GROUP_ORDER, delta))
    });
    let decoded_point = count(&bytes, |b| reference::Point::decode(b).is_some());
    let decoded_identity = count(&bytes, |b| *b == IDENTITY_ENCODING);
    // Valid encodings with the top bit set or plus p, which only the canonicity check rejects.
    let without_top_bit = |b: &[u8; 32]| {
        let mut bytes = *b;
        bytes[31] &= 0x7f;
        bytes
    };
    let top_bit = count(&bytes, |b| {
        b[31] & 0x80 != 0 && reference::Point::decode(&without_top_bit(b)).is_some()
    });
    let plus_p = count(&bytes, |b| {
        [0, 4, 6]
            .iter()
            .any(|s| *b == add_small(&FIELD_MODULUS, *s))
    });
    // Negated valid encodings, which only the sign check rejects.
    let negated = count(&bytes, |b| {
        b[0] & 1 == 1
            && reference::negate_field_element(b)
                .is_some_and(|s| reference::Point::decode(&s).is_some())
    });

    let scalars = samples(arb_scalar(), SAMPLES, &mut runner);
    let zero = count(&scalars, |s| s.is_zero());
    let one = reference::Scalar::one();
    let plus_minus_one = count(&scalars, |s| *s == one || *s == -one);

    // Multiplications are slow in debug builds, so fewer points are sampled.
    let points = samples(arb_point(), SAMPLES / 5, &mut runner);
    let identity = count(&points, |(p, _)| *p == RistrettoPoint::zero());
    let other_representative = count(&points, |(_, p)| {
        let decoded = reference::Point::decode(&p.encode()).unwrap();
        !decoded.is_same_representative(p)
    });

    println!(
        "32 bytes: scalar {decoded_scalar}, l - 3..l + 3 {near_order}, point {decoded_point}, \
         identity {decoded_identity}, top bit {top_bit}, plus p {plus_p}, negated {negated}; \
         scalars: zero {zero}, ±1 {plus_minus_one}; points (of {}): identity {identity}, other \
         representative {other_representative}",
        SAMPLES / 5
    );
    assert!(decoded_scalar > 200 && SAMPLES - decoded_scalar > 200);
    assert!(near_order > 5);
    assert!(decoded_point > 150 && SAMPLES - decoded_point > 150);
    assert!(decoded_identity > 5 && top_bit > 20 && plus_p > 0 && negated > 50);
    assert!(zero > 20 && plus_minus_one > 40);
    assert!(identity > 10 && other_representative > 50);
}
