// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Runs sequences of operations on the scalars and points of `groups::secp256k1`, the group of
//! threshold Schnorr in fastcrypto-threshold, and compares every result with k256, an independent
//! implementation. Values enter through every decoder: the arkworks point encoding (also through
//! BCS and JSON), SEC1, x-only, big-endian scalars and reduction modulo n, from arbitrary bytes,
//! from values near n and p, or from the encoding of an earlier point with a byte changed.
//! Operands are earlier results, so the sequences reach the identity, ±G, repeated and negated
//! points and the scalars 0 and ±1.
//!
//! Invariants: nothing panics; each decoder accepts exactly the encodings that k256 (or the
//! canonical arkworks encoding computed from k256's coordinates) accepts, decodes to the same value
//! and round trips, and BCS and JSON agree with it; inversion and division fail exactly for zero;
//! multi-scalar multiplication fails exactly for mismatched lengths; every result equals k256's.

#![no_main]

#[path = "secp256k1_group_common.rs"]
mod secp256k1_group_common;

use arbitrary::Arbitrary;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::groups::secp256k1::{ProjectivePoint, Scalar};
use fastcrypto::groups::{Doubling, GroupElement, MultiScalarMul, Scalar as _};
use fastcrypto::serde_helpers::ToFromByteArray;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, U256};
use libfuzzer_sys::fuzz_target;
use secp256k1_group_common::{add_small, FIELD_MODULUS, GROUP_ORDER};

/// Bounds the work per input.
const MAX_OPS: usize = 32;
/// The largest number of terms of `MultiScalarMul`.
const MAX_TERMS: usize = 8;

/// The arkworks encoding of the identity.
const IDENTITY_ENCODING: [u8; 33] =
    hex_literal::hex!("000000000000000000000000000000000000000000000000000000000000000040");

#[derive(Arbitrary, Debug)]
enum Op {
    /// Big-endian, as `Scalar::from_byte_array` decodes it.
    ScalarFromBytes([u8; 32]),
    /// Big-endian of any length, reduced modulo n.
    ScalarFromBytesModOrder(Vec<u8>),
    ScalarFromU128(u128),
    /// n + d, big-endian: decoding rejects d >= 0.
    ScalarNearOrder(i8),
    /// The arkworks encoding: x little-endian and a flag byte.
    PointFromBytes([u8; 32], u8),
    /// The arkworks encoding of an earlier point (by index) with a byte (by index) xored.
    PointFromChangedBytes(u8, u8, u8),
    /// SEC1: a tag and x big-endian.
    PointFromSec1(u8, [u8; 32]),
    /// x big-endian, lifted to the point with an even y.
    PointFromX([u8; 32]),
    /// x = p + d (so x >= p for d >= 0, and x = p - 3 is on the curve) in the arkworks encoding
    /// (0), SEC1 (1) or x-only (2), with a large or odd y if the flag is set.
    PointNearModulus(i8, u8, bool),
    /// The indices are taken modulo the number of scalars or points.
    ScalarAdd(u8, u8),
    ScalarSub(u8, u8),
    ScalarMul(u8, u8),
    ScalarNeg(u8),
    ScalarDiv(u8, u8),
    PointAdd(u8, u8),
    PointSub(u8, u8),
    PointNeg(u8),
    PointDouble(u8),
    /// point * scalar, with a point index and a scalar index.
    Mul(u8, u8),
    /// point / scalar, with a point index and a scalar index.
    Div(u8, u8),
    /// `multi_scalar_mul` of (scalar index, point index) terms, with the last scalar dropped if
    /// the flag is set.
    MultiScalarMul(Vec<(u8, u8)>, bool),
    /// Compare the encodings of a point with k256.
    Encode(u8),
}

/// Every value in fastcrypto and in k256.
struct State {
    scalars: Vec<(Scalar, k256::Scalar)>,
    points: Vec<(ProjectivePoint, k256::ProjectivePoint)>,
}

impl State {
    fn new() -> Self {
        let g = ProjectivePoint::generator();
        let expected_g = k256::ProjectivePoint::GENERATOR;
        Self {
            scalars: vec![
                (Scalar::zero(), k256::Scalar::ZERO),
                (Scalar::generator(), k256::Scalar::ONE),
                (-Scalar::generator(), -k256::Scalar::ONE),
            ],
            points: vec![
                (ProjectivePoint::zero(), k256::ProjectivePoint::IDENTITY),
                (g, expected_g),
                (-g, -expected_g),
            ],
        }
    }

    fn scalar(&self, index: u8) -> (Scalar, k256::Scalar) {
        self.scalars[index as usize % self.scalars.len()]
    }

    fn point(&self, index: u8) -> (ProjectivePoint, k256::ProjectivePoint) {
        self.points[index as usize % self.points.len()]
    }

    fn push_scalar(&mut self, scalar: Scalar, expected: k256::Scalar) {
        assert_eq!(
            scalar.to_byte_array(),
            <[u8; 32]>::from(expected.to_bytes())
        );
        self.scalars.push((scalar, expected));
    }

    fn push_point(&mut self, point: ProjectivePoint, expected: k256::ProjectivePoint) {
        assert_eq!(point.to_byte_array(), expected_encoding(&expected));
        self.points.push((point, expected));
    }

    /// Decodes an arkworks encoding through `from_byte_array`, BCS and JSON, and keeps the point.
    fn decode_point(&mut self, bytes: &[u8; 33]) {
        let decoded = ProjectivePoint::from_byte_array(bytes);
        let expected = decode_with_k256(bytes);
        assert_eq!(decoded.is_ok(), expected.is_some());
        assert_eq!(
            bcs::from_bytes::<ProjectivePoint>(bytes).ok(),
            decoded.clone().ok()
        );
        let json = serde_json::to_string(&Base64::encode(bytes)).unwrap();
        assert_eq!(
            serde_json::from_str::<ProjectivePoint>(&json).ok(),
            decoded.clone().ok()
        );
        if let (Ok(point), Some(expected)) = (decoded, expected) {
            assert_eq!(point.to_byte_array(), *bytes);
            self.push_point(point, expected);
        }
    }
}

/// The arkworks encoding of a k256 point: x little-endian followed by 0x80 iff y > p - y.
fn expected_encoding(point: &k256::ProjectivePoint) -> [u8; 33] {
    let encoded = point.to_affine().to_encoded_point(false);
    let (Some(x), Some(y)) = (encoded.x(), encoded.y()) else {
        return IDENTITY_ENCODING;
    };
    let y = U256::from_be_slice(y);
    let mut bytes = [0; 33];
    bytes[..32].copy_from_slice(x);
    bytes[..32].reverse();
    if y > U256::from_be_slice(&FIELD_MODULUS).wrapping_sub(&y) {
        bytes[32] = 0x80;
    }
    bytes
}

/// The point with the given SEC1 compressed encoding, by k256. k256 also accepts the 0x05 tag,
/// which SEC1 doesn't define, so only 0x02 and 0x03 are passed on.
fn decode_sec1_with_k256(tag: u8, x: &[u8; 32]) -> Option<k256::ProjectivePoint> {
    if tag != 0x02 && tag != 0x03 {
        return None;
    }
    let mut bytes = [tag; 33];
    bytes[1..].copy_from_slice(x);
    let point = AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(bytes).ok()?);
    Option::<AffinePoint>::from(point).map(Into::into)
}

/// The point that the arkworks encoding canonically encodes, if any, by decompressing x with k256
/// and comparing with [expected_encoding].
fn decode_with_k256(bytes: &[u8; 33]) -> Option<k256::ProjectivePoint> {
    if *bytes == IDENTITY_ENCODING {
        return Some(k256::ProjectivePoint::IDENTITY);
    }
    let mut x: [u8; 32] = bytes[..32].try_into().unwrap();
    x.reverse();
    let point = decode_sec1_with_k256(0x02, &x)?;
    [point, -point]
        .into_iter()
        .find(|p| expected_encoding(p) == *bytes)
}

fn apply(state: &mut State, op: Op) {
    match op {
        Op::ScalarFromBytes(bytes) => {
            let decoded = Scalar::from_byte_array(&bytes);
            let expected = Option::<k256::Scalar>::from(k256::Scalar::from_repr(bytes.into()));
            assert_eq!(decoded.is_ok(), expected.is_some());
            assert_eq!(bcs::from_bytes::<Scalar>(&bytes).ok(), decoded.clone().ok());
            if let (Ok(scalar), Some(expected)) = (decoded, expected) {
                state.push_scalar(scalar, expected);
            }
        }
        Op::ScalarFromBytesModOrder(bytes) => {
            let expected = bytes.iter().fold(k256::Scalar::ZERO, |acc, byte| {
                acc * k256::Scalar::from(256u64) + k256::Scalar::from(*byte as u64)
            });
            state.push_scalar(Scalar::from_bytes_mod_order(&bytes), expected);
        }
        Op::ScalarFromU128(value) => {
            let expected = k256::Scalar::from((value >> 64) as u64)
                * k256::Scalar::from(1u64 << 32)
                * k256::Scalar::from(1u64 << 32)
                + k256::Scalar::from(value as u64);
            state.push_scalar(Scalar::from(value), expected);
        }
        Op::ScalarNearOrder(delta) => {
            apply(state, Op::ScalarFromBytes(add_small(&GROUP_ORDER, delta)));
        }
        Op::PointNearModulus(delta, encoding, flag) => {
            let x = add_small(&FIELD_MODULUS, delta);
            let op = match encoding % 3 {
                0 => {
                    let mut little_endian = x;
                    little_endian.reverse();
                    Op::PointFromBytes(little_endian, if flag { 0x80 } else { 0x00 })
                }
                1 => Op::PointFromSec1(if flag { 0x03 } else { 0x02 }, x),
                _ => Op::PointFromX(x),
            };
            apply(state, op);
        }
        Op::PointFromBytes(x, flag) => {
            let mut bytes = [flag; 33];
            bytes[..32].copy_from_slice(&x);
            state.decode_point(&bytes);
        }
        Op::PointFromChangedBytes(p, index, xor) => {
            let mut bytes = state.point(p).0.to_byte_array();
            bytes[index as usize % 33] ^= xor;
            state.decode_point(&bytes);
        }
        Op::PointFromSec1(tag, x) => {
            let mut bytes = [tag; 33];
            bytes[1..].copy_from_slice(&x);
            let decoded = ProjectivePoint::from_sec1_bytes(&bytes);
            let expected = decode_sec1_with_k256(tag, &x);
            assert_eq!(decoded.is_ok(), expected.is_some());
            if let (Ok(point), Some(expected)) = (decoded, expected) {
                assert_eq!(point.to_sec1_bytes().unwrap(), bytes);
                state.push_point(point, expected);
            }
        }
        Op::PointFromX(x) => {
            let decoded = ProjectivePoint::with_even_y_from_x_be_bytes(&x);
            let expected = decode_sec1_with_k256(0x02, &x);
            assert_eq!(decoded.is_ok(), expected.is_some());
            if let (Ok(point), Some(expected)) = (decoded, expected) {
                assert_eq!(point.x_as_be_bytes().unwrap(), x);
                assert!(point.has_even_y().unwrap());
                state.push_point(point, expected);
            }
        }
        Op::ScalarAdd(a, b) => {
            let ((x, ex), (y, ey)) = (state.scalar(a), state.scalar(b));
            state.push_scalar(x + y, ex + ey);
        }
        Op::ScalarSub(a, b) => {
            let ((x, ex), (y, ey)) = (state.scalar(a), state.scalar(b));
            state.push_scalar(x - y, ex - ey);
        }
        Op::ScalarMul(a, b) => {
            let ((x, ex), (y, ey)) = (state.scalar(a), state.scalar(b));
            state.push_scalar(x * y, ex * ey);
        }
        Op::ScalarNeg(a) => {
            let (x, ex) = state.scalar(a);
            state.push_scalar(-x, -ex);
        }
        Op::ScalarDiv(a, b) => {
            let ((x, ex), (y, ey)) = (state.scalar(a), state.scalar(b));
            let inverse = Option::<k256::Scalar>::from(ey.invert());
            assert_eq!(y.inverse().is_ok(), inverse.is_some());
            match (x / y, inverse) {
                (Ok(quotient), Some(inverse)) => state.push_scalar(quotient, ex * inverse),
                (Err(_), None) => {}
                _ => panic!("division and inversion disagree"),
            }
        }
        Op::PointAdd(a, b) => {
            let ((p, ep), (q, eq)) = (state.point(a), state.point(b));
            assert_eq!(p == q, ep == eq);
            state.push_point(p + q, ep + eq);
        }
        Op::PointSub(a, b) => {
            let ((p, ep), (q, eq)) = (state.point(a), state.point(b));
            state.push_point(p - q, ep - eq);
        }
        Op::PointNeg(a) => {
            let (p, ep) = state.point(a);
            state.push_point(-p, -ep);
        }
        Op::PointDouble(a) => {
            let (p, ep) = state.point(a);
            state.push_point(p.double(), ep.double());
        }
        Op::Mul(a, s) => {
            let ((p, ep), (x, ex)) = (state.point(a), state.scalar(s));
            state.push_point(p * x, ep * ex);
        }
        Op::Div(a, s) => {
            let ((p, ep), (x, ex)) = (state.point(a), state.scalar(s));
            match (p / x, Option::<k256::Scalar>::from(ex.invert())) {
                (Ok(quotient), Some(inverse)) => state.push_point(quotient, ep * inverse),
                (Err(_), None) => {}
                _ => panic!("division and inversion disagree"),
            }
        }
        Op::MultiScalarMul(terms, drop_last) => {
            let terms = &terms[..terms.len().min(MAX_TERMS)];
            let mut scalars = terms
                .iter()
                .map(|(s, _)| state.scalar(*s).0)
                .collect::<Vec<_>>();
            let points = terms
                .iter()
                .map(|(_, p)| state.point(*p).0)
                .collect::<Vec<_>>();
            let expected = terms
                .iter()
                .map(|(s, p)| state.point(*p).1 * state.scalar(*s).1)
                .sum::<k256::ProjectivePoint>();
            if drop_last && scalars.pop().is_some() {
                assert!(ProjectivePoint::multi_scalar_mul(&scalars, &points).is_err());
            } else {
                let result = ProjectivePoint::multi_scalar_mul(&scalars, &points).unwrap();
                state.push_point(result, expected);
            }
        }
        Op::Encode(a) => {
            let (p, ep) = state.point(a);
            let sec1 = ep.to_affine().to_encoded_point(true);
            match sec1.x() {
                None => {
                    assert!(p.is_zero());
                    assert!(p.to_sec1_bytes().is_err());
                    assert!(p.x_as_be_bytes().is_err());
                    assert!(p.has_even_y().is_err());
                }
                Some(x) => {
                    assert!(!p.is_zero());
                    assert_eq!(&p.to_sec1_bytes().unwrap()[..], sec1.as_bytes());
                    assert_eq!(&p.x_as_be_bytes().unwrap()[..], &x[..]);
                    assert_eq!(p.has_even_y().unwrap(), sec1.as_bytes()[0] == 0x02);
                }
            }
            let bytes = p.to_byte_array();
            assert_eq!(bcs::to_bytes(&p).unwrap(), bytes);
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(serde_json::from_str::<ProjectivePoint>(&json).unwrap(), p);
        }
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let mut state = State::new();
    for op in ops.into_iter().take(MAX_OPS) {
        apply(&mut state, op);
    }
});
