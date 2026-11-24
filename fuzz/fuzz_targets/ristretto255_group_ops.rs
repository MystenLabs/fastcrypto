// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Runs sequences of operations on the scalars and points of `groups::ristretto255` and compares
//! every result with a reference written from RFC 9496 on arkworks' field arithmetic, which shares
//! no code with curve25519-dalek. Values enter through every decoder (also through BCS and JSON),
//! the reductions modulo the group order l, the one-way map and the hash functions, from arbitrary
//! bytes, from values near l and p, or from the encoding of an earlier point, negated or with a
//! byte changed. Operands are earlier results, so the sequences reach the identity, ±G, repeated
//! and negated points and the scalars 0 and ±1. Decoding the encoding of an earlier point gives
//! another representative of the same element on the curve.
//!
//! Invariants: nothing panics; each decoder accepts exactly the encodings that the reference
//! accepts, decodes to the same value and round trips, and BCS and JSON agree with it; the trusted
//! decoder agrees for points and reduces scalars; inversion and division fail exactly for zero;
//! multi-scalar multiplication, with and without precomputed tables, fails exactly for mismatched
//! lengths and gives the same result for every strategy; equal points have equal encodings; every
//! result equals the reference's.

#![no_main]

#[allow(dead_code)]
#[path = "../../fastcrypto/src/tests/ristretto255_reference.rs"]
mod ristretto255_reference;

use arbitrary::Arbitrary;
use ark_ff::{Field, One, Zero};
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::groups::ristretto255::{MixedMsmStrategy, RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{
    Doubling, FiatShamirChallenge, FromTrustedByteArray, GroupElement, HashToGroupElement,
    MixedMultiScalarMul, MultiScalarMul, Scalar as _,
};
use fastcrypto::serde_helpers::ToFromByteArray;
use libfuzzer_sys::fuzz_target;
use ristretto255_reference::{
    add_small, concat, decode_scalar, encode_scalar, hash_to_point, negate_field_element,
    reduce_scalar, Point, Scalar, FIELD_MODULUS, GROUP_ORDER,
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha512};
use std::fmt::Debug;

/// Bounds the work per input.
const MAX_OPS: usize = 32;
/// The largest number of terms of a multi-scalar multiplication.
const MAX_TERMS: usize = 8;
/// Bounds the length of domain separation tags. Those longer than 255 bytes are hashed.
const MAX_DST_LENGTH: usize = 300;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Little-endian, through every decoder of scalars.
    ScalarFromBytes([u8; 32]),
    /// l + d: decoding rejects d >= 0.
    ScalarNearOrder(i8),
    /// 64 bytes, reduced modulo l.
    ScalarFromWideBytes([u8; 32], [u8; 32]),
    ScalarFromU128(u128),
    /// The hash of a message to a scalar and to a Fiat-Shamir challenge.
    ScalarFromMessage(Vec<u8>),
    /// Through every decoder of points.
    PointFromBytes([u8; 32]),
    /// p + d: decoding rejects d >= 0, and accepts for example d = -3 and d = -9.
    PointNearModulus(i8),
    /// The encoding of an earlier point (by index), negated: decoding rejects all but the identity.
    PointFromNegatedBytes(u8),
    /// The encoding of an earlier point (by index) with a byte (by index) xored.
    PointFromChangedBytes(u8, u8, u8),
    /// The encoding of an earlier point (by index), decoded again.
    PointFromEncoding(u8),
    /// The one-way map.
    PointFromUniformBytes([u8; 32], [u8; 32]),
    /// hash_to_ristretto255 of a message, split at an index, with a domain separation tag that is
    /// repeated up to a length below [MAX_DST_LENGTH].
    PointFromMessage(Vec<u8>, u8, Vec<u8>, u16),
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
    /// The sum of (scalar index, point index) terms.
    MultiScalarMul(Vec<(u8, u8)>, Msm),
}

#[derive(Arbitrary, Debug)]
enum Msm {
    Plain {
        drop_last: bool,
    },
    /// The points before the split are precomputed, and the scalars are split `shift` later (so the
    /// lengths match for 0). The bound and the weight of the strategy are u8::MAX for usize::MAX.
    Precomputed {
        split: u8,
        shift: i8,
        max_weighted_points: u8,
        dynamic_point_weight: u8,
    },
}

/// Every value in fastcrypto and in the reference.
struct State {
    scalars: Vec<(RistrettoScalar, Scalar)>,
    points: Vec<(RistrettoPoint, Point)>,
}

impl State {
    fn new() -> Self {
        let one = RistrettoScalar::generator();
        let g = RistrettoPoint::generator();
        let expected_g = Point::generator();
        Self {
            scalars: vec![
                (RistrettoScalar::zero(), Scalar::zero()),
                (one, Scalar::one()),
                (-one, -Scalar::one()),
            ],
            points: vec![
                (RistrettoPoint::zero(), Point::identity()),
                (g, expected_g),
                (-g, -expected_g),
            ],
        }
    }

    fn scalar(&self, index: u8) -> (RistrettoScalar, Scalar) {
        self.scalars[index as usize % self.scalars.len()]
    }

    fn point(&self, index: u8) -> (RistrettoPoint, Point) {
        self.points[index as usize % self.points.len()]
    }

    fn push_scalar(&mut self, scalar: RistrettoScalar, expected: Scalar) {
        assert_eq!(scalar.to_byte_array(), encode_scalar(&expected));
        self.scalars.push((scalar, expected));
    }

    fn push_point(&mut self, point: RistrettoPoint, expected: Point) {
        assert_eq!(point.to_byte_array(), expected.encode());
        self.points.push((point, expected));
    }

    fn decode_point(&mut self, bytes: &[u8; 32]) {
        let decoded = decode::<RistrettoPoint>(bytes);
        assert_eq!(RistrettoPoint::from_trusted_byte_array(bytes).ok(), decoded);
        let expected = Point::decode(bytes);
        assert_eq!(decoded.is_some(), expected.is_some());
        if let (Some(point), Some(expected)) = (decoded, expected) {
            assert_eq!(point.to_byte_array(), *bytes);
            self.push_point(point, expected);
        }
    }

    fn decode_scalar(&mut self, bytes: &[u8; 32]) {
        let decoded = decode::<RistrettoScalar>(bytes);
        let expected = decode_scalar(bytes);
        assert_eq!(decoded.is_some(), expected.is_some());
        if let Some(scalar) = decoded {
            assert_eq!(scalar.to_byte_array(), *bytes);
        }
        let reduced = RistrettoScalar::from_bytes_mod_order(bytes);
        assert_eq!(
            RistrettoScalar::from_trusted_byte_array(bytes).unwrap(),
            reduced
        );
        self.push_scalar(reduced, reduce_scalar(bytes));
    }
}

/// Decodes through `from_byte_array`, BCS and JSON, which must agree.
fn decode<T: ToFromByteArray<32> + DeserializeOwned + PartialEq + Debug>(
    bytes: &[u8; 32],
) -> Option<T> {
    let decoded = T::from_byte_array(bytes).ok();
    assert_eq!(bcs::from_bytes::<T>(bytes).ok(), decoded);
    let json = serde_json::to_string(&Base64::encode(bytes)).unwrap();
    assert_eq!(serde_json::from_str::<T>(&json).ok(), decoded);
    decoded
}

fn multi_scalar_mul(state: &mut State, terms: &[(u8, u8)], msm: Msm) {
    let terms = &terms[..terms.len().min(MAX_TERMS)];
    let mut scalars = terms
        .iter()
        .map(|(s, _)| state.scalar(*s).0)
        .collect::<Vec<_>>();
    let points = terms
        .iter()
        .map(|(_, p)| state.point(*p).0)
        .collect::<Vec<_>>();
    let expected = terms.iter().fold(Point::identity(), |acc, (s, p)| {
        acc + state.point(*p).1 * state.scalar(*s).1
    });
    let result = match msm {
        Msm::Plain { drop_last } => {
            let mismatch = drop_last && scalars.pop().is_some();
            let result = RistrettoPoint::multi_scalar_mul(&scalars, &points);
            assert_eq!(result.is_err(), mismatch);
            result
        }
        Msm::Precomputed {
            split,
            shift,
            max_weighted_points,
            dynamic_point_weight,
        } => {
            let extend = |x: u8| if x == u8::MAX { usize::MAX } else { x.into() };
            let strategy = MixedMsmStrategy {
                max_weighted_points: extend(max_weighted_points),
                dynamic_point_weight: extend(dynamic_point_weight),
            };
            let split = split as usize % (terms.len() + 1);
            let scalar_split = split.saturating_add_signed(shift.into()).min(terms.len());
            let (static_points, dynamic_points) = points.split_at(split);
            let (static_scalars, dynamic_scalars) = scalars.split_at(scalar_split);
            let result = RistrettoPoint::precompute_with_strategy(static_points, strategy)
                .unwrap()
                .mixed_multi_scalar_mul(static_scalars, dynamic_scalars, dynamic_points);
            assert_eq!(result.is_err(), split != scalar_split);
            result
        }
    };
    if let Ok(result) = result {
        state.push_point(result, expected);
    }
}

fn apply(state: &mut State, op: Op) {
    match op {
        Op::ScalarFromBytes(bytes) => state.decode_scalar(&bytes),
        Op::ScalarNearOrder(delta) => state.decode_scalar(&add_small(&GROUP_ORDER, delta.into())),
        Op::ScalarFromWideBytes(low, high) => {
            let bytes = concat(&low, &high);
            state.push_scalar(
                RistrettoScalar::from_bytes_mod_order_wide(&bytes),
                reduce_scalar(&bytes),
            );
        }
        Op::ScalarFromU128(value) => {
            state.push_scalar(RistrettoScalar::from(value), Scalar::from(value));
        }
        Op::ScalarFromMessage(msg) => {
            let expected = reduce_scalar(&Sha512::digest(&msg));
            state.push_scalar(RistrettoScalar::hash_to_group_element(&msg), expected);
            let challenge = RistrettoScalar::fiat_shamir_reduction_to_group_element(&msg);
            assert_eq!(challenge.to_byte_array()[31], 0);
        }
        Op::PointFromBytes(bytes) => state.decode_point(&bytes),
        Op::PointNearModulus(delta) => {
            state.decode_point(&add_small(&FIELD_MODULUS, delta.into()));
        }
        Op::PointFromNegatedBytes(p) => {
            let bytes = state.point(p).0.to_byte_array();
            state.decode_point(&negate_field_element(&bytes).unwrap());
        }
        Op::PointFromChangedBytes(p, index, xor) => {
            let mut bytes = state.point(p).0.to_byte_array();
            bytes[index as usize % 32] ^= xor;
            state.decode_point(&bytes);
        }
        Op::PointFromEncoding(p) => {
            let (point, _) = state.point(p);
            state.decode_point(&point.to_byte_array());
            assert_eq!(state.points.last().unwrap().0, point);
        }
        Op::PointFromUniformBytes(low, high) => {
            let bytes = concat(&low, &high);
            state.push_point(
                RistrettoPoint::from_uniform_bytes(&bytes),
                Point::from_uniform_bytes(&bytes),
            );
        }
        Op::PointFromMessage(msg, split, dst, dst_length) => {
            let dst_length = dst_length as usize % MAX_DST_LENGTH;
            let dst = dst.into_iter().cycle().take(dst_length).collect::<Vec<_>>();
            let (start, end) = msg.split_at(split as usize % (msg.len() + 1));
            state.push_point(
                RistrettoPoint::hash_to_ristretto255_with_dst(&[start, end], &dst),
                hash_to_point(&msg, &dst),
            );
            let expected = Point::from_uniform_bytes(&Sha512::digest(&msg).into());
            state.push_point(RistrettoPoint::hash_to_group_element(&msg), expected);
        }
        Op::ScalarAdd(a, b) => {
            let ((x, ex), (y, ey)) = (state.scalar(a), state.scalar(b));
            assert_eq!(x == y, ex == ey);
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
            let inverse = ey.inverse();
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
            assert_eq!(p == q, p.to_byte_array() == q.to_byte_array());
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
            state.push_point(p.double(), ep + ep);
        }
        Op::Mul(a, s) => {
            let ((p, ep), (x, ex)) = (state.point(a), state.scalar(s));
            state.push_point(p * x, ep * ex);
        }
        Op::Div(a, s) => {
            let ((p, ep), (x, ex)) = (state.point(a), state.scalar(s));
            match (p / x, ex.inverse()) {
                (Ok(quotient), Some(inverse)) => state.push_point(quotient, ep * inverse),
                (Err(_), None) => {}
                _ => panic!("division and inversion disagree"),
            }
        }
        Op::MultiScalarMul(terms, msm) => multi_scalar_mul(state, &terms, msm),
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let mut state = State::new();
    for op in ops.into_iter().take(MAX_OPS) {
        apply(&mut state, op);
    }
});
