// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// THIS FILE IS AI-ONLY

//! Runs sequences of operations on secp256r1 scalars and points with the arithmetic under
//! fastcrypto's ECDSA, `groups::secp256r1` and the windowed scalar multiplier, and compares every
//! result with p256, an independent implementation. ECDSA verification and recovery compute
//! u1 * G + u2 * Q with `two_scalar_mul`, where the signer controls u1, u2 and Q. Here the operands
//! are earlier results, so the sequences reach the identity, ±G, repeated and negated points and
//! the scalars 0 and ±1. The multipliers use the parameters of ECDSA and others, with windows of 1
//! to 10 bits.
//!
//! Invariants: nothing panics; scalar decoding accepts exactly the big-endian encodings of the
//! values below n, round trips and agrees with BCS; inversion and division fail exactly for zero;
//! every result equals p256's.

#![no_main]

use arbitrary::Arbitrary;
use ark_ff::PrimeField;
use fastcrypto::groups::multiplier::windowed::{multi_scalar_mul, WindowedScalarMultiplier};
use fastcrypto::groups::multiplier::{ScalarMultiplier, ToLittleEndianBytes};
use fastcrypto::groups::secp256r1::{ProjectivePoint, Scalar};
use fastcrypto::groups::{Doubling, GroupElement, Scalar as _};
use fastcrypto::secp256r1::{PRECOMPUTED_POINTS, SLIDING_WINDOW_WIDTH};
use fastcrypto::serde_helpers::ToFromByteArray;
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::{Group, PrimeField as _};
use std::array::from_fn;
use std::collections::HashMap;

/// Bounds the work per input.
const MAX_OPS: usize = 32;
/// The largest number of terms of `MultiScalarMul`.
const MAX_TERMS: usize = 4;

/// The parameters (cache size, sliding window width) of a multiplier.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Parameters {
    /// The multiplier of ECDSA in fastcrypto::secp256r1.
    Ecdsa,
    /// 1-bit windows for both scalars of `two_scalar_mul`.
    Cache2Window1,
    Cache4Window2,
    Cache32Window3,
    Cache1024Window9,
}

type Multiplier<const CACHE_SIZE: usize, const WINDOW: usize> =
    WindowedScalarMultiplier<ProjectivePoint, Scalar, CACHE_SIZE, WINDOW>;

fn with_generator<const CACHE_SIZE: usize, const WINDOW: usize>() -> Multiplier<CACHE_SIZE, WINDOW>
{
    Multiplier::new(ProjectivePoint::generator(), ProjectivePoint::zero())
}

static ECDSA: Lazy<Multiplier<PRECOMPUTED_POINTS, SLIDING_WINDOW_WIDTH>> =
    Lazy::new(with_generator);
static CACHE_2_WINDOW_1: Lazy<Multiplier<2, 1>> = Lazy::new(with_generator);
static CACHE_4_WINDOW_2: Lazy<Multiplier<4, 2>> = Lazy::new(with_generator);
static CACHE_32_WINDOW_3: Lazy<Multiplier<32, 3>> = Lazy::new(with_generator);
static CACHE_1024_WINDOW_9: Lazy<Multiplier<1024, 9>> = Lazy::new(with_generator);

#[derive(Arbitrary, Debug)]
enum Op {
    ScalarFromBytes([u8; 32]),
    ScalarFromU128(u128),
    /// 2^(k mod 257) - (d mod 4): leading zero windows, and scalars at window boundaries.
    PowerOfTwoMinus(u16, u8),
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
    /// `mul` of a multiplier with the point as its base, with a point index and a scalar index.
    MultiplierMul(Parameters, u8, u8),
    /// `two_scalar_mul(u1, Q, u2)` of a multiplier with the generator as its base, as in ECDSA,
    /// with the indices of u1, Q and u2.
    TwoScalarMul(Parameters, u8, u8, u8),
    /// `multi_scalar_mul` of (scalar index, point index) terms, with the default window width and
    /// an optional precomputed table (term index, window width).
    MultiScalarMul(Vec<(u8, u8)>, u8, Option<(u8, u8)>),
}

/// Every value in fastcrypto and in p256.
struct State {
    scalars: Vec<(Scalar, p256::Scalar)>,
    points: Vec<(ProjectivePoint, p256::ProjectivePoint)>,
}

impl State {
    fn new() -> Self {
        let g = ProjectivePoint::generator();
        let expected_g = p256::ProjectivePoint::GENERATOR;
        Self {
            scalars: vec![
                (Scalar::zero(), p256::Scalar::ZERO),
                (Scalar::generator(), p256::Scalar::ONE),
                (-Scalar::generator(), -p256::Scalar::ONE),
            ],
            points: vec![
                (ProjectivePoint::zero(), p256::ProjectivePoint::IDENTITY),
                (g, expected_g),
                (-g, -expected_g),
            ],
        }
    }

    fn scalar(&self, index: u8) -> (Scalar, p256::Scalar) {
        self.scalars[index as usize % self.scalars.len()]
    }

    fn point(&self, index: u8) -> (ProjectivePoint, p256::ProjectivePoint) {
        self.points[index as usize % self.points.len()]
    }

    fn push_scalar(&mut self, scalar: Scalar, expected: p256::Scalar) {
        check_scalar(&scalar, &expected);
        self.scalars.push((scalar, expected));
    }

    fn push_point(&mut self, point: ProjectivePoint, expected: p256::ProjectivePoint) {
        check_point(&point, &expected);
        self.points.push((point, expected));
    }
}

/// Checks a scalar against p256 through its big-endian encoding, and the little-endian bytes that
/// the multipliers read.
fn check_scalar(scalar: &Scalar, expected: &p256::Scalar) {
    let big_endian = <[u8; 32]>::from(expected.to_bytes());
    assert_eq!(scalar.to_byte_array(), big_endian);
    let mut little_endian = big_endian;
    little_endian.reverse();
    assert_eq!(scalar.to_le_bytes(), little_endian);
}

/// Checks a point against p256 through its affine coordinates.
fn check_point(point: &ProjectivePoint, expected: &p256::ProjectivePoint) {
    let expected = expected.to_affine().to_encoded_point(false);
    let converted = match (expected.x(), expected.y()) {
        (Some(x), Some(y)) => {
            ProjectivePoint::from(ark_secp256r1::Projective::from(ark_secp256r1::Affine::new(
                ark_secp256r1::Fq::from_be_bytes_mod_order(x),
                ark_secp256r1::Fq::from_be_bytes_mod_order(y),
            )))
        }
        _ => ProjectivePoint::zero(),
    };
    assert_eq!(*point, converted);
}

fn from_p256_scalar(scalar: &p256::Scalar) -> Scalar {
    Scalar::from_byte_array(&scalar.to_bytes().into()).expect("a scalar below n does not decode")
}

fn mul_with_base<const CACHE_SIZE: usize, const WINDOW: usize>(
    base: ProjectivePoint,
    scalar: &Scalar,
) -> ProjectivePoint {
    Multiplier::<CACHE_SIZE, WINDOW>::new(base, ProjectivePoint::zero()).mul(scalar)
}

/// The table that `multi_scalar_mul` expects for a window of the given width:
/// 2^(width - 1) * point, ..., (2^width - 1) * point.
fn precomputed_multiples(point: &ProjectivePoint, width: usize) -> Vec<ProjectivePoint> {
    let mut multiples = vec![point.repeated_doubling(width as u64 - 1)];
    for _ in 1..1 << (width - 1) {
        multiples.push(*multiples.last().unwrap() + point);
    }
    multiples
}

fn msm<const N: usize>(
    terms: &[(Scalar, ProjectivePoint)],
    width: usize,
    table: Option<(usize, usize)>,
) -> ProjectivePoint {
    let scalars: [Scalar; N] = from_fn(|i| terms[i].0);
    let elements: [ProjectivePoint; N] = from_fn(|i| terms[i].1);
    let tables = table
        .map(|(i, table_width)| {
            HashMap::from([(i, precomputed_multiples(&elements[i], table_width))])
        })
        .unwrap_or_default();
    multi_scalar_mul(&scalars, &elements, &tables, width, ProjectivePoint::zero())
}

fn run(state: &mut State, op: Op) {
    match op {
        Op::ScalarFromBytes(bytes) => {
            let expected = Option::<p256::Scalar>::from(p256::Scalar::from_repr(bytes.into()));
            let decoded = Scalar::from_byte_array(&bytes);
            assert_eq!(decoded.is_ok(), expected.is_some());
            assert_eq!(bcs::from_bytes::<Scalar>(&bytes).ok(), decoded.clone().ok());
            if let (Ok(scalar), Some(expected)) = (decoded, expected) {
                assert_eq!(scalar.to_byte_array(), bytes);
                state.push_scalar(scalar, expected);
            }
        }
        Op::ScalarFromU128(value) => {
            state.push_scalar(Scalar::from(value), p256::Scalar::from_u128(value))
        }
        Op::PowerOfTwoMinus(k, d) => {
            let expected = (0..k % 257).fold(p256::Scalar::ONE, |x, _| x.double())
                - p256::Scalar::from((d % 4) as u64);
            state.push_scalar(from_p256_scalar(&expected), expected);
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
            let inverse = Option::<p256::Scalar>::from(ey.invert());
            assert_eq!(y.inverse().is_ok(), inverse.is_some());
            match (x / y, inverse) {
                (Ok(quotient), Some(inverse)) => state.push_scalar(quotient, ex * inverse),
                (Err(_), None) => {}
                (result, _) => panic!("division by {ey:?} gives {result:?}"),
            }
        }
        Op::PointAdd(a, b) => {
            let ((p, ep), (q, eq)) = (state.point(a), state.point(b));
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
            state.push_point(p.double(), Group::double(&ep));
        }
        Op::Mul(p, s) => {
            let ((p, ep), (s, es)) = (state.point(p), state.scalar(s));
            state.push_point(p * s, ep * es);
        }
        Op::MultiplierMul(parameters, p, s) => {
            let ((p, ep), (s, es)) = (state.point(p), state.scalar(s));
            let product = match parameters {
                Parameters::Ecdsa => {
                    mul_with_base::<PRECOMPUTED_POINTS, SLIDING_WINDOW_WIDTH>(p, &s)
                }
                Parameters::Cache2Window1 => mul_with_base::<2, 1>(p, &s),
                Parameters::Cache4Window2 => mul_with_base::<4, 2>(p, &s),
                Parameters::Cache32Window3 => mul_with_base::<32, 3>(p, &s),
                Parameters::Cache1024Window9 => mul_with_base::<1024, 9>(p, &s),
            };
            state.push_point(product, ep * es);
        }
        Op::TwoScalarMul(parameters, u1, q, u2) => {
            let ((u1, eu1), (q, eq), (u2, eu2)) =
                (state.scalar(u1), state.point(q), state.scalar(u2));
            let result = match parameters {
                Parameters::Ecdsa => ECDSA.two_scalar_mul(&u1, &q, &u2),
                Parameters::Cache2Window1 => CACHE_2_WINDOW_1.two_scalar_mul(&u1, &q, &u2),
                Parameters::Cache4Window2 => CACHE_4_WINDOW_2.two_scalar_mul(&u1, &q, &u2),
                Parameters::Cache32Window3 => CACHE_32_WINDOW_3.two_scalar_mul(&u1, &q, &u2),
                Parameters::Cache1024Window9 => CACHE_1024_WINDOW_9.two_scalar_mul(&u1, &q, &u2),
            };
            state.push_point(result, p256::ProjectivePoint::GENERATOR * eu1 + eq * eu2);
        }
        Op::MultiScalarMul(terms, width, table) => {
            let terms = terms
                .iter()
                .take(MAX_TERMS)
                .map(|(s, p)| (state.scalar(*s), state.point(*p)))
                .collect::<Vec<_>>();
            if terms.is_empty() {
                return;
            }
            let expected = terms
                .iter()
                .map(|((_, es), (_, ep))| *ep * es)
                .sum::<p256::ProjectivePoint>();
            let terms = terms
                .iter()
                .map(|((s, _), (p, _))| (*s, *p))
                .collect::<Vec<_>>();
            let width = 1 + width as usize % 10;
            let table = table
                .map(|(i, table_width)| (i as usize % terms.len(), 1 + table_width as usize % 8));
            let result = match terms.len() {
                1 => msm::<1>(&terms, width, table),
                2 => msm::<2>(&terms, width, table),
                3 => msm::<3>(&terms, width, table),
                _ => msm::<MAX_TERMS>(&terms, width, table),
            };
            state.push_point(result, expected);
        }
    }
}

fuzz_target!(|ops: Vec<Op>| {
    let mut state = State::new();
    for op in ops.into_iter().take(MAX_OPS) {
        run(&mut state, op);
    }
});
