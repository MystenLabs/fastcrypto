// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests that `fastcrypto::groups::ristretto255` and its Lean model
//! (`../model/RistrettoModel.lean`) return the same results on the same inputs.
//!
//! Points enter the model through its decoder and leave through its encoder, so every test also
//! exercises both. A result that is an error on either side is compared as `Err(())`.

use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{Doubling, GroupElement, MultiScalarMul, Scalar};
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_lean_testing::lean_rs::LeanCapability;
use fastcrypto_lean_testing::{hex, hex_all, same};
use proptest::collection::vec;
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use ristretto_lean_harness::open;

type Output = Result<String, ()>;

const P: [u8; 32] = {
    let mut p = [0xff; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

fn rust<const N: usize, T: ToFromByteArray<N>>(x: FastCryptoResult<T>) -> Output {
    x.map(|x| hex(&x)).map_err(|_| ())
}

fn ok<const N: usize, T: ToFromByteArray<N>>(x: T) -> Output {
    Ok(hex(&x))
}

fn unary<'a>(lean: &'a LeanCapability<'static>, name: &str) -> impl Fn(String) -> Output + 'a {
    let f = lean
        .exported::<(String,), Result<String, String>>(&format!("ristretto_model_{name}"))
        .unwrap();
    move |a| f.call(a).unwrap().map_err(|_| ())
}

fn binary<'a>(
    lean: &'a LeanCapability<'static>,
    name: &str,
) -> impl Fn(String, String) -> Output + 'a {
    let f = lean
        .exported::<(String, String), Result<String, String>>(&format!("ristretto_model_{name}"))
        .unwrap();
    move |a, b| f.call(a, b).unwrap().map_err(|_| ())
}

/// Scalars from a seed: mostly uniform, sometimes small, to hit zero and carries.
fn scalar() -> impl Strategy<Value = RistrettoScalar> {
    prop_oneof![
        any::<u64>().prop_map(|seed| RistrettoScalar::rand(&mut StdRng::seed_from_u64(seed))),
        (0u64..4).prop_map(RistrettoScalar::from),
        (1u64..4).prop_map(|x| -RistrettoScalar::from(x)),
    ]
}

/// Points of unknown discrete log, small multiples of the generator and the identity.
fn point() -> impl Strategy<Value = RistrettoPoint> {
    prop_oneof![
        any::<u64>().prop_map(|seed| RistrettoPoint::from_uniform_bytes(&wide(seed))),
        scalar().prop_map(|k| RistrettoPoint::generator() * k),
        Just(RistrettoPoint::zero()),
    ]
}

fn wide(seed: u64) -> [u8; 64] {
    let mut bytes = [0; 64];
    StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
    bytes
}

fn valid_encoding() -> impl Strategy<Value = [u8; 32]> {
    point().prop_map(|p| p.to_byte_array())
}

/// Integers at the edges of what the decoders accept, too rare to rely on random sampling: small
/// values (`s = 1` and `s = p - 1` are the encodings that decode to `y = 0`), around `p`, around
/// the group order `L`, and with the top bit set.
fn boundary_encodings() -> Vec<[u8; 32]> {
    let small = (0u8..8).map(|n| {
        let mut bytes = [0; 32];
        bytes[0] = n;
        bytes
    });
    let top_bit_set = small.clone().map(|mut bytes| {
        bytes[31] |= 0x80;
        bytes
    });
    let around_p = (0xe5u8..=0xff).map(|low| {
        let mut bytes = P;
        bytes[0] = low;
        bytes
    });
    let order_minus_one = (-RistrettoScalar::from(1u64)).to_byte_array();
    let around_order = (0u8..3).map(move |delta| {
        let mut bytes = order_minus_one;
        bytes[0] += delta;
        bytes
    });
    small
        .chain(top_bit_set)
        .chain(around_p)
        .chain(around_order)
        .collect()
}

/// 32 bytes that are often, but not always, a valid point or scalar encoding: uniform bytes, valid
/// encodings and those with one bit flipped.
fn encoding() -> impl Strategy<Value = [u8; 32]> {
    prop_oneof![
        any::<[u8; 32]>(),
        valid_encoding(),
        scalar().prop_map(|k| k.to_byte_array()),
        (valid_encoding(), 0usize..256).prop_map(|(mut bytes, bit)| {
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        }),
    ]
}

#[test]
fn constants() {
    let lean = open();
    let constant = |name: &str| {
        lean.exported::<(u64,), String>(&format!("ristretto_model_{name}"))
            .unwrap()
            .call(0)
            .unwrap()
    };
    assert_eq!(constant("point_zero"), hex(&RistrettoPoint::zero()));
    assert_eq!(
        constant("point_generator"),
        hex(&RistrettoPoint::generator())
    );
}

#[test]
fn point_decode() {
    let lean = open();
    let decode = unary(&lean, "point_decode");
    same(
        encoding(),
        |bytes| rust(RistrettoPoint::from_byte_array(bytes)),
        |bytes| decode(::hex::encode(bytes)),
    );
}

#[test]
fn point_decode_boundary() {
    let lean = open();
    let decode = unary(&lean, "point_decode");
    for bytes in boundary_encodings() {
        assert_eq!(
            rust(RistrettoPoint::from_byte_array(&bytes)),
            decode(::hex::encode(bytes)),
            "{bytes:?}"
        );
    }
}

#[test]
fn point_add() {
    let lean = open();
    let add = binary(&lean, "point_add");
    same(
        (point(), point()),
        |(a, b)| ok(*a + *b),
        |(a, b)| add(hex(a), hex(b)),
    );
}

#[test]
fn point_add_to_itself() {
    let lean = open();
    let add = binary(&lean, "point_add");
    same(point(), |a| ok(*a + *a), |a| add(hex(a), hex(a)));
}

#[test]
fn point_sub() {
    let lean = open();
    let sub = binary(&lean, "point_sub");
    same(
        (point(), point()),
        |(a, b)| ok(*a - *b),
        |(a, b)| sub(hex(a), hex(b)),
    );
}

#[test]
fn point_neg() {
    let lean = open();
    let neg = unary(&lean, "point_neg");
    same(point(), |a| ok(-*a), |a| neg(hex(a)));
}

#[test]
fn point_double() {
    let lean = open();
    let double = unary(&lean, "point_double");
    same(point(), |a| ok(a.double()), |a| double(hex(a)));
}

#[test]
fn point_mul() {
    let lean = open();
    let mul = binary(&lean, "point_mul");
    same(
        (point(), scalar()),
        |(a, k)| ok(*a * *k),
        |(a, k)| mul(hex(a), hex(k)),
    );
}

#[test]
fn point_div() {
    let lean = open();
    let div = binary(&lean, "point_div");
    same(
        (point(), scalar()),
        |(a, k)| rust(*a / *k),
        |(a, k)| div(hex(a), hex(k)),
    );
}

#[test]
fn point_msm() {
    let lean = open();
    let msm = lean
        .exported::<(Vec<String>, Vec<String>), Result<String, String>>("ristretto_model_point_msm")
        .unwrap();
    same(
        (vec(scalar(), 0..6), vec(point(), 0..6)),
        |(ks, ps)| rust(RistrettoPoint::multi_scalar_mul(ks, ps)),
        |(ks, ps)| msm.call(hex_all(ks), hex_all(ps)).unwrap().map_err(|_| ()),
    );
}

#[test]
fn point_from_uniform_bytes() {
    let lean = open();
    let from_uniform = binary(&lean, "point_from_uniform");
    same(
        any::<u64>().prop_map(wide),
        |bytes| ok(RistrettoPoint::from_uniform_bytes(bytes)),
        |bytes| from_uniform(::hex::encode(&bytes[..32]), ::hex::encode(&bytes[32..])),
    );
}

#[test]
fn scalar_decode() {
    let lean = open();
    let decode = unary(&lean, "scalar_decode");
    same(
        encoding(),
        |bytes| rust(RistrettoScalar::from_byte_array(bytes)),
        |bytes| decode(::hex::encode(bytes)),
    );
}

#[test]
fn scalar_decode_boundary() {
    let lean = open();
    let decode = unary(&lean, "scalar_decode");
    for bytes in boundary_encodings() {
        assert_eq!(
            rust(RistrettoScalar::from_byte_array(&bytes)),
            decode(::hex::encode(bytes)),
            "{bytes:?}"
        );
    }
}

#[test]
fn scalar_add() {
    let lean = open();
    let add = binary(&lean, "scalar_add");
    same(
        (scalar(), scalar()),
        |(a, b)| ok(*a + *b),
        |(a, b)| add(hex(a), hex(b)),
    );
}

#[test]
fn scalar_sub() {
    let lean = open();
    let sub = binary(&lean, "scalar_sub");
    same(
        (scalar(), scalar()),
        |(a, b)| ok(*a - *b),
        |(a, b)| sub(hex(a), hex(b)),
    );
}

#[test]
fn scalar_neg() {
    let lean = open();
    let neg = unary(&lean, "scalar_neg");
    same(scalar(), |a| ok(-*a), |a| neg(hex(a)));
}

#[test]
fn scalar_mul() {
    let lean = open();
    let mul = binary(&lean, "scalar_mul");
    same(
        (scalar(), scalar()),
        |(a, b)| ok(*a * *b),
        |(a, b)| mul(hex(a), hex(b)),
    );
}

#[test]
fn scalar_inverse() {
    let lean = open();
    let inverse = unary(&lean, "scalar_inverse");
    same(scalar(), |a| rust(a.inverse()), |a| inverse(hex(a)));
}

#[test]
fn scalar_from_bytes_mod_order() {
    let lean = open();
    let reduce = unary(&lean, "scalar_mod_order");
    same(
        any::<[u8; 32]>(),
        |bytes| ok(RistrettoScalar::from_bytes_mod_order(bytes)),
        |bytes| reduce(::hex::encode(bytes)),
    );
}

#[test]
fn scalar_from_bytes_mod_order_wide() {
    let lean = open();
    let reduce = unary(&lean, "scalar_mod_order_wide");
    same(
        any::<u64>().prop_map(wide),
        |bytes| ok(RistrettoScalar::from_bytes_mod_order_wide(bytes)),
        |bytes| reduce(::hex::encode(bytes)),
    );
}
