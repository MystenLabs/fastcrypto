// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Property tests: `fastcrypto_tbls::polynomial::Poly` over BLS12-381 scalars and its Lean model
//! (`../model/ShamirModel.lean`) return the same results on the same inputs.

use fastcrypto::groups::bls12381::Scalar;
use fastcrypto::groups::Scalar as _;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::polynomial::{Eval, Poly};
use fastcrypto_tbls::types::ShareIndex;
use lean_rs::{LeanBuiltCapability, LeanCapability, LeanRuntime};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use rand::rngs::StdRng;
use rand::SeedableRng;
use shamir_lean_harness::MANIFEST;

fn hex(s: &Scalar) -> String {
    hex::encode(s.to_byte_array())
}

fn hex_poly(coeffs: &[Scalar]) -> Vec<String> {
    coeffs.iter().map(hex).collect()
}

fn coefficients(p: &Poly<Scalar>) -> Vec<Scalar> {
    (0..=p.degree_bound()).map(|i| *p.coefficient(i)).collect()
}

/// Scalars from a seed: mostly uniform, sometimes small, to hit both carries and zero.
fn scalar() -> impl Strategy<Value = Scalar> {
    prop_oneof![
        any::<u64>().prop_map(|seed| Scalar::rand(&mut StdRng::seed_from_u64(seed))),
        (0u128..4).prop_map(Scalar::from),
    ]
}

fn open() -> LeanCapability<'static> {
    let runtime = LeanRuntime::init().expect("Lean runtime");
    LeanCapability::from_build_manifest(
        runtime,
        LeanBuiltCapability::manifest_path(MANIFEST)
            .manifest_env_var("LEAN_RS_CAPABILITY_SHAMIR_MODEL_MANIFEST"),
    )
    .expect("Lean model")
}

#[test]
fn c0_and_degree_bound() {
    let lean = open();
    let c0 = lean.exported::<(Vec<String>,), Result<String, String>>("shamir_model_c0").unwrap();
    let degree_bound = lean
        .exported::<(Vec<String>,), Result<u64, String>>("shamir_model_degree_bound")
        .unwrap();
    TestRunner::default()
        .run(&vec(scalar(), 0..12), |coeffs| {
            let p = Poly::from(coeffs.clone());
            prop_assert_eq!(c0.call(hex_poly(&coeffs)).unwrap(), Ok(hex(&p.c0())));
            prop_assert_eq!(
                degree_bound.call(hex_poly(&coeffs)).unwrap(),
                Ok(p.degree_bound() as u64)
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn eval() {
    let lean = open();
    let eval = lean
        .exported::<(Vec<String>, u64), Result<String, String>>("shamir_model_eval")
        .unwrap();
    TestRunner::default()
        .run(&(vec(scalar(), 0..12), 1u16..), |(coeffs, i)| {
            let p = Poly::from(coeffs.clone());
            let value = p.eval(ShareIndex::new(i).unwrap()).value;
            prop_assert_eq!(eval.call(hex_poly(&coeffs), i as u64).unwrap(), Ok(hex(&value)));
            Ok(())
        })
        .unwrap();
}

#[test]
fn add() {
    let lean = open();
    let add = lean
        .exported::<(Vec<String>, Vec<String>), Result<Vec<String>, String>>("shamir_model_add")
        .unwrap();
    TestRunner::default()
        .run(&(vec(scalar(), 1..12), vec(scalar(), 1..12)), |(a, b)| {
            let sum = Poly::from(a.clone()) + &Poly::from(b.clone());
            prop_assert_eq!(
                add.call(hex_poly(&a), hex_poly(&b)).unwrap(),
                Ok(hex_poly(&coefficients(&sum)))
            );
            Ok(())
        })
        .unwrap();
}

/// Shares of a random polynomial at random indices, with `t` sometimes off by one and indices
/// sometimes repeated, so that both the `Ok` and the `Err` paths are compared.
#[test]
fn recover_c0() {
    let lean = open();
    let recover = lean
        .exported::<(u64, Vec<u64>, Vec<String>), Result<String, String>>(
            "shamir_model_recover_c0",
        )
        .unwrap();
    let inputs = (vec(scalar(), 1..8), vec(1u16..40, 0..10), -1i64..=1);
    TestRunner::default()
        .run(&inputs, |(coeffs, indices, dt)| {
            let p = Poly::from(coeffs.clone());
            let shares: Vec<Eval<Scalar>> = indices
                .iter()
                .map(|&i| p.eval(ShareIndex::new(i).unwrap()))
                .collect();
            let t = (shares.len() as i64 + dt).max(0) as u16;
            let rust = Poly::<Scalar>::recover_c0(t, shares.iter()).map(|c| hex(&c));
            let lean = recover
                .call(
                    t as u64,
                    indices.iter().map(|&i| i as u64).collect(),
                    shares.iter().map(|s| hex(&s.value)).collect(),
                )
                .unwrap();
            prop_assert_eq!(lean.is_ok(), rust.is_ok());
            if let Ok(c) = rust {
                prop_assert_eq!(lean, Ok(c));
            }
            Ok(())
        })
        .unwrap();
}
