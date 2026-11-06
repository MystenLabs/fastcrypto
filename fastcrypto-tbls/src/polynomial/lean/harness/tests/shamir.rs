// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Property tests: `fastcrypto_tbls::polynomial::Poly` over BLS12-381 scalars and its Lean model
//! (`../model/ShamirModel.lean`) return the same results on the same inputs.

use fastcrypto::groups::bls12381::Scalar;
use fastcrypto::groups::Scalar as _;
use fastcrypto_lean_testing::{hex, hex_all, same};
use fastcrypto_tbls::polynomial::{Eval, Poly};
use fastcrypto_tbls::types::ShareIndex;
use proptest::collection::vec;
use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use shamir_lean_harness::open;

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

#[test]
fn c0() {
    let lean = open();
    let c0 = lean
        .exported::<(Vec<String>,), Result<String, String>>("shamir_model_c0")
        .unwrap();
    same(
        vec(scalar(), 0..12),
        |coeffs| Ok(hex(&Poly::from(coeffs.clone()).c0())),
        |coeffs| c0.call(hex_all(coeffs)).unwrap(),
    );
}

#[test]
fn degree_bound() {
    let lean = open();
    let degree_bound = lean
        .exported::<(Vec<String>,), Result<u64, String>>("shamir_model_degree_bound")
        .unwrap();
    same(
        vec(scalar(), 0..12),
        |coeffs| Ok(Poly::from(coeffs.clone()).degree_bound() as u64),
        |coeffs| degree_bound.call(hex_all(coeffs)).unwrap(),
    );
}

#[test]
fn eval() {
    let lean = open();
    let eval = lean
        .exported::<(Vec<String>, u64), Result<String, String>>("shamir_model_eval")
        .unwrap();
    same(
        (vec(scalar(), 0..12), 1u16..),
        |(coeffs, i)| {
            let value = Poly::from(coeffs.clone())
                .eval(ShareIndex::new(*i).unwrap())
                .value;
            Ok(hex(&value))
        },
        |(coeffs, i)| eval.call(hex_all(coeffs), *i as u64).unwrap(),
    );
}

#[test]
fn add() {
    let lean = open();
    let add = lean
        .exported::<(Vec<String>, Vec<String>), Result<Vec<String>, String>>("shamir_model_add")
        .unwrap();
    same(
        (vec(scalar(), 1..12), vec(scalar(), 1..12)),
        |(a, b)| {
            let sum = Poly::from(a.clone()) + &Poly::from(b.clone());
            Ok(hex_all(&coefficients(&sum)))
        },
        |(a, b)| add.call(hex_all(a), hex_all(b)).unwrap(),
    );
}

/// Shares of a random polynomial at random indices, with `t` sometimes off by one and indices
/// sometimes repeated, so that both the `Ok` and the `Err` paths are compared.
#[test]
fn recover_c0() {
    let lean = open();
    let recover = lean
        .exported::<(u64, Vec<u64>, Vec<String>), Result<String, String>>("shamir_model_recover_c0")
        .unwrap();
    let shares = |coeffs: &Vec<Scalar>, indices: &Vec<u16>| -> Vec<Eval<Scalar>> {
        let p = Poly::from(coeffs.clone());
        indices
            .iter()
            .map(|&i| p.eval(ShareIndex::new(i).unwrap()))
            .collect()
    };
    let threshold = |indices: &Vec<u16>, dt: i64| (indices.len() as i64 + dt).max(0) as u16;
    same(
        (vec(scalar(), 1..8), vec(1u16..40, 0..10), -1i64..=1),
        |(coeffs, indices, dt)| {
            let shares = shares(coeffs, indices);
            Poly::<Scalar>::recover_c0(threshold(indices, *dt), shares.iter())
                .map(|c| hex(&c))
                .map_err(|_| ())
        },
        |(coeffs, indices, dt)| {
            let shares = shares(coeffs, indices);
            recover
                .call(
                    threshold(indices, *dt) as u64,
                    indices.iter().map(|&i| i as u64).collect(),
                    shares.iter().map(|s| hex(&s.value)).collect(),
                )
                .unwrap()
                .map_err(|_| ())
        },
    );
}
