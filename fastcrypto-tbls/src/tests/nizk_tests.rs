// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::nizk::{DLNizk, DdhTupleNizk};
use crate::random_oracle::RandomOracle;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{GroupElement, Scalar};
use rand::thread_rng;

type Group = RistrettoPoint;

#[test]
fn test_dl_nizk() {
    let x = <Group as GroupElement>::ScalarType::rand(&mut thread_rng());
    let g_x = Group::generator() * x;

    let nizk = DLNizk::create(&x, &g_x, &RandomOracle::new("test"), &mut thread_rng());
    assert!(nizk.verify(&g_x, &RandomOracle::new("test")).is_ok());
    assert!(nizk.verify(&g_x, &RandomOracle::new("test2")).is_err());
    assert!(nizk
        .verify(&Group::generator(), &RandomOracle::new("test"))
        .is_err());
}

#[test]
fn test_ddh_nizk() {
    let x1 = <Group as GroupElement>::ScalarType::rand(&mut thread_rng());
    let x2 = <Group as GroupElement>::ScalarType::rand(&mut thread_rng());
    let g_x1 = Group::generator() * x1;
    let g_x2 = Group::generator() * x2;
    let g_x1_x2 = g_x1 * x2;

    let nizk = DdhTupleNizk::create(
        &x2,
        &g_x1,
        &g_x2,
        &g_x1_x2,
        &RandomOracle::new("test"),
        &mut thread_rng(),
    );
    assert!(nizk
        .verify(&g_x1, &g_x2, &g_x1_x2, &RandomOracle::new("test"))
        .is_ok());
    assert!(nizk
        .verify(&g_x1, &g_x2, &g_x1_x2, &RandomOracle::new("test2"))
        .is_err());
    assert!(nizk
        .verify(&g_x1, &g_x2, &g_x2, &RandomOracle::new("test"))
        .is_err());
}
