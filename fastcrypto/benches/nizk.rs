// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::*;
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{GroupElement, Scalar};
use fastcrypto::nizk::DdhTupleNizk;
use rand::thread_rng;

fn verification(c: &mut Criterion) {
    let e = RistrettoScalar::rand(&mut thread_rng());
    let x = RistrettoScalar::rand(&mut thread_rng());
    let g = RistrettoPoint::generator() * RistrettoScalar::rand(&mut thread_rng());
    let h = g * e;
    let x_g = g * x;
    let x_h = h * x;
    let nizk = DdhTupleNizk::create(&x, &g, &h, &x_g, &x_h, &mut thread_rng());

    c.bench_function("nizk/ddh/verification", |b| {
        b.iter(|| nizk.verify(&g, &h, &x_g, &x_h))
    });
}

criterion_group! {
    name = nizk;
    config = Criterion::default();
    targets = verification,
}

criterion_main!(nizk);
