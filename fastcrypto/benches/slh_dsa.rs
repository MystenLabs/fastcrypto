// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! SLH-DSA end-to-end benches.
//!
//! - SLH-DSA-SHA2-128s   (FIPS 205):       keygen, sign, verify
//!
//! Run: cargo bench -p fastcrypto --features experimental --bench slh_dsa

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use fastcrypto::sphincs::{slh_keygen, slh_sign, slh_verify, SlhDsaParams};

fn seeds(n: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        (0..n).map(|i| 0x50u8.wrapping_add(i as u8)).collect(),
        (0..n).map(|i| 0x60u8.wrapping_add(i as u8)).collect(),
        (0..n).map(|i| 0xA0u8.wrapping_add(i as u8)).collect(),
    )
}

fn slh_dsa_bench(c: &mut Criterion) {
    let msg = b"slh-dsa bench message".to_vec();

    // ---- SHA2-128s: all three ops ----
    let params = SlhDsaParams::sha2_128s();
    let (sk_seed, sk_prf, pk_seed) = seeds(params.n);
    let (pk, sk) = slh_keygen(&params, &sk_seed, &sk_prf, &pk_seed);
    let sig = slh_sign(&params, &sk, &msg, None);

    c.bench_function("SLH-DSA/SHA2-128s/keygen", |b| {
        b.iter(|| slh_keygen(&params, &sk_seed, &sk_prf, &pk_seed))
    });
    c.bench_function("SLH-DSA/SHA2-128s/sign", |b| {
        b.iter(|| slh_sign(&params, &sk, &msg, None))
    });
    c.bench_function("SLH-DSA/SHA2-128s/verify", |b| {
        b.iter(|| slh_verify(&params, &pk, &msg, &sig))
    });
}

criterion_group!(benches, slh_dsa_bench);
criterion_main!(benches);
