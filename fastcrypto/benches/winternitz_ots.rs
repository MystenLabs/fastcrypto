// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

use criterion::{BenchmarkId, Criterion};
use fastcrypto::sphincs::winternitz_ots::{wots_pk_from_sig, wots_sign, WotsParams};
use fastcrypto::sphincs::Adrs;

/// For a fixed `n`, benches sign and verify across the given `lg_w` values in
/// two separate Criterion groups (`.../sign` and `.../verify`). Separating the
/// groups keeps each group's violin plot comparing like-for-like across lg_w.
///
/// This surfaces the WOTS+ compute <-> signature-size tradeoff: as `lg_w`
/// grows, sig size shrinks (fewer elements) but chains get longer
/// (2^lg_w - 1 hashes per chain). Per-element PRF cost dominates at small
/// lg_w, so the compute curve is U-shaped.
fn bench_sweep_n(c: &mut Criterion, n: u16, lg_ws: &[u16]) {
    let n_us = n as usize;
    let pk_seed: Vec<u8> = (0..n_us).map(|i| 0xA0u8.wrapping_add(i as u8)).collect();
    let sk_seed: Vec<u8> = (0..n_us).map(|i| 0x50u8.wrapping_add(i as u8)).collect();
    let msg: Vec<u8> = (0..n_us).map(|i| 0x10u8.wrapping_add(i as u8)).collect();
    let adrs = Adrs::new();

    let mut sign_group = c.benchmark_group(format!("WOTS+/n={n}/sign"));
    for &lg_w in lg_ws {
        let params = WotsParams::new(n, lg_w);
        let sig_bytes = params.num_elements() as usize * params.n as usize;
        let label = format!("lg_w={lg_w}/sig={sig_bytes}B");
        println!(
            "WOTS+ n={n} lg_w={lg_w}: sig={sig_bytes} B ({} elements x {n})",
            params.num_elements()
        );
        sign_group.bench_function(BenchmarkId::from_parameter(&label), |b| {
            b.iter(|| wots_sign(&params, &sk_seed, &pk_seed, adrs, &msg));
        });
    }
    sign_group.finish();

    let mut verify_group = c.benchmark_group(format!("WOTS+/n={n}/verify"));
    for &lg_w in lg_ws {
        let params = WotsParams::new(n, lg_w);
        let sig_bytes = params.num_elements() as usize * params.n as usize;
        let label = format!("lg_w={lg_w}/sig={sig_bytes}B");
        let sig = wots_sign(&params, &sk_seed, &pk_seed, adrs, &msg);
        verify_group.bench_function(BenchmarkId::from_parameter(&label), |b| {
            b.iter(|| wots_pk_from_sig(&params, &sig, &msg, &pk_seed, adrs));
        });
    }
    verify_group.finish();
}

fn wots_bench(c: &mut Criterion) {
    // Legal lg_w values satisfy (8n) mod lg_w = 0. Within each n, the sweep
    // spans the spec-relevant range and brackets it to show the full curve.
    // NIST-standardized choices: FIPS 205 picks lg_w=4 for all n;
    // SP 800-230 IPD picks lg_w=2 (n=16,32) and lg_w=3 (n=24).
    bench_sweep_n(c, 16, &[1, 2, 4, 8]);
    bench_sweep_n(c, 24, &[1, 2, 3, 4, 6, 8]);
    bench_sweep_n(c, 32, &[1, 2, 4, 8]);
}

criterion_group!(benches, wots_bench);
criterion_main!(benches);
