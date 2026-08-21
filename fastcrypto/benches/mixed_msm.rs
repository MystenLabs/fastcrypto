// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmark: locate the crossover between dalek's precomputed mixed
//! MSM (Straus with static tables) and its plain MSM (Straus below 190
//! points, Pippenger above) over a grid of S static points with dense
//! scalars plus D dynamic points. It calibrates `MAX_STRAUS_POINTS` and
//! `DYNAMIC_POINT_WEIGHT` in `groups::ristretto255`: for each D, the
//! crossover `S_0(D)` is the static size at which `plain` first beats
//! `precomp_mixed` (interpolated between grid points), and the two constants
//! are a linear fit `S_0(D) = MAX_STRAUS_POINTS - DYNAMIC_POINT_WEIGHT * D`.
//! The dalek primitives are timed directly, since the fastcrypto wrapper
//! applies that rule itself. The crossover is a property of the two
//! implementations on the benchmarking machine, not of any caller.
//!
//! Run with: `cargo bench -p fastcrypto --bench mixed_msm`

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{RistrettoPoint, VartimeRistrettoPrecomputation};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{VartimeMultiscalarMul, VartimePrecomputedMultiscalarMul};
use rand::RngCore;

fn rand_scalars(n: usize) -> Vec<Scalar> {
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| {
            let mut bytes = [0u8; 64];
            rng.fill_bytes(&mut bytes);
            Scalar::from_bytes_mod_order_wide(&bytes)
        })
        .collect()
}

fn rand_points(n: usize) -> Vec<RistrettoPoint> {
    rand_scalars(n)
        .iter()
        .map(|s| RISTRETTO_BASEPOINT_POINT * s)
        .collect()
}

fn benchmarks(c: &mut Criterion) {
    // Powers of two and their midpoints on the static axis; none, then
    // factors of four apart, on the dynamic axis.
    let static_sizes = [64usize, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048];
    let dynamic_sizes = [0usize, 32, 128, 512];

    for &d in &dynamic_sizes {
        let mut group = c.benchmark_group(format!("mixed_msm_dyn{d}"));
        group.warm_up_time(Duration::from_secs(1));
        group.measurement_time(Duration::from_secs(3));
        for &s in &static_sizes {
            let static_points = rand_points(s);
            let static_scalars = rand_scalars(s);
            let dynamic_points = rand_points(d);
            let dynamic_scalars = rand_scalars(d);
            let precomp = VartimeRistrettoPrecomputation::new(&static_points);
            let all_scalars = [static_scalars.clone(), dynamic_scalars.clone()].concat();
            let all_points = [static_points.clone(), dynamic_points.clone()].concat();

            group.bench_with_input(BenchmarkId::new("precomp_mixed", s), &s, |b, _| {
                b.iter(|| {
                    black_box(precomp.vartime_mixed_multiscalar_mul(
                        black_box(&static_scalars),
                        black_box(&dynamic_scalars),
                        black_box(&dynamic_points),
                    ))
                })
            });
            group.bench_with_input(BenchmarkId::new("plain", s), &s, |b, _| {
                b.iter(|| {
                    black_box(RistrettoPoint::vartime_multiscalar_mul(
                        black_box(&all_scalars),
                        black_box(&all_points),
                    ))
                })
            });
        }
        group.finish();
    }
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
