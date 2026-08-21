// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Micro-benchmark: locate the crossover between the precomputed mixed MSM
//! (Straus with static tables) and a plain MSM (Pippenger at these sizes)
//! for the BP++ verifier's workload shape: S static generators with dense
//! scalars plus D dynamic points (proof points + commitments).
//!
//! This calibrates the fallback threshold in `bulletproofspp::norm_linear::verify`.
//!
//! Run with: `cargo bench -p fastcrypto --bench mixed_msm`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use fastcrypto::groups::ristretto255::{RistrettoPoint, RistrettoScalar};
use fastcrypto::groups::{
    GroupElement, MixedMultiScalarMul, MultiScalarMul, PrecomputableMultiScalarMul, Scalar,
};

fn rand_scalars(n: usize) -> Vec<RistrettoScalar> {
    let mut rng = rand::thread_rng();
    (0..n).map(|_| RistrettoScalar::rand(&mut rng)).collect()
}

fn rand_points(n: usize) -> Vec<RistrettoPoint> {
    rand_scalars(n)
        .iter()
        .map(|s| RistrettoPoint::generator() * s)
        .collect()
}

fn benchmarks(c: &mut Criterion) {
    // Static sizes bracketing the gap between the last size measured to
    // benefit from precomputation (265 = 64-bit x16: 1 + 8 + 256 generators)
    // and the first measured to regress (521 = 64-bit x32).
    let static_sizes = [265usize, 297, 329, 361, 393, 425, 457, 489, 521];
    // Dynamic side of the 64-bit x32 verifier: 5 circuit points + 32 value
    // commitments + 2*9 NLA round points. Smaller configs have fewer.
    let dynamic_sizes = [25usize, 55];

    for &d in &dynamic_sizes {
        let mut group = c.benchmark_group(format!("mixed_msm_dyn{d}"));
        for &s in &static_sizes {
            let static_points = rand_points(s);
            let static_scalars = rand_scalars(s);
            let dynamic_points = rand_points(d);
            let dynamic_scalars = rand_scalars(d);
            let precomp = RistrettoPoint::precompute(&static_points).unwrap();
            let all_scalars = [static_scalars.clone(), dynamic_scalars.clone()].concat();
            let all_points = [static_points.clone(), dynamic_points.clone()].concat();

            group.bench_with_input(BenchmarkId::new("precomp_mixed", s), &s, |b, _| {
                b.iter(|| {
                    black_box(precomp.mixed_multi_scalar_mul(
                        black_box(&static_scalars),
                        black_box(&dynamic_scalars),
                        black_box(&dynamic_points),
                    ))
                })
            });
            group.bench_with_input(BenchmarkId::new("plain", s), &s, |b, _| {
                b.iter(|| {
                    black_box(RistrettoPoint::multi_scalar_mul(
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
