// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::bls12381;
use rand::thread_rng;
use std::num::NonZeroU32;

mod tbls_benches {
    use super::*;
    use fastcrypto_tbls::polynomial::Poly;
    use fastcrypto_tbls::tbls::ThresholdBls;
    use fastcrypto_tbls::types::ThresholdBls12381MinSig;

    fn tbls(c: &mut Criterion) {
        let msg = b"test";

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group("Batch signing");
            let private_poly = Poly::<bls12381::Scalar>::rand(500, &mut thread_rng());
            const WEIGHTS: [usize; 5] = [10, 20, 30, 40, 50];
            for w in WEIGHTS {
                let shares = (1..=w)
                    .map(|i| private_poly.eval(NonZeroU32::new(i as u32).unwrap()))
                    .collect::<Vec<_>>();

                create.bench_function(format!("w={}", w).as_str(), |b| {
                    b.iter(|| ThresholdBls12381MinSig::partial_sign_batch(&shares, msg))
                });
            }
        }

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group("Recover full signature");
            const TOTAL_WEIGHTS: [usize; 4] = [666, 833, 1111, 1666];
            for w in TOTAL_WEIGHTS {
                let private_poly = Poly::<bls12381::Scalar>::rand(w as u32, &mut thread_rng());
                let shares = (1..=w)
                    .map(|i| private_poly.eval(NonZeroU32::new(i as u32).unwrap()))
                    .collect::<Vec<_>>();

                let sigs = ThresholdBls12381MinSig::partial_sign_batch(&shares, msg);

                create.bench_function(format!("w={}", w).as_str(), |b| {
                    b.iter(|| ThresholdBls12381MinSig::aggregate(w as u32, &sigs).unwrap())
                });
            }
        }
    }

    criterion_group! {
        name = tbls_benches;
        config = Criterion::default();
        targets = tbls,
    }
}

criterion_main!(tbls_benches::tbls_benches);
