// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use rand::thread_rng;

mod rvss_benches {
    use super::*;
    use fastcrypto::groups::{GroupElement, Scalar as GScalar};
    use fastcrypto_tbls::rvss::{Gadget, Point, Scalar, RVSS};
    use itertools::Itertools;

    fn exps(c: &mut Criterion) {
        let mut create: BenchmarkGroup<_> = c.benchmark_group("ops");
        {
            let x = Point::generator() * Scalar::rand(&mut thread_rng());
            let y = Scalar::rand(&mut thread_rng());
            create.bench_function(&("g exp".to_string()), move |b| b.iter(|| x * y));
        }
    }

    fn gadget(c: &mut Criterion) {
        const KS: [usize; 3] = [80, 100, 120];
        let mut create: BenchmarkGroup<_> = c.benchmark_group("gadget");

        for k in KS {
            let h = Point::generator();
            let omega = Scalar::rand(&mut thread_rng());

            create.bench_function(format!("create k={}", k).as_str(), |b| {
                b.iter(|| Gadget::new(k, h, omega))
            });

            let gadget = Gadget::new(k, h, omega);
            create.bench_function(format!("verify k={}", k).as_str(), |b| {
                b.iter(|| gadget.verify(k).unwrap())
            });
        }
    }

    fn rvss(c: &mut Criterion) {
        let ns = [64, 128, 256, 512, 1024, 2048];
        let ks = [80];
        let mut create: BenchmarkGroup<_> = c.benchmark_group("rvss");

        for n in ns {
            for k in ks {
                let sk = (1..=n)
                    .map(|_| GScalar::rand(&mut thread_rng()))
                    .collect_vec();
                let pks = sk
                    .iter()
                    .map(|sk_i| Point::generator() * sk_i)
                    .collect_vec();
                let t = (n / 3) * 2;
                let omega = GScalar::rand(&mut thread_rng());

                create.bench_function(format!("create t={}, n={}, k={}", t, n, k).as_str(), |b| {
                    b.iter(|| RVSS::new(k, t, omega, &pks))
                });

                let rvss = RVSS::new(k, t, omega, &pks);
                println!(
                    "rvss msg with n {}, size {}",
                    n,
                    bcs::to_bytes(&rvss).unwrap().len()
                );
                create.bench_function(format!("verify t={}, n={}, k={}", t, n, k).as_str(), |b| {
                    b.iter(|| rvss.verify(k, t, &pks).unwrap())
                });

                create.bench_function(format!("decrypt t={}, n={}, k={}", t, n, k).as_str(), |b| {
                    b.iter(|| rvss.optimistic_decrypt(10, &sk[10]).unwrap())
                });
            }
        }
    }

    criterion_group! {
        name = rvss_benches;
        config = Criterion::default();
        targets =
            exps,
            gadget,
            rvss
    }
}

criterion_main!(rvss_benches::rvss_benches);
