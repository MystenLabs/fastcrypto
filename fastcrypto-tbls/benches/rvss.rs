// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::bls12381;
use rand::thread_rng;

mod rvss_benches {
    use super::*;
    use fastcrypto::groups::{GroupElement, Pairing, Scalar};
    use fastcrypto_tbls::rvss::{Gadget, RVSS};
    use fastcrypto_tbls::tbls::ThresholdBls;
    use itertools::Itertools;

    fn exps(c: &mut Criterion) {
        let mut create: BenchmarkGroup<_> = c.benchmark_group("ops");
        {
            let x = bls12381::G1Element::generator() * bls12381::Scalar::rand(&mut thread_rng());
            let y = bls12381::Scalar::rand(&mut thread_rng());
            create.bench_function(&("g1 exp".to_string()), move |b| b.iter(|| x * y));
        }
        {
            let x = bls12381::G2Element::generator() * bls12381::Scalar::rand(&mut thread_rng());
            let y = bls12381::Scalar::rand(&mut thread_rng());
            create.bench_function(&("g2 exp".to_string()), move |b| b.iter(|| x * y));
        }

        {
            let x = bls12381::G1Element::generator() * bls12381::Scalar::rand(&mut thread_rng());
            let y = bls12381::G2Element::generator() * bls12381::Scalar::rand(&mut thread_rng());
            create.bench_function(&("pairing".to_string()), move |b| b.iter(|| x.pairing(&y)));
        }
    }

    fn gadget(c: &mut Criterion) {
        const ks: [usize; 3] = [80, 100, 120];
        let mut create: BenchmarkGroup<_> = c.benchmark_group("gadget");

        for K in ks {
            let h = bls12381::G1Element::generator();
            let omega = bls12381::Scalar::rand(&mut thread_rng());

            create.bench_function(format!("create k={}", K).as_str(), |b| {
                b.iter(|| Gadget::new(K, h, omega))
            });

            let gadget = Gadget::new(K, h, omega);
            create.bench_function(format!("verify k={}", K).as_str(), |b| {
                b.iter(|| gadget.verify(K).unwrap())
            });
        }
    }

    fn rvss(c: &mut Criterion) {
        let ns = [64, 128, 256, 512, 1024, 2048];
        let ks = [80];
        let mut create: BenchmarkGroup<_> = c.benchmark_group("rvss");

        for n in ns {
            for k in ks {
                let pks = (1..=n)
                    .map(|i| bls12381::G1Element::generator() * bls12381::Scalar::from(i as u128))
                    .collect_vec();
                let t = (n / 3) * 2;
                let omega = bls12381::Scalar::rand(&mut thread_rng());

                create.bench_function(format!("create t={}, n={}, k={}", t, n, k).as_str(), |b| {
                    b.iter(|| RVSS::new(k, t, omega, &pks))
                });

                let rvss = RVSS::new(80, t, omega, &pks);
                println!(
                    "rvss msg with n {}, size {}",
                    n,
                    bcs::to_bytes(&rvss).unwrap().len()
                );
                create.bench_function(format!("verify t={}, n={}, k={}", t, n, k).as_str(), |b| {
                    b.iter(|| rvss.verify(k, t, &pks).unwrap())
                });

                create.bench_function(format!("decrypt t={}, n={}, k={}", t, n, k).as_str(), |b| {
                    b.iter(|| {
                        rvss.optimistic_decrypt(10, &bls12381::Scalar::from(11))
                            .unwrap()
                    })
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
