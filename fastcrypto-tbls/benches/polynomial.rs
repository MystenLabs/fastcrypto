// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::bls12381;
use fastcrypto_tbls::polynomial::Poly;
use rand::thread_rng;
use std::num::NonZeroU32;

mod polynomial_benches {
    use super::*;

    fn polynomials(c: &mut Criterion) {
        const SIZES: [usize; 7] = [128, 256, 512, 1024, 2048, 4096, 8192];
        type G = bls12381::G2Element;

        {
            let mut vss_sk_gen: BenchmarkGroup<_> = c.benchmark_group("VSS secret key generation");
            for n in SIZES {
                let t = n / 3;
                vss_sk_gen.bench_function(format!("n={}, t={}", n, t).as_str(), |b| {
                    b.iter(|| Poly::<bls12381::Scalar>::rand(t as u32, &mut thread_rng()))
                });
            }
        }

        {
            let mut vss_pk_gen: BenchmarkGroup<_> = c.benchmark_group("VSS public key generation");
            for n in SIZES {
                let t = n / 3;
                let vss_sk = Poly::<bls12381::Scalar>::rand(t as u32, &mut thread_rng());
                vss_pk_gen.bench_function(format!("n={}, t={}", n, t).as_str(), |b| {
                    b.iter(|| vss_sk.commit::<G>())
                });
            }
        }

        {
            let mut shares_gen: BenchmarkGroup<_> = c.benchmark_group("Shares generation");
            for n in SIZES {
                let t = n / 3;
                let vss_sk = Poly::<bls12381::Scalar>::rand(t as u32, &mut thread_rng());
                shares_gen.bench_function(format!("n={}, t={}", n, t).as_str(), |b| {
                    b.iter(|| {
                        (1u32..=(n as u32)).for_each(|i| {
                            vss_sk.eval(NonZeroU32::new(i).unwrap());
                        })
                    })
                });
            }
        }

        {
            // k represents the maximal number of shares per one party.
            // Note that in DKG protocol, each party verifies its shares vs O(f+1) VSS public keys,
            // but here we test only vs one VSS public key.
            let mut shares_verification: BenchmarkGroup<_> = c.benchmark_group("Verify k shares");
            for n in SIZES {
                let t = n / 3;
                let k = n / 10;
                let vss_sk = Poly::<bls12381::Scalar>::rand(t as u32, &mut thread_rng());
                let vss_pk = vss_sk.commit::<G>();
                shares_verification.bench_function(
                    format!("n={}, t={}, k={}", n, t, k).as_str(),
                    |b| {
                        b.iter(|| {
                            (1u32..=(k as u32)).for_each(|i| {
                                vss_pk.eval(NonZeroU32::new(i).unwrap());
                            })
                        })
                    },
                );
            }
        }
    }

    criterion_group! {
        name = polynomial_benches;
        config = Criterion::default();
        targets = polynomials,
    }
}

criterion_main!(polynomial_benches::polynomial_benches);
