// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
use fastcrypto_vdf::math::extended_gcd::extended_euclidean_algorithm;
use fastcrypto_vdf::math::jacobi::jacobi;
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_bigint_dig::Sign;
use rand::{thread_rng, RngCore};
use std::str::FromStr;

fn jacobi_benchmark(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Jacobi".to_string());

    let primes = [
        BigInt::from_str("40094690950920881030683735292761468389214899724061").unwrap(),
        // BN254 field modulus
        BigInt::from_str("21888242871839275222246405745257275088696311157297823662689037894645226208583").unwrap(),
        BigInt::from_str("9850474933090316161325735413644496314011175485542608857336970036355288804004524486744573258192938553").unwrap(),
        BigInt::from_str("7568304713565077502573241397060395233114272334717110389484122188865572262580962050391580896924688655803068457013889851075632569688753640278308582703422703").unwrap(),
        BigInt::from_str("177936553897922261333164712410242884021141613334565149505848952826212491241771489747671651876796162246463307642229416178115038439759411468976306741727054586407871065937781422970533238726218439981299971510624199735799141406458705159532021234549127390010928558972193365915987838285442951665356778289757172235943").unwrap(),
        BigInt::from_str("32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389647960126939249806625440700685819469589938384356951833568218188663").unwrap(),
        BigInt::from_str("197094279717529776652945533421408519016291293185778176422038767173246838389717778782272450609952179792102389097362657787152898007436991089430517979761145200893975140029279440383697629952398509684430189989830512427761221044255503309237697000446508821686655886069366603792908696660367648281136978401042076354619587515552611650395121072487799107192700364331538210709886133279169829259881605487142555274403314509719321602412760314496712012939372327177464352472192738122541539747842405435171078768578664156285412471750348778431888800482596404122201686947621151032470989798594881908508768154982514267787085456831726879055929531619461354230569362180363281846948763424056650300352728927552479847814231289623672826128091486169286759").unwrap(),
        ];

    for p in primes {
        let bits = p.bits();
        let p_bigint_dig =
            num_bigint_dig::BigInt::from_bytes_be(Sign::Plus, &p.clone().to_bytes_be().1);

        group.bench_function(format!("{} bits", bits), move |b| {
            b.iter_batched(
                || thread_rng().gen_biguint(bits - 1).to_bigint().unwrap(),
                |a| jacobi(&a, &p),
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("{} bits (num-bigint-dig)", bits), move |b| {
            b.iter_batched(
                || {
                    let a = thread_rng().gen_biguint(bits - 1).to_bigint().unwrap();
                    num_bigint_dig::BigInt::from_bytes_be(Sign::Plus, &a.clone().to_bytes_be().1)
                },
                |a| num_bigint_dig::algorithms::jacobi(&a, &p_bigint_dig),
                BatchSize::SmallInput,
            );
        });
    }
}

fn euclid_benchmark(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("GCD".to_string());

    for bytes in [256, 512, 1024, 2048] {
        group.bench_function(format!("{} bits", bytes), move |b| {
            b.iter_batched(
                || {
                    let mut bytes = vec![0u8; bytes];

                    thread_rng().fill_bytes(&mut bytes);
                    let a = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);

                    thread_rng().fill_bytes(&mut bytes);
                    let b = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);

                    (a, b)
                },
                |(a, b)| extended_euclidean_algorithm(&a, &b),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = class_group_benchmarks;
    config = Criterion::default().sample_size(100);
    targets = jacobi_benchmark, euclid_benchmark,
}

criterion_main!(class_group_benchmarks);
