// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod multiset_hash_benches {
    use criterion::*;
    use fastcrypto::hash::{EllipticCurveMultisetHash, LtHashQ32, MultisetHash};

    fn bench<H: MultisetHash<32> + Default + Clone, M: measurement::Measurement>(
        name: &str,
        items: &[[u8; 32]],
        group: &mut BenchmarkGroup<M>,
    ) {
        let mut populated = H::default();
        populated.insert_all(items);

        group.bench_function(BenchmarkId::new("insert", name), |b| {
            let mut hash = H::default();
            b.iter(|| hash.insert(items[0]))
        });
        group.bench_function(BenchmarkId::new("insert_all_1000", name), |b| {
            b.iter(|| {
                let mut hash = H::default();
                hash.insert_all(items);
                hash
            })
        });
        group.bench_function(BenchmarkId::new("union", name), |b| {
            let mut hash = H::default();
            b.iter(|| hash.union(&populated))
        });
        group.bench_function(BenchmarkId::new("digest", name), |b| {
            b.iter(|| populated.digest())
        });
    }

    fn multiset_hash(c: &mut Criterion) {
        let items: Vec<[u8; 32]> = (0..1000).map(|_| rand::random()).collect();
        let mut group = c.benchmark_group("MultisetHash");
        bench::<EllipticCurveMultisetHash, _>("ECMH", &items, &mut group);
        bench::<LtHashQ32, _>("LtHashQ32", &items, &mut group);
    }

    criterion_group! {
        name = multiset_hash_benches;
        config = Criterion::default();
        targets = multiset_hash,
    }
}

criterion_main!(multiset_hash_benches::multiset_hash_benches);
