// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;
extern crate rand;

mod hash_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::hash::HashFunction;
    use fastcrypto::hash::*;

    fn hash_single<
        H: HashFunction<DIGEST_SIZE>,
        const DIGEST_SIZE: usize,
        M: measurement::Measurement,
    >(
        name: &str,
        input: &[u8],
        c: &mut BenchmarkGroup<M>,
    ) {
        c.bench_with_input(
            BenchmarkId::new(name.to_string(), input.len()),
            &input,
            |b, input| {
                b.iter(|| H::digest(input));
            },
        );
    }

    fn hash(c: &mut Criterion) {
        static INPUT_SIZES: [usize; 5] = [0, 128, 256, 512, 1024];

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Hash");

        for size in INPUT_SIZES.iter() {
            let input: Vec<u8> = (0..*size).map(|_| rand::random::<u8>()).collect();
            hash_single::<Sha256, 32, _>("Sha256", &input, &mut group);
            hash_single::<Sha3_256, 32, _>("Sha3_256", &input, &mut group);
            hash_single::<Blake2b256, 32, _>("Blake2b256", &input, &mut group);
            hash_single::<Blake3, 32, _>("Blake3", &input, &mut group);
            hash_single::<Keccak256, 32, _>("Keccak256", &input, &mut group);
            hash_single::<Sha512, 64, _>("Sha512", &input, &mut group);
            hash_single::<Sha3_512, 64, _>("Sha3_512", &input, &mut group);
        }
    }

    criterion_group! {
        name = hash_benches;
        config = Criterion::default();
        targets = hash,
    }
}

criterion_main!(hash_benches::hash_benches,);
