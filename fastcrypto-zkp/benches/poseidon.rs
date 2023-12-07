// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[macro_use]
extern crate criterion;

mod poseidon_benches {
    use ark_std::UniformRand;
    use criterion::*;

    fn poseidon(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Poseidon");

        for size in (0..=32).step_by(4) {
            group.bench_with_input(
                BenchmarkId::new("Hash".to_string(), size),
                &size,
                |b, size| {
                    let mut rng = ark_std::test_rng();
                    let inputs: Vec<ark_bn254::Fr> =
                        (0..*size).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();
                    b.iter(|| {
                        fastcrypto_zkp::bn254::poseidon::poseidon_merkle_tree(inputs.clone())
                    });
                },
            );
        }
    }

    criterion_group! {
        name = poseidon_benches;
        config = Criterion::default();
        targets = poseidon,
    }
}

criterion_main!(poseidon_benches::poseidon_benches,);
