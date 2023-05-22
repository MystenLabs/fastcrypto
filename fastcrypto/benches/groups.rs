// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod group_benches {
    use criterion::{measurement, BenchmarkGroup, Criterion};
    use fastcrypto::groups;
    use fastcrypto::groups::bls12381::{G1Element, G2Element, GTElement};
    use fastcrypto::groups::multiplier::{ConstantTimeMultiplier, ScalarMultiplier};
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto::groups::secp256r1::ProjectivePoint;
    use fastcrypto::groups::{secp256r1, GroupElement, HashToGroupElement, Pairing, Scalar};
    use rand::thread_rng;

    fn add_single<G: GroupElement, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::generator() * G::ScalarType::rand(&mut thread_rng());
        c.bench_function(&(name.to_string()), move |b| b.iter(|| x + y));
    }

    fn add(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Add");
        add_single::<G1Element, _>("BLS12381-G1", &mut group);
        add_single::<G2Element, _>("BLS12381-G2", &mut group);
        add_single::<GTElement, _>("BLS12381-GT", &mut group);
        add_single::<RistrettoPoint, _>("Ristretto255", &mut group);
    }

    fn scale_single<G: GroupElement, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::ScalarType::rand(&mut thread_rng());
        c.bench_function(&(name.to_string()), move |b| b.iter(|| x * y));
    }

    fn scale(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Scalar To Point Multiplication");
        scale_single::<G1Element, _>("BLS12381-G1", &mut group);
        scale_single::<G2Element, _>("BLS12381-G2", &mut group);
        scale_single::<GTElement, _>("BLS12381-GT", &mut group);
        scale_single::<RistrettoPoint, _>("Ristretto255", &mut group);
        scale_single::<ProjectivePoint, _>("Secp256r1", &mut group);

        let multiplier = ConstantTimeMultiplier::<ProjectivePoint, secp256r1::Scalar, 32, 32>::new(
            ProjectivePoint::generator(),
        );
        let y = &groups::secp256r1::Scalar::rand(&mut thread_rng());
        group.bench_function("Secp256r1 precomputed (32)", move |b| {
            b.iter(|| multiplier.mul(y))
        });
    }

    fn hash_to_group_single<G: GroupElement + HashToGroupElement, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let seed = b"Hello, World!";
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| G::hash_to_group_element(seed))
        });
    }

    fn hash_to_group(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Hash-to-group");
        hash_to_group_single::<G1Element, _>("BLS12381-G1", &mut group);
        hash_to_group_single::<G2Element, _>("BLS12381-G2", &mut group);
        hash_to_group_single::<RistrettoPoint, _>("Ristretto255", &mut group);
    }

    fn pairing_single<G: GroupElement + Pairing, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::Other::generator()
            * <<G as Pairing>::Other as GroupElement>::ScalarType::rand(&mut thread_rng());
        c.bench_function(&(name.to_string()), move |b| b.iter(|| G::pairing(&x, &y)));
    }

    fn pairing(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Pairing");
        pairing_single::<G1Element, _>("BLS12381-G1", &mut group);
    }

    criterion_group! {
        name = group_benches;
        config = Criterion::default().sample_size(100);
        targets =
            add,
            scale,
            hash_to_group,
            pairing,
    }
}

criterion_main!(group_benches::group_benches,);
