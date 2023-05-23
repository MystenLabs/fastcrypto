// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod group_benches {
    use criterion::measurement::Measurement;
    use criterion::{measurement, BenchmarkGroup, Criterion};
    use fastcrypto::groups;
    use fastcrypto::groups::bls12381::{G1Element, G2Element, GTElement};
    use fastcrypto::groups::multiplier::comb_method::CombMultiplier;
    use fastcrypto::groups::multiplier::fixed_window::{
        DefaultDoubleMultiplier, DoubleScalarMultiplier, FixedWindowMultiplier, MyDoubleMultiplier,
        WrappingDoubleMultiplier,
    };
    use fastcrypto::groups::multiplier::ScalarMultiplier;
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto::groups::secp256r1::ProjectivePoint;
    use fastcrypto::groups::{
        secp256r1, Doubling, GroupElement, HashToGroupElement, Pairing, Scalar,
    };
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

    fn scale_single_precomputed<G: GroupElement, Mul: ScalarMultiplier<G>, M: Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::ScalarType::rand(&mut thread_rng());

        let multiplier = Mul::new(x);
        c.bench_function(&(name.to_string()), move |b| b.iter(|| multiplier.mul(&y)));
    }

    fn scale(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Scalar To Point Multiplication");
        scale_single::<G1Element, _>("BLS12381-G1", &mut group);
        scale_single::<G2Element, _>("BLS12381-G2", &mut group);
        scale_single::<GTElement, _>("BLS12381-GT", &mut group);
        scale_single::<RistrettoPoint, _>("Ristretto255", &mut group);
        scale_single::<ProjectivePoint, _>("Secp256r1", &mut group);

        scale_single_precomputed::<
            ProjectivePoint,
            FixedWindowMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 32>,
            _,
        >("Secp256r1 Fixed window (16)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            FixedWindowMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 32>,
            _,
        >("Secp256r1 Fixed window (32)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            FixedWindowMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 32>,
            _,
        >("Secp256r1 Fixed window (64)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            FixedWindowMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 32>,
            _,
        >("Secp256r1 Fixed window (128)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            FixedWindowMultiplier<ProjectivePoint, secp256r1::Scalar, 256, 32>,
            _,
        >("Secp256r1 Fixed window (256)", &mut group);

        scale_single_precomputed::<
            ProjectivePoint,
            CombMultiplier<ProjectivePoint, secp256r1::Scalar, 4, 128, 32>,
            _,
        >("Secp256r1 Comb method (4x128 = 512)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            CombMultiplier<ProjectivePoint, secp256r1::Scalar, 8, 86, 32>,
            _,
        >("Secp256r1 Comb method (8x86 = 688)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            CombMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 64, 32>,
            _,
        >("Secp256r1 Comb method (16x64 = 1024)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            CombMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 52, 32>,
            _,
        >("Secp256r1 Comb method (32x52 = 1664)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            CombMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 43, 32>,
            _,
        >("Secp256r1 Comb method (64x43 = 2752)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            CombMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 37, 32>,
            _,
        >("Secp256r1 Comb method (128x37 = 4736)", &mut group);
    }

    fn double_scale_single<G: GroupElement, Mul: DoubleScalarMultiplier<G>, M: Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let g1 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s1 = G::ScalarType::rand(&mut thread_rng());
        let g2 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s2 = G::ScalarType::rand(&mut thread_rng());

        let multiplier = Mul::new(g1);
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| multiplier.mul(&s1, &g2, &s2))
        });
    }

    fn double_scale(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Double Scalar Multiplication");

        double_scale_single::<
            ProjectivePoint,
            MyDoubleMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 32>,
            _,
        >("Secp256r1 Straus (16)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            MyDoubleMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 32>,
            _,
        >("Secp256r1 Straus (32)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            MyDoubleMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 32>,
            _,
        >("Secp256r1 Straus (64)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            MyDoubleMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 32>,
            _,
        >("Secp256r1 Straus (128)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            MyDoubleMultiplier<ProjectivePoint, secp256r1::Scalar, 256, 32>,
            _,
        >("Secp256r1 Straus (256)", &mut group);
        double_scale_single::<ProjectivePoint, DefaultDoubleMultiplier<ProjectivePoint>, _>(
            "Secp256r1",
            &mut group,
        );
        double_scale_single::<
            ProjectivePoint,
            WrappingDoubleMultiplier<
                ProjectivePoint,
                CombMultiplier<ProjectivePoint, secp256r1::Scalar, 4, 128, 32>,
            >,
            _,
        >("Secp256r1 Comb (4x128", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WrappingDoubleMultiplier<
                ProjectivePoint,
                CombMultiplier<ProjectivePoint, secp256r1::Scalar, 8, 86, 32>,
            >,
            _,
        >("Secp256r1 Comb (8x86)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WrappingDoubleMultiplier<
                ProjectivePoint,
                CombMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 64, 32>,
            >,
            _,
        >("Secp256r1 Comb (16x64)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WrappingDoubleMultiplier<
                ProjectivePoint,
                CombMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 52, 32>,
            >,
            _,
        >("Secp256r1 Comb (32x52)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WrappingDoubleMultiplier<
                ProjectivePoint,
                CombMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 43, 32>,
            >,
            _,
        >("Secp256r1 Comb (64x43)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WrappingDoubleMultiplier<
                ProjectivePoint,
                CombMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 37, 32>,
            >,
            _,
        >("Secp256r1 Comb (128x37)", &mut group);
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
            double_scale,
    }
}

criterion_main!(group_benches::group_benches,);
