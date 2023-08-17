// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod group_benches {
    use criterion::measurement::Measurement;
    use criterion::{measurement, BenchmarkGroup, Criterion};
    use fastcrypto::groups::bls12381::{G1Element, G2Element, GTElement};
    use fastcrypto::groups::class_group::{Discriminant, QuadraticForm};
    use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
    use fastcrypto::groups::multiplier::ScalarMultiplier;
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto::groups::secp256r1::ProjectivePoint;
    use fastcrypto::groups::{
        secp256r1, GroupElement, HashToGroupElement, Pairing, ParameterizedGroupElement, Scalar,
    };
    use num_bigint::BigInt;
    use num_traits::Num;
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
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 32, 5>,
            _,
        >("Secp256r1 Fixed window (16)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 32, 5>,
            _,
        >("Secp256r1 Fixed window (32)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 32, 5>,
            _,
        >("Secp256r1 Fixed window (64)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 32, 5>,
            _,
        >("Secp256r1 Fixed window (128)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 256, 32, 5>,
            _,
        >("Secp256r1 Fixed window (256)", &mut group);
    }

    fn double_scale_single<G: GroupElement, Mul: ScalarMultiplier<G>, M: Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let g1 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s1 = G::ScalarType::rand(&mut thread_rng());
        let g2 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s2 = G::ScalarType::rand(&mut thread_rng());

        let multiplier = Mul::new(g1);
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| multiplier.two_scalar_mul(&s1, &g2, &s2))
        });
    }

    fn double_scale(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Double Scalar Multiplication");

        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 32, 5>,
            _,
        >("Secp256r1 Straus (16)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 32, 5>,
            _,
        >("Secp256r1 Straus (32)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 32, 5>,
            _,
        >("Secp256r1 Straus (64)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 32, 5>,
            _,
        >("Secp256r1 Straus (128)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 256, 32, 5>,
            _,
        >("Secp256r1 Straus (256)", &mut group);
        double_scale_single::<ProjectivePoint, DefaultMultiplier<ProjectivePoint>, _>(
            "Secp256r1",
            &mut group,
        );
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

    /// Implementation of a `Multiplier` where scalar multiplication is done without any pre-computation by
    /// simply calling the GroupElement implementation. Only used for benchmarking.
    struct DefaultMultiplier<G: GroupElement>(G);

    impl<G: GroupElement> ScalarMultiplier<G> for DefaultMultiplier<G> {
        fn new(base_element: G) -> Self {
            Self(base_element)
        }

        fn mul(&self, scalar: &G::ScalarType) -> G {
            self.0 * scalar
        }
    }

    fn class_group_ops(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Class Group Operation");
        let d = Discriminant::try_from(BigInt::from_str_radix("-9458193260787340859710210783898414376413627187338129653105774703043377776905956484932486183722303201135571583745806165441941755833466966188398807387661571", 10).unwrap()).unwrap();
        let x = QuadraticForm::generator(&d).mul(&BigInt::from(1234));
        let y = QuadraticForm::generator(&d).mul(&BigInt::from(4321));
        group.bench_function("Compose (512 bit discriminant)", move |b| {
            b.iter(|| x.compose(&y))
        });

        let d = Discriminant::try_from(BigInt::from_str_radix("-173197108158285529655099692042166386683260486655764503111574151459397279244340625070436917386670107433539464870917173822190635872887684166173874718269704667936351650895772937202272326332043347073303124000059154982400685660701006453457007094026343973435157790533480400962985543272080923974737725172126369794019", 10).unwrap()).unwrap();
        let x = QuadraticForm::generator(&d).mul(&BigInt::from(1234));
        let y = QuadraticForm::generator(&d).mul(&BigInt::from(4321));
        group.bench_function("Compose (1024 bit discriminant)", move |b| {
            b.iter(|| x.compose(&y))
        });
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
            class_group_ops,
    }
}

criterion_main!(group_benches::group_benches,);
