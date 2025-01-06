// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod group_benches {
    use criterion::measurement::Measurement;
    use criterion::{measurement, BenchmarkGroup, BenchmarkId, Criterion};
    use fastcrypto::groups::bls12381::{
        G1Element, G1ElementUncompressed, G2Element, GTElement, Scalar as BlsScalar,
        G1_ELEMENT_BYTE_LENGTH, G2_ELEMENT_BYTE_LENGTH, GT_ELEMENT_BYTE_LENGTH, SCALAR_LENGTH,
    };
    use fastcrypto::groups::multiplier::windowed::WindowedScalarMultiplier;
    use fastcrypto::groups::multiplier::ScalarMultiplier;
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto::groups::secp256r1::ProjectivePoint;
    use fastcrypto::groups::{
        bls12381, secp256r1, FromTrustedByteArray, GroupElement, HashToGroupElement,
        MultiScalarMul, Pairing, Scalar,
    };
    use fastcrypto::serde_helpers::ToFromByteArray;
    use rand::thread_rng;

    fn add_single<G: GroupElement, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::generator() * G::ScalarType::rand(&mut thread_rng());
        c.bench_function(name.to_string(), move |b| b.iter(|| x + y));
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
        c.bench_function(name.to_string(), move |b| b.iter(|| x * y));
    }

    fn scale_single_precomputed<
        G: GroupElement,
        Mul: ScalarMultiplier<G, G::ScalarType>,
        M: Measurement,
    >(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let x = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let y = G::ScalarType::rand(&mut thread_rng());

        let multiplier = Mul::new(x, G::zero());
        c.bench_function(name.to_string(), move |b| b.iter(|| multiplier.mul(&y)));
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
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 5>,
            _,
        >("Secp256r1 Fixed window (16)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 5>,
            _,
        >("Secp256r1 Fixed window (32)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 5>,
            _,
        >("Secp256r1 Fixed window (64)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 5>,
            _,
        >("Secp256r1 Fixed window (128)", &mut group);
        scale_single_precomputed::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 256, 5>,
            _,
        >("Secp256r1 Fixed window (256)", &mut group);
    }

    fn blst_msm_single<G: GroupElement + MultiScalarMul, M: Measurement>(
        name: &str,
        len: &usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let (scalars, points): (Vec<G::ScalarType>, Vec<G>) = (0..*len)
            .map(|_| {
                (
                    G::ScalarType::generator() * G::ScalarType::rand(&mut thread_rng()),
                    G::generator() * G::ScalarType::rand(&mut thread_rng()),
                )
            })
            .unzip();
        c.bench_function(BenchmarkId::new(name.to_string(), len), move |b| {
            b.iter(|| G::multi_scalar_mul(&scalars, &points).unwrap())
        });
    }

    fn blst_msm(c: &mut Criterion) {
        static INPUT_SIZES: [usize; 6] = [32, 64, 128, 256, 512, 1024];
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSM using BLST");
        for size in INPUT_SIZES.iter() {
            blst_msm_single::<G1Element, _>("BLS12381-G1", size, &mut group);
        }
        for size in INPUT_SIZES.iter() {
            blst_msm_single::<G2Element, _>("BLS12381-G2", size, &mut group);
        }
    }

    fn double_scale_single<
        G: GroupElement,
        Mul: ScalarMultiplier<G, G::ScalarType>,
        M: Measurement,
    >(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let g1 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s1 = G::ScalarType::rand(&mut thread_rng());
        let g2 = G::generator() * G::ScalarType::rand(&mut thread_rng());
        let s2 = G::ScalarType::rand(&mut thread_rng());

        let multiplier = Mul::new(g1, G::zero());
        c.bench_function(name.to_string(), move |b| {
            b.iter(|| multiplier.two_scalar_mul(&s1, &g2, &s2))
        });
    }

    fn double_scale(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Double Scalar Multiplication");

        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 16, 5>,
            _,
        >("Secp256r1 Straus (16)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 32, 5>,
            _,
        >("Secp256r1 Straus (32)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 64, 5>,
            _,
        >("Secp256r1 Straus (64)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 128, 5>,
            _,
        >("Secp256r1 Straus (128)", &mut group);
        double_scale_single::<
            ProjectivePoint,
            WindowedScalarMultiplier<ProjectivePoint, secp256r1::Scalar, 256, 5>,
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
        c.bench_function(name.to_string(), move |b| {
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
        c.bench_function(name.to_string(), move |b| b.iter(|| G::pairing(&x, &y)));
    }

    fn pairing(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Pairing");
        pairing_single::<G1Element, _>("BLS12381-G1", &mut group);
    }

    fn sum(c: &mut Criterion) {
        static NUMBER_OF_TERMS: [usize; 4] = [10, 100, 500, 1000];

        for n in NUMBER_OF_TERMS {
            let terms: Vec<G1Element> = (0..n)
                .map(|_| G1Element::generator() * bls12381::Scalar::rand(&mut thread_rng()))
                .collect();

            let terms_uncompressed = terms
                .iter()
                .map(G1ElementUncompressed::from)
                .map(G1ElementUncompressed::into_byte_array)
                .collect::<Vec<_>>();

            let terms_compressed = terms
                .iter()
                .map(G1Element::to_byte_array)
                .collect::<Vec<_>>();

            c.bench_function(&format!("Sum/BLS12381-G1/{} uncompressed", n), move |b| {
                b.iter_batched(
                    || terms_uncompressed.clone(),
                    |t| {
                        let terms_deserialized = t
                            .into_iter()
                            .map(G1ElementUncompressed::from_trusted_byte_array)
                            .collect::<Vec<_>>();
                        G1ElementUncompressed::sum(terms_deserialized.as_slice())
                    },
                    criterion::BatchSize::SmallInput,
                )
            });

            c.bench_function(&format!("Sum/BLS12381-G1/{} compressed", n), move |b| {
                b.iter_batched(
                    || terms_compressed.clone(),
                    |t| {
                        t.iter()
                            .map(G1Element::from_trusted_byte_array)
                            .map(Result::unwrap)
                            .reduce(|a, b| a + b)
                    },
                    criterion::BatchSize::SmallInput,
                )
            });
        }
    }

    /// Implementation of a `Multiplier` where scalar multiplication is done without any pre-computation by
    /// simply calling the GroupElement implementation. Only used for benchmarking.
    struct DefaultMultiplier<G: GroupElement>(G);

    impl<G: GroupElement> ScalarMultiplier<G, G::ScalarType> for DefaultMultiplier<G> {
        fn new(base_element: G, _zero: G) -> Self {
            Self(base_element)
        }

        fn mul(&self, scalar: &G::ScalarType) -> G {
            self.0 * scalar
        }

        fn two_scalar_mul(
            &self,
            base_scalar: &G::ScalarType,
            other_element: &G,
            other_scalar: &G::ScalarType,
        ) -> G {
            self.0 * base_scalar + *other_element * other_scalar
        }
    }

    fn deser_single<
        G: GroupElement + ToFromByteArray<LENGTH> + FromTrustedByteArray<LENGTH>,
        M: Measurement,
        const LENGTH: usize,
    >(
        name: &str,
        trusted: bool,
        c: &mut BenchmarkGroup<M>,
    ) {
        let as_bytes = G::generator().to_byte_array();
        c.bench_function(name.to_string(), move |b| {
            b.iter(|| {
                if trusted {
                    G::from_trusted_byte_array(&as_bytes).unwrap()
                } else {
                    G::from_byte_array(&as_bytes).unwrap()
                }
            })
        });
    }

    fn deserialize(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Deserialize");
        deser_single::<BlsScalar, _, { SCALAR_LENGTH }>(
            "BLS12381-Scalar-trusted",
            true,
            &mut group,
        );
        deser_single::<BlsScalar, _, { SCALAR_LENGTH }>("BLS12381-Scalar", false, &mut group);
        deser_single::<G1Element, _, { G1_ELEMENT_BYTE_LENGTH }>(
            "BLS12381-G1-trusted",
            true,
            &mut group,
        );
        deser_single::<G1Element, _, { G1_ELEMENT_BYTE_LENGTH }>("BLS12381-G1", false, &mut group);
        deser_single::<G2Element, _, { G2_ELEMENT_BYTE_LENGTH }>(
            "BLS12381-G2-trusted",
            true,
            &mut group,
        );
        deser_single::<G2Element, _, { G2_ELEMENT_BYTE_LENGTH }>("BLS12381-G2", false, &mut group);
        deser_single::<GTElement, _, { GT_ELEMENT_BYTE_LENGTH }>(
            "BLS12381-GT-trusted",
            true,
            &mut group,
        );
        deser_single::<GTElement, _, { GT_ELEMENT_BYTE_LENGTH }>("BLS12381-GT", false, &mut group);
    }

    criterion_group! {
        name = group_benches;
        config = Criterion::default().sample_size(100);
        targets =
            deserialize,
            add,
            scale,
            hash_to_group,
            pairing,
            double_scale,
            blst_msm,
            sum,
    }
}

criterion_main!(group_benches::group_benches,);
