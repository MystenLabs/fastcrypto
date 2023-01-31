// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod ecvrf_ristretto_benches {

    use criterion::Criterion;
    use fastcrypto::vrf::ecvrf::ECVRFKeyPair;
    use fastcrypto::vrf::VRFKeyPair;
    use fastcrypto::vrf::VRFProof;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    fn keygen(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        c.bench_function("ECVRF Ristretto key generation", move |b| {
            b.iter(|| ECVRFKeyPair::generate(&mut csprng))
        });
    }

    fn proof(c: &mut Criterion) {
        let kp = ECVRFKeyPair::generate(&mut thread_rng());
        let input = b"Hello, world!";
        c.bench_function("ECVRF Ristretto proving", move |b| {
            b.iter(|| kp.prove(input))
        });
    }

    fn verify(c: &mut Criterion) {
        let kp = ECVRFKeyPair::generate(&mut thread_rng());
        let input = b"Hello, world!";
        let proof = kp.prove(input);
        c.bench_function("ECVRF Ristretto verification", move |b| {
            b.iter(|| proof.verify(input, &kp.pk))
        });
    }

    criterion_group! {
        name = ecvrf_ristretto_benches;
        config = Criterion::default().sample_size(100);
        targets = keygen, proof, verify,
    }
}

criterion_main!(ecvrf_ristretto_benches::ecvrf_ristretto_benches,);
