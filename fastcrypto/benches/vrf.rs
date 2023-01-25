// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod vrf_benches {

    use criterion::Criterion;
    use fastcrypto::vrf::ecvrf::ECVRFKeyPair;
    use fastcrypto::vrf::VRFKeyPair;
    use fastcrypto::vrf::VRFProof;
    use rand::rngs::ThreadRng;
    use rand::thread_rng;

    fn keygen(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        c.bench_function("ECVRF key generation", move |b| {
            b.iter(|| ECVRFKeyPair::generate(&mut csprng))
        });
    }

    fn proof(c: &mut Criterion) {
        let kp = ECVRFKeyPair::generate(&mut thread_rng());
        let input = b"Hello, world!";
        c.bench_function("ECVRF proving", move |b| b.iter(|| kp.prove(input)));
    }

    fn verify(c: &mut Criterion) {
        let kp = ECVRFKeyPair::generate(&mut thread_rng());
        let input = b"Hello, world!";
        let proof = kp.prove(input);
        c.bench_function("ECVRF verification", move |b| {
            b.iter(|| proof.verify(input, &kp.pk))
        });
    }

    criterion_group! {
        name = vrf_benches;
        config = Criterion::default().sample_size(100);
        targets = keygen, proof, verify,
    }
}

criterion_main!(vrf_benches::vrf_benches,);
