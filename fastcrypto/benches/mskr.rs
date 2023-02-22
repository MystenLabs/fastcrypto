// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

mod mskr_benches {
    use criterion::measurement;

    use blst::blst_fr;
    use criterion::BenchmarkGroup;
    use criterion::BenchmarkId;
    use criterion::Criterion;
    use fastcrypto::bls12381::mskr::HashToScalar;
    use fastcrypto::bls12381::mskr::Randomize;
    use fastcrypto::bls12381::{min_pk, min_sig};
    use fastcrypto::hash::HashFunction;
    use fastcrypto::hash::Sha256;
    use fastcrypto::traits::{AggregateAuthenticator, KeyPair, Signer, VerifyingKey};
    use rand::thread_rng;

    fn verify_single<
        KP: KeyPair + Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
        A: AggregateAuthenticator<Sig = KP::Sig, PrivKey = KP::PrivKey, PubKey = KP::PubKey>,
        S,
        H: HashToScalar<S>,
        const PUBKEY_LENGTH: usize,
        M: measurement::Measurement,
    >(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) where
        KP::PubKey: Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
    {
        let msg = Sha256::digest(*b"Hello, world!").to_vec();

        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kps = (0..size)
            .map(|_| KP::generate(&mut csprng))
            .collect::<Vec<_>>();
        let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

        let sigs = kps
            .iter()
            .map(|kp| kp.randomize(kp.public(), &pks).sign(&msg))
            .collect::<Vec<_>>();

        let randomized_pks = pks
            .iter()
            .map(|pk| pk.randomize(pk, &pks))
            .collect::<Vec<_>>();

        let data = (sigs, randomized_pks, msg);

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(data),
            |b, (sigs, randomized_pks, msg)| {
                b.iter(|| {
                    let aggregate_sig = A::aggregate(sigs).unwrap();
                    let r = aggregate_sig.verify(randomized_pks, msg);
                    assert!(r.is_ok());
                });
            },
        );
    }

    fn verify(c: &mut Criterion) {
        let batch_sizes: Vec<usize> = (100..=1_000).step_by(100).collect();
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSKR Verify");
        for size in batch_sizes {
            verify_single::<
                min_sig::BLS12381KeyPair,
                min_sig::BLS12381AggregateSignature,
                blst_fr,
                min_sig::mskr::BLS12381Hash,
                { <min_sig::BLS12381PublicKey as VerifyingKey>::LENGTH },
                _,
            >("BLS12381 min_sig", size, &mut group);

            verify_single::<
                min_pk::BLS12381KeyPair,
                min_pk::BLS12381AggregateSignature,
                blst_fr,
                min_pk::mskr::BLS12381Hash,
                { <min_pk::BLS12381PublicKey as VerifyingKey>::LENGTH },
                _,
            >("BLS12381 min_pk", size, &mut group);
        }
    }

    fn verify_dabo_single<
        KP: KeyPair + Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
        A: AggregateAuthenticator<Sig = KP::Sig, PrivKey = KP::PrivKey, PubKey = KP::PubKey>,
        S,
        H: HashToScalar<S>,
        const PUBKEY_LENGTH: usize,
        M: measurement::Measurement,
    >(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) where
        KP::PubKey: Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
    {
        let msgs: Vec<_> = (0..size)
            .map(|i| fastcrypto::hash::Sha256::digest(i.to_string().as_bytes()).digest)
            .collect();

        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kps = (0..size)
            .map(|_| KP::generate(&mut csprng))
            .collect::<Vec<_>>();
        let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

        let sigs = kps
            .iter()
            .zip(msgs.iter())
            .map(|(kp, msg)| kp.randomize(kp.public(), &pks).sign(msg.as_slice()))
            .collect::<Vec<_>>();

        let randomized_pks = pks
            .iter()
            .map(|pk| pk.randomize(pk, &pks))
            .collect::<Vec<_>>();

        let data = (sigs, randomized_pks, msgs);

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(data),
            |b, (sigs, randomized_pks, msgs)| {
                b.iter(|| {
                    let r = KP::PubKey::verify_batch_empty_fail_different_msg(
                        msgs,
                        randomized_pks,
                        sigs,
                    );
                    assert!(r.is_ok());
                });
            },
        );
    }

    fn verify_dabo(c: &mut Criterion) {
        let batch_sizes: Vec<usize> = (100..=1_000).step_by(100).collect();
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSKR Verify DABO");
        for size in batch_sizes {
            verify_dabo_single::<
                min_sig::BLS12381KeyPair,
                min_sig::BLS12381AggregateSignature,
                blst_fr,
                min_sig::mskr::BLS12381Hash,
                { <min_sig::BLS12381PublicKey as VerifyingKey>::LENGTH },
                _,
            >("BLS12381 min_sig", size, &mut group);

            verify_dabo_single::<
                min_pk::BLS12381KeyPair,
                min_pk::BLS12381AggregateSignature,
                blst_fr,
                min_pk::mskr::BLS12381Hash,
                { <min_pk::BLS12381PublicKey as VerifyingKey>::LENGTH },
                _,
            >("BLS12381 min_pk", size, &mut group);
        }
    }

    fn keygen_single<
        KP: KeyPair + Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
        A: AggregateAuthenticator<Sig = KP::Sig, PrivKey = KP::PrivKey, PubKey = KP::PubKey>,
        S,
        H: HashToScalar<S>,
        const PUBKEY_LENGTH: usize,
        M: measurement::Measurement,
    >(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) where
        KP::PubKey: Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
    {
        let total = 1_00;

        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kps = (0..total)
            .map(|_| min_pk::BLS12381KeyPair::generate(&mut csprng))
            .collect::<Vec<_>>();
        let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

        c.bench_function(&(name.to_string()), |b| {
            b.iter(|| {
                let mut csprng: rand::rngs::ThreadRng = thread_rng();
                let kp = min_pk::BLS12381KeyPair::generate(&mut csprng);
                kp.randomize(kp.public(), &pks);
            });
        });
    }

    fn keygen(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSKR Keygen");
        keygen_single::<
            min_sig::BLS12381KeyPair,
            min_sig::BLS12381AggregateSignature,
            blst_fr,
            min_sig::mskr::BLS12381Hash,
            { <min_sig::BLS12381PublicKey as VerifyingKey>::LENGTH },
            _,
        >("BLS12381 min_sig", &mut group);

        keygen_single::<
            min_pk::BLS12381KeyPair,
            min_pk::BLS12381AggregateSignature,
            blst_fr,
            min_pk::mskr::BLS12381Hash,
            { <min_pk::BLS12381PublicKey as VerifyingKey>::LENGTH },
            _,
        >("BLS12381 min_pk", &mut group);
    }

    fn sign_single<
        KP: KeyPair + Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
        A: AggregateAuthenticator<Sig = KP::Sig, PrivKey = KP::PrivKey, PubKey = KP::PubKey>,
        S,
        H: HashToScalar<S>,
        const PUBKEY_LENGTH: usize,
        M: measurement::Measurement,
    >(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) where
        KP::PubKey: Randomize<KP::PubKey, S, H, PUBKEY_LENGTH>,
    {
        let msg = Sha256::digest(*b"Hello, world!").to_vec();
        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kp = min_pk::BLS12381KeyPair::generate(&mut csprng);

        c.bench_function(&(name.to_string()), |b| {
            b.iter(|| {
                kp.sign(&msg);
            });
        });
    }

    fn sign(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSKR Sign");
        sign_single::<
            min_sig::BLS12381KeyPair,
            min_sig::BLS12381AggregateSignature,
            blst_fr,
            min_sig::mskr::BLS12381Hash,
            { <min_sig::BLS12381PublicKey as VerifyingKey>::LENGTH },
            _,
        >("BLS12381 min_sig", &mut group);

        sign_single::<
            min_pk::BLS12381KeyPair,
            min_pk::BLS12381AggregateSignature,
            blst_fr,
            min_pk::mskr::BLS12381Hash,
            { <min_pk::BLS12381PublicKey as VerifyingKey>::LENGTH },
            _,
        >("BLS12381 min_pk", &mut group);
    }

    criterion_group! {
        name = mskr_benches;
        config = Criterion::default().sample_size(100);
        targets = verify, verify_dabo, keygen, sign,
    }
}

criterion_main!(mskr_benches::mskr_benches,);
