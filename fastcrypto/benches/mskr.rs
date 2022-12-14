// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;

// cargo criterion --bench mskr --features experimental
mod mskr_benches {
    use blst::blst_fr;
    use blst::blst_scalar;
    use criterion::measurement;
    use criterion::BenchmarkGroup;
    use criterion::BenchmarkId;
    use criterion::Criterion;
    use fastcrypto::bls12381::min_pk::{randomize_g1_pk, randomize_g2_signature};
    use fastcrypto::bls12381::min_sig::get_128bit_scalar;
    use fastcrypto::bls12381::min_sig::get_one;
    use fastcrypto::bls12381::min_sig::{randomize_g1_signature, randomize_g2_pk};
    use fastcrypto::bls12381::{min_pk, min_sig};
    use fastcrypto::hash::HashFunction;
    use fastcrypto::hash::Sha256;
    use fastcrypto::traits::mskr::HashToScalar;
    use fastcrypto::traits::mskr::Randomize;
    use fastcrypto::traits::{AggregateAuthenticator, KeyPair, Signer, VerifyingKey};
    use rand::thread_rng;
    use std::time::Duration;

    const MIN_SIGNERS: usize = 100;
    const MAX_SIGNERS: usize = 1_000;
    const STEP_SIGNERS: usize = 100;

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

        let aggregate_sig = A::aggregate(&sigs).unwrap();

        let data = (aggregate_sig, randomized_pks, msg);

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(data),
            |b, (aggregate_sig, randomized_pks, msg)| {
                b.iter(|| {
                    let r = aggregate_sig.verify(randomized_pks, msg);
                    assert!(r.is_ok());
                });
            },
        );
    }

    fn verify(c: &mut Criterion) {
        let batch_sizes: Vec<usize> = (MIN_SIGNERS..=MAX_SIGNERS).step_by(STEP_SIGNERS).collect();
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

    fn aggregate_single<
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

        let data = sigs;

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &data,
            |b, sigs| {
                b.iter(|| {
                    let _ = A::aggregate(sigs).unwrap();
                });
            },
        );
    }

    fn aggregate(c: &mut Criterion) {
        let batch_sizes: Vec<usize> = (MIN_SIGNERS..=MAX_SIGNERS).step_by(STEP_SIGNERS).collect();
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSKR Aggregate");
        for size in batch_sizes {
            aggregate_single::<
                min_sig::BLS12381KeyPair,
                min_sig::BLS12381AggregateSignature,
                blst_fr,
                min_sig::mskr::BLS12381Hash,
                { <min_sig::BLS12381PublicKey as VerifyingKey>::LENGTH },
                _,
            >("BLS12381 min_sig", size, &mut group);

            aggregate_single::<
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

    fn verify_dabo_min_sig_single<M: measurement::Measurement>(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg = Sha256::digest(*b"Hello, world!").to_vec();

        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kps = (0..size)
            .map(|_| min_sig::BLS12381KeyPair::generate(&mut csprng))
            .collect::<Vec<_>>();
        let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

        let sigs = kps.iter().map(|kp| kp.sign(&msg)).collect::<Vec<_>>();

        let mut rands: Vec<blst_scalar> = Vec::with_capacity(sigs.len());
        rands.push(get_one());
        for _ in 1..sigs.len() {
            rands.push(get_128bit_scalar(&mut csprng));
        }

        let randomized_sigs = sigs
            .iter()
            .zip(rands.iter())
            .zip(pks.iter())
            .map(|((sig, r), pk)| randomize_g1_signature(sig, r).randomize(pk, &pks))
            .collect::<Vec<_>>();

        let aggregate_sig =
            min_sig::BLS12381AggregateSignature::aggregate(&randomized_sigs).unwrap();

        let randomized_pks = pks
            .iter()
            .map(|pk| pk.randomize(pk, &pks))
            .collect::<Vec<_>>();

        let data = (aggregate_sig, randomized_pks, msg, rands);

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(data),
            |b, (aggregate_sig, pks, msg, rands)| {
                b.iter(|| {
                    let randomized_pks = pks
                        .iter()
                        .zip(rands.iter())
                        .map(|(pk, r)| randomize_g2_pk(pk, r))
                        .collect::<Vec<_>>();
                    let r = aggregate_sig.verify(&randomized_pks, msg);
                    assert!(r.is_ok());
                });
            },
        );
    }

    fn verify_dabo_min_pk_single<M: measurement::Measurement>(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg = Sha256::digest(*b"Hello, world!").to_vec();

        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kps = (0..size)
            .map(|_| min_pk::BLS12381KeyPair::generate(&mut csprng))
            .collect::<Vec<_>>();
        let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

        let sigs = kps.iter().map(|kp| kp.sign(&msg)).collect::<Vec<_>>();

        let mut rands: Vec<blst_scalar> = Vec::with_capacity(sigs.len());
        rands.push(get_one());
        for _ in 1..sigs.len() {
            rands.push(get_128bit_scalar(&mut csprng));
        }

        let randomized_sigs = sigs
            .iter()
            .zip(rands.iter())
            .zip(pks.iter())
            .map(|((sig, r), pk)| randomize_g2_signature(sig, r).randomize(pk, &pks))
            .collect::<Vec<_>>();

        let aggregate_sig =
            min_pk::BLS12381AggregateSignature::aggregate(&randomized_sigs).unwrap();

        let randomized_pks = pks
            .iter()
            .map(|pk| pk.randomize(pk, &pks))
            .collect::<Vec<_>>();

        let data = (aggregate_sig, randomized_pks, msg, rands);

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(data),
            |b, (aggregate_sig, pks, msg, rands)| {
                b.iter(|| {
                    let randomized_pks = pks
                        .iter()
                        .zip(rands.iter())
                        .map(|(pk, r)| randomize_g1_pk(pk, r))
                        .collect::<Vec<_>>();
                    let r = aggregate_sig.verify(&randomized_pks, msg);
                    assert!(r.is_ok());
                });
            },
        );
    }

    fn verify_dabo(c: &mut Criterion) {
        let batch_sizes: Vec<usize> = (MIN_SIGNERS..=MAX_SIGNERS).step_by(STEP_SIGNERS).collect();
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSKR Verify DABO");
        for size in batch_sizes {
            verify_dabo_min_sig_single("BLS12381 min_sig", size, &mut group);
            verify_dabo_min_pk_single("BLS12381 min_pk", size, &mut group);
        }
    }

    fn aggregate_dabo_min_sig_single<M: measurement::Measurement>(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg = Sha256::digest(*b"Hello, world!").to_vec();

        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kps = (0..size)
            .map(|_| min_sig::BLS12381KeyPair::generate(&mut csprng))
            .collect::<Vec<_>>();
        let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

        let sigs = kps.iter().map(|kp| kp.sign(&msg)).collect::<Vec<_>>();

        let mut rands: Vec<blst_scalar> = Vec::with_capacity(sigs.len());
        rands.push(get_one());
        for _ in 1..sigs.len() {
            rands.push(get_128bit_scalar(&mut csprng));
        }

        let data = (sigs, rands);

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(data),
            |b, (sigs, rands)| {
                b.iter(|| {
                    let randomized_sigs = sigs
                        .iter()
                        .zip(rands.iter())
                        .zip(pks.iter())
                        .map(|((sig, r), pk)| randomize_g1_signature(sig, r).randomize(pk, &pks))
                        .collect::<Vec<_>>();

                    let _ =
                        min_sig::BLS12381AggregateSignature::aggregate(&randomized_sigs).unwrap();
                });
            },
        );
    }

    fn aggregate_dabo_min_pk_single<M: measurement::Measurement>(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg = Sha256::digest(*b"Hello, world!").to_vec();

        let mut csprng: rand::rngs::ThreadRng = thread_rng();
        let kps = (0..size)
            .map(|_| min_pk::BLS12381KeyPair::generate(&mut csprng))
            .collect::<Vec<_>>();
        let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

        let sigs = kps.iter().map(|kp| kp.sign(&msg)).collect::<Vec<_>>();

        let mut rands: Vec<blst_scalar> = Vec::with_capacity(sigs.len());
        rands.push(get_one());
        for _ in 1..sigs.len() {
            rands.push(get_128bit_scalar(&mut csprng));
        }

        let data = (sigs, rands, pks);

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(data),
            |b, (sigs, rands, pks)| {
                b.iter(|| {
                    let randomized_sigs = sigs
                        .iter()
                        .zip(rands.iter())
                        .zip(pks.iter())
                        .map(|((sig, r), pk)| randomize_g2_signature(sig, r).randomize(pk, &pks))
                        .collect::<Vec<_>>();

                    let _ =
                        min_pk::BLS12381AggregateSignature::aggregate(&randomized_sigs).unwrap();
                });
            },
        );
    }

    fn aggregate_dabo(c: &mut Criterion) {
        let batch_sizes: Vec<usize> = (MIN_SIGNERS..=MAX_SIGNERS).step_by(STEP_SIGNERS).collect();
        let mut group: BenchmarkGroup<_> = c.benchmark_group("MSKR Aggregate DABO");
        for size in batch_sizes {
            aggregate_dabo_min_sig_single("BLS12381 min_sig", size, &mut group);
            aggregate_dabo_min_pk_single("BLS12381 min_pk", size, &mut group);
        }
    }

    criterion_group! {
        name = mskr_benches;
        config = Criterion::default().sample_size(100);
        // targets = verify, verify_dabo, aggregate, aggregate_dabo, keygen, sign,
        targets =  aggregate_dabo
    }
}

criterion_main!(mskr_benches::mskr_benches,);
