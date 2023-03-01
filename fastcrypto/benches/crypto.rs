// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;
extern crate ed25519_consensus;
extern crate rand;

mod signature_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::secp256k1::Secp256k1KeyPair;
    use fastcrypto::secp256r1::Secp256r1KeyPair;
    use fastcrypto::traits::Signer;
    use fastcrypto::traits::{RecoverableSignature, RecoverableSigner};
    use fastcrypto::{
        bls12381,
        ed25519::*,
        hash::{Blake2b256, HashFunction},
        traits::{AggregateAuthenticator, KeyPair, VerifyingKey},
    };
    use rand::{prelude::ThreadRng, thread_rng};
    use std::borrow::Borrow;

    fn sign_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg: &[u8] = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        c.bench_function(&(name.to_string()), move |b| b.iter(|| keypair.sign(msg)));
    }

    fn sign_recoverable_single<KP: KeyPair + RecoverableSigner, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg: &[u8] = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| keypair.sign_recoverable(msg))
        });
    }

    fn sign(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Sign");
        sign_single::<Ed25519KeyPair, _>("Ed25519", &mut group);
        sign_single::<bls12381::min_sig::BLS12381KeyPair, _>("BLS12381MinSig", &mut group);
        sign_single::<bls12381::min_pk::BLS12381KeyPair, _>("BLS12381MinPk", &mut group);
        sign_single::<Secp256k1KeyPair, _>("Secp256k1", &mut group);
        sign_single::<Secp256r1KeyPair, _>("Secp256r1", &mut group);
        sign_recoverable_single::<Secp256k1KeyPair, _>("Secp256k1 recoverable", &mut group);
        sign_recoverable_single::<Secp256r1KeyPair, _>("Secp256r1 recoverable", &mut group);
    }

    fn verify_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        let public_key = keypair.public();
        let signature = keypair.sign(msg);
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| public_key.verify(msg, &signature))
        });
    }

    fn recover_single<KP: RecoverableSigner + KeyPair, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        let signature = keypair.sign_recoverable(msg);
        c.bench_function(&(name.to_string()), move |b| {
            b.iter(|| signature.recover(msg))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Verify");
        verify_single::<Ed25519KeyPair, _>("Ed25519", &mut group);
        verify_single::<bls12381::min_sig::BLS12381KeyPair, _>("BLS12381MinSig", &mut group);
        verify_single::<bls12381::min_pk::BLS12381KeyPair, _>("BLS12381MinPk", &mut group);
        verify_single::<Secp256k1KeyPair, _>("Secp256k1", &mut group);
        verify_single::<Secp256r1KeyPair, _>("Secp256r1", &mut group);
        recover_single::<Secp256k1KeyPair, _>("Secp256k1 recoverable", &mut group);
        recover_single::<Secp256r1KeyPair, _>("Secp256r1 recoverable", &mut group);
    }

    struct TestDataBatchedVerification<KP: KeyPair> {
        msg: Vec<u8>,
        public_keys: Vec<<KP as KeyPair>::PubKey>,
        signatures: Vec<<KP as KeyPair>::Sig>,
    }

    /// Generate keys and signatures for the same message and a given signature scheme.
    fn generate_test_data<KP: KeyPair>(size: usize) -> TestDataBatchedVerification<KP> {
        let msg: Vec<u8> = Blake2b256::digest(b"Hello, world!".as_slice()).to_vec();

        let mut csprng: ThreadRng = thread_rng();
        let keypairs: Vec<_> = (0..size).map(|_| KP::generate(&mut csprng)).collect();
        let signatures: Vec<_> = keypairs.iter().map(|key| key.sign(&msg)).collect();
        let public_keys: Vec<_> = keypairs.iter().map(|key| key.public().clone()).collect();

        TestDataBatchedVerification {
            msg,
            public_keys,
            signatures,
        }
    }

    fn verify_batch_signatures_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let test_data = generate_test_data::<KP>(size);
        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(
                &test_data.msg,
                &test_data.public_keys,
                &test_data.signatures,
            ),
            |b, (m, pks, sigs)| {
                b.iter(|| VerifyingKey::verify_batch_empty_fail(m, pks, sigs));
            },
        );
    }

    fn verify_aggregate_signatures_single<
        KP: KeyPair,
        A: AggregateAuthenticator<Sig = KP::Sig, PrivKey = KP::PrivKey, PubKey = KP::PubKey>,
        M: measurement::Measurement,
    >(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let test_data = generate_test_data::<KP>(size);

        let aggregate_signature = A::aggregate(&test_data.signatures).unwrap();

        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(&test_data.msg, &test_data.public_keys, &aggregate_signature),
            |b, (msg, pks, sig)| {
                b.iter(|| sig.verify(pks, msg));
            },
        );
    }

    struct TestDataBatchedVerificationDifferentMsgs<KP: KeyPair> {
        msgs: Vec<[u8; 32]>,
        public_keys: Vec<<KP as KeyPair>::PubKey>,
        signatures: Vec<<KP as KeyPair>::Sig>,
    }

    /// Generate messages, keys and signatures (same number of each) for a given signature scheme.
    fn generate_test_data_different_msg<KP: KeyPair>(
        size: usize,
    ) -> TestDataBatchedVerificationDifferentMsgs<KP> {
        let msgs: Vec<[u8; 32]> = (0..size)
            .map(|i| fastcrypto::hash::Sha256::digest(i.to_string().as_bytes()).digest)
            .collect();

        let mut csprng: ThreadRng = thread_rng();
        let keypairs: Vec<_> = (0..size).map(|_| KP::generate(&mut csprng)).collect();
        let signatures: Vec<_> = keypairs
            .iter()
            .zip(&msgs)
            .map(|(key, msg)| key.sign(msg))
            .collect();
        let public_keys: Vec<_> = keypairs.iter().map(|key| key.public().clone()).collect();

        TestDataBatchedVerificationDifferentMsgs {
            msgs,
            public_keys,
            signatures,
        }
    }

    fn verify_batch_signatures_different_msg_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let test_data = generate_test_data_different_msg::<KP>(size);
        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(
                &test_data.msgs,
                &test_data.public_keys,
                &test_data.signatures,
            ),
            |b, (m, pks, sigs)| {
                b.iter(|| VerifyingKey::verify_batch_empty_fail_different_msg(m, pks, sigs));
            },
        );
    }

    fn verify_aggregate_signatures_different_msg_single<
        KP: KeyPair,
        A: AggregateAuthenticator<Sig = KP::Sig, PrivKey = KP::PrivKey, PubKey = KP::PubKey>,
        M: measurement::Measurement,
    >(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let test_data = generate_test_data_different_msg::<KP>(size);
        let aggregate_signature = A::aggregate(&test_data.signatures).unwrap();
        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(
                test_data
                    .msgs
                    .iter()
                    .map(|m| m.as_slice())
                    .collect::<Vec<&[u8]>>(),
                test_data.public_keys,
                aggregate_signature,
            ),
            |b, (msgs, pk, sig)| {
                b.iter(|| sig.verify_different_msg(pk, msgs));
            },
        );
    }

    /// Benchmark batch verification of multiple signatures over the same message.
    fn verify_batch_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 5] = [4, 8, 16, 32, 64];
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Verify batch");
        for size in BATCH_SIZES.iter() {
            verify_batch_signatures_single::<Secp256k1KeyPair, _>(
                "Secp256k1_batch",
                *size,
                &mut group,
            );
            verify_batch_signatures_single::<Secp256r1KeyPair, _>(
                "Secp256r1_batch",
                *size,
                &mut group,
            );
            verify_batch_signatures_single::<Ed25519KeyPair, _>("Ed25519_batch", *size, &mut group);
            verify_batch_signatures_single::<bls12381::min_sig::BLS12381KeyPair, _>(
                "BLS12381MinSig_batched",
                *size,
                &mut group,
            );
            verify_batch_signatures_single::<bls12381::min_pk::BLS12381KeyPair, _>(
                "BLS12381MinPk_batched",
                *size,
                &mut group,
            );
            verify_aggregate_signatures_single::<
                bls12381::min_sig::BLS12381KeyPair,
                bls12381::min_sig::BLS12381AggregateSignature,
                _,
            >("BLS12381MinSig_aggregated", *size, &mut group);
            verify_aggregate_signatures_single::<
                bls12381::min_pk::BLS12381KeyPair,
                bls12381::min_pk::BLS12381AggregateSignature,
                _,
            >("BLS12381MinPk_aggregated", *size, &mut group);
        }
    }

    /// Benchmark batch verification of multiple signatures over different messages.
    fn verify_batch_signatures_different_msg(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 5] = [4, 8, 16, 32, 64];

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Verify batch different messages");

        for size in BATCH_SIZES.iter() {
            verify_batch_signatures_different_msg_single::<Secp256r1KeyPair, _>(
                "Secp256r1_batch",
                *size,
                &mut group,
            );

            verify_batch_signatures_different_msg_single::<Secp256k1KeyPair, _>(
                "Secp256k1_batch",
                *size,
                &mut group,
            );

            verify_batch_signatures_different_msg_single::<Ed25519KeyPair, _>(
                "Ed25519_batch",
                *size,
                &mut group,
            );
            verify_aggregate_signatures_different_msg_single::<
                Ed25519KeyPair,
                Ed25519AggregateSignature,
                _,
            >("Ed25519_aggregate", *size, &mut group);
            verify_batch_signatures_different_msg_single::<bls12381::min_sig::BLS12381KeyPair, _>(
                "BLS12381MinSig_batch",
                *size,
                &mut group,
            );
            verify_batch_signatures_different_msg_single::<bls12381::min_pk::BLS12381KeyPair, _>(
                "BLS12381MinPk_batch",
                *size,
                &mut group,
            );
            verify_aggregate_signatures_different_msg_single::<
                bls12381::min_sig::BLS12381KeyPair,
                bls12381::min_sig::BLS12381AggregateSignature,
                _,
            >("BLS12381MinSig_aggregate", *size, &mut group);
            verify_aggregate_signatures_different_msg_single::<
                bls12381::min_pk::BLS12381KeyPair,
                bls12381::min_pk::BLS12381AggregateSignature,
                _,
            >("BLS12381MinPk_aggregate", *size, &mut group);
        }
    }

    struct TestDataBatchedVerificationDifferentMsgsDifferentKeys<
        KP: KeyPair,
        AS: AggregateAuthenticator<Sig = KP::Sig>,
    > {
        msgs: Vec<[u8; 32]>,
        public_keys: Vec<Vec<<KP as KeyPair>::PubKey>>,
        signatures: Vec<AS>,
    }

    fn generate_test_data_different_msg_different_key<
        KP: KeyPair,
        AS: AggregateAuthenticator<Sig = KP::Sig>,
    >(
        size: usize,
    ) -> TestDataBatchedVerificationDifferentMsgsDifferentKeys<KP, AS> {
        let mut result = TestDataBatchedVerificationDifferentMsgsDifferentKeys {
            msgs: Vec::new(),
            public_keys: Vec::new(),
            signatures: Vec::new(),
        };
        let mut csprng: ThreadRng = thread_rng();
        for i in 0..size {
            let msg = fastcrypto::hash::Sha256::digest(i.to_string().as_bytes()).digest;
            result.msgs.push(msg);
            let keypairs: Vec<_> = (0..40).map(|_| KP::generate(&mut csprng)).collect();
            result
                .public_keys
                .push(keypairs.iter().map(|key| key.public().clone()).collect());
            let signatures: Vec<_> = keypairs.iter().map(|key| key.sign(&msg)).collect();
            let sig = AS::aggregate(&signatures).unwrap();
            result.signatures.push(sig);
        }
        result
    }

    fn verify_batch_signatures_different_msg_different_key<
        KP: KeyPair,
        AS: AggregateAuthenticator<Sig = KP::Sig, PubKey = KP::PubKey>,
        M: measurement::Measurement,
    >(
        name: &str,
        size: usize,
        c: &mut BenchmarkGroup<M>,
    ) {
        let test_data = generate_test_data_different_msg_different_key::<KP, AS>(size);
        c.bench_with_input(
            BenchmarkId::new(name.to_string(), size),
            &(test_data.msgs, test_data.public_keys, test_data.signatures),
            |b, (m, pks, sigs)| {
                let sigs_ref = sigs.iter().map(|m| m.borrow()).collect::<Vec<_>>();
                let msgs_ref = m.iter().map(|m| m.borrow()).collect::<Vec<_>>();
                let cloned_pks = pks.clone();
                b.iter(|| {
                    let pks_iters = cloned_pks.iter().map(|pk| pk.iter()).collect::<Vec<_>>();
                    AS::batch_verify(&sigs_ref, pks_iters, &msgs_ref)
                });
            },
        );
    }

    /// Benchmark batch verification of multiple signatures over different messages and different keys.
    fn verify_batch_signatures_different_msg_different_keys(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 5] = [4, 8, 16, 32, 64];

        let mut group: BenchmarkGroup<_> =
            c.benchmark_group("Verify batch different messages different keys");

        for size in BATCH_SIZES.iter() {
            verify_batch_signatures_different_msg_different_key::<
                bls12381::min_sig::BLS12381KeyPair,
                bls12381::min_sig::BLS12381AggregateSignature,
                _,
            >("BLS12381MinSig_aggregate", *size, &mut group);
            verify_batch_signatures_different_msg_different_key::<
                bls12381::min_pk::BLS12381KeyPair,
                bls12381::min_pk::BLS12381AggregateSignature,
                _,
            >("BLS12381MinPk_aggregate", *size, &mut group);
        }
    }

    fn aggregate_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 5] = [4, 8, 16, 32, 64];
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Aggregate signatures");

        let mut csprng: ThreadRng = thread_rng();

        for size in BATCH_SIZES.iter() {
            let blst_min_sig_keypairs: Vec<_> = (0..*size)
                .map(|_| bls12381::min_sig::BLS12381KeyPair::generate(&mut csprng))
                .collect();
            let blst_min_pk_keypairs: Vec<_> = (0..*size)
                .map(|_| bls12381::min_pk::BLS12381KeyPair::generate(&mut csprng))
                .collect();

            let msg: Vec<u8> = Blake2b256::digest(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
            )
            .to_vec();

            let blst_min_sig_signatures: Vec<_> = blst_min_sig_keypairs
                .iter()
                .map(|key| key.sign(&msg))
                .collect();
            let blst_min_pk_signatures: Vec<_> = blst_min_pk_keypairs
                .iter()
                .map(|key| key.sign(&msg))
                .collect();

            group.bench_with_input(
                BenchmarkId::new("BLS12381MinSig", *size),
                &(blst_min_sig_signatures),
                |b, sig| {
                    b.iter(|| {
                        bls12381::min_sig::BLS12381AggregateSignature::aggregate(sig).unwrap()
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new("BLS12381MinPk", *size),
                &(blst_min_pk_signatures),
                |b, sig| {
                    b.iter(|| {
                        bls12381::min_pk::BLS12381AggregateSignature::aggregate(sig).unwrap()
                    });
                },
            );
        }
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let mut csprng2 = csprng.clone();
        let mut csprng3 = csprng.clone();
        let mut csprng4 = csprng.clone();
        let mut csprng5 = csprng.clone();

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Key generation");

        group.bench_function("Ed25519", move |b| {
            b.iter(|| Ed25519KeyPair::generate(&mut csprng))
        });
        group.bench_function("BLS12381MinSig", move |b| {
            b.iter(|| bls12381::min_sig::BLS12381KeyPair::generate(&mut csprng2))
        });
        group.bench_function("BLS12381MinPk", move |b| {
            b.iter(|| bls12381::min_pk::BLS12381KeyPair::generate(&mut csprng3))
        });
        group.bench_function("Secp256k1", move |b| {
            b.iter(|| Secp256k1KeyPair::generate(&mut csprng4))
        });
        group.bench_function("Secp256r1", move |b| {
            b.iter(|| Secp256r1KeyPair::generate(&mut csprng5))
        });
    }

    criterion_group! {
        name = signature_benches;
        config = Criterion::default().sample_size(20);
        targets =
           sign,
           verify,
           verify_batch_signatures,
           verify_batch_signatures_different_msg,
           verify_batch_signatures_different_msg_different_keys,
           aggregate_signatures,
           key_generation,
    }
}

criterion_main!(signature_benches::signature_benches,);
