// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;
extern crate ed25519_consensus;
extern crate rand;

mod signature_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::{
        bls12377::{BLS12377AggregateSignature, BLS12377KeyPair},
        bls12381::{BLS12381AggregateSignature, BLS12381KeyPair},
        ed25519::*,
        hash::{Blake2b256, HashFunction},
        secp256k1::Secp256k1KeyPair,
        traits::{AggregateAuthenticator, KeyPair, VerifyingKey},
        Verifier,
    };
    use rand::{prelude::ThreadRng, thread_rng};
    use signature::Signer;

    fn sign_single<KP: KeyPair>(name: &str, c: &mut Criterion) {
        let msg: &[u8] = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        c.bench_function(&(name.to_string() + " signing"), move |b| {
            b.iter(|| keypair.sign(msg))
        });
    }

    fn sign(c: &mut Criterion) {
        sign_single::<Ed25519KeyPair>("Ed25519", c);
        sign_single::<BLS12381KeyPair>("BLS12381", c);
        sign_single::<BLS12377KeyPair>("BLS12377", c);
        sign_single::<Secp256k1KeyPair>("Sepc256k1", c);
    }

    fn verify_single<KP: KeyPair>(name: &str, c: &mut Criterion) {
        let msg = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        let public_key = keypair.public();
        let signature = keypair.sign(msg);
        c.bench_function(&(name.to_string() + " signature verification"), move |b| {
            b.iter(|| public_key.verify(msg, &signature))
        });
    }

    fn verify(c: &mut Criterion) {
        verify_single::<Ed25519KeyPair>("Ed25519", c);
        verify_single::<BLS12381KeyPair>("BLS12381", c);
        verify_single::<BLS12377KeyPair>("BLS12377", c);
        verify_single::<Secp256k1KeyPair>("Sepc256k1", c);
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
            BenchmarkId::new(name.to_string() + " batched verification", size),
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
            BenchmarkId::new(name.to_string() + " aggregate verification", size),
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
            BenchmarkId::new(
                name.to_string() + " batched verification with different messages",
                size,
            ),
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
            BenchmarkId::new(
                name.to_string() + " aggregate verification with different messages",
                size,
            ),
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

    fn verify_batch_signatures<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZES: [usize; 10] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];
        for size in BATCH_SIZES.iter() {
            verify_batch_signatures_single::<Ed25519KeyPair, _>("Ed25519", *size, c);
            verify_batch_signatures_single::<BLS12377KeyPair, _>("BLS12377", *size, c);
            verify_batch_signatures_single::<BLS12381KeyPair, _>("BLS12381", *size, c);
            verify_aggregate_signatures_single::<BLS12377KeyPair, BLS12377AggregateSignature, _>(
                "BLS12377", *size, c,
            );
            verify_aggregate_signatures_single::<BLS12381KeyPair, BLS12381AggregateSignature, _>(
                "BLS12381", *size, c,
            );
        }
    }

    fn verify_batch_signatures_different_msg<M: measurement::Measurement>(
        c: &mut BenchmarkGroup<M>,
    ) {
        static BATCH_SIZES: [usize; 10] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];
        for size in BATCH_SIZES.iter() {
            verify_batch_signatures_different_msg_single::<Ed25519KeyPair, _>("Ed25519", *size, c);
            verify_aggregate_signatures_different_msg_single::<
                Ed25519KeyPair,
                Ed25519AggregateSignature,
                _,
            >("Ed25519", *size, c);
            verify_batch_signatures_different_msg_single::<BLS12377KeyPair, _>(
                "BLS12377", *size, c,
            );
            verify_aggregate_signatures_different_msg_single::<
                BLS12377KeyPair,
                BLS12377AggregateSignature,
                _,
            >("BLS12377", *size, c);
            verify_batch_signatures_different_msg_single::<BLS12381KeyPair, _>(
                "BLS12381", *size, c,
            );
            verify_aggregate_signatures_different_msg_single::<
                BLS12381KeyPair,
                BLS12381AggregateSignature,
                _,
            >("BLS12381", *size, c);
        }
    }

    fn aggregate_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 10] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];

        let mut csprng: ThreadRng = thread_rng();

        for size in BATCH_SIZES.iter() {
            let blst_keypairs: Vec<_> = (0..*size)
                .map(|_| BLS12381KeyPair::generate(&mut csprng))
                .collect();

            let msg: Vec<u8> = Blake2b256::digest(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
            )
            .to_vec();

            let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(&msg)).collect();

            c.bench_with_input(
                BenchmarkId::new("BLS12381 signature aggregation", *size),
                &(blst_signatures),
                |b, sig| {
                    b.iter(|| BLS12381AggregateSignature::aggregate(sig).unwrap());
                },
            );
        }
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let mut csprng2 = csprng.clone();
        let mut csprng3 = csprng.clone();
        let mut csprng4 = csprng.clone();

        c.bench_function("Ed25519 keypair generation", move |b| {
            b.iter(|| Ed25519KeyPair::generate(&mut csprng))
        });
        c.bench_function("BLS12381 keypair generation", move |b| {
            b.iter(|| BLS12381KeyPair::generate(&mut csprng2))
        });
        c.bench_function("BLS12377 keypair generation", move |b| {
            b.iter(|| BLS12377KeyPair::generate(&mut csprng3))
        });
        c.bench_function("Secp256k1 keypair generation", move |b| {
            b.iter(|| Secp256k1KeyPair::generate(&mut csprng4))
        });
    }

    fn verification_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("verification_comparison");
        group.sampling_mode(SamplingMode::Flat);

        verify_batch_signatures(&mut group);
        verify_batch_signatures_different_msg(&mut group);
        group.finish();
    }

    criterion_group! {
        name = signature_benches;
        config = Criterion::default();
        targets =
           sign,
           verify,
           verification_comparison,
           aggregate_signatures,
           key_generation,
    }
}

criterion_main!(signature_benches::signature_benches,);
