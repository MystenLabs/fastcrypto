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
        bls12381::{BLS12381AggregateSignature, BLS12381KeyPair, BLS12381Signature},
        ed25519::*,
        hash::Blake2b,
        secp256k1::{Secp256k1KeyPair, Secp256k1Signature},
        traits::{AggregateAuthenticator, KeyPair, VerifyingKey},
        Verifier,
    };
    use generic_array::typenum::U32;
    use rand::{prelude::ThreadRng, thread_rng};
    use signature::Signer;

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let ed_keypair = Ed25519KeyPair::generate(&mut csprng);
        let blst_keypair = BLS12381KeyPair::generate(&mut csprng);
        let secp256k1_keypair = Secp256k1KeyPair::generate(&mut csprng);
        let msg: &[u8] = b"";

        c.bench_function("Ed25519 signing", move |b| b.iter(|| ed_keypair.sign(msg)));
        c.bench_function("BLS12381 signing", move |b| {
            b.iter(|| blst_keypair.sign(msg))
        });
        c.bench_function("Secp256k1 signing", move |b| {
            b.iter(|| secp256k1_keypair.sign(msg))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let ed_keypair = Ed25519KeyPair::generate(&mut csprng);
        let blst_keypair = BLS12381KeyPair::generate(&mut csprng.clone());
        let secp256k1_keypair = Secp256k1KeyPair::generate(&mut csprng.clone());

        let ed_public = ed_keypair.public();
        let blst_public = blst_keypair.public();
        let secp256k1_public = secp256k1_keypair.public();

        let msg: &[u8] = b"";
        let ed_sig: Ed25519Signature = ed_keypair.sign(msg);
        let blst_sig: BLS12381Signature = blst_keypair.sign(msg);
        let secp256k1_sig: Secp256k1Signature = secp256k1_keypair.sign(msg);

        c.bench_function("Ed25519 signature verification", move |b| {
            b.iter(|| ed_public.verify(msg, &ed_sig))
        });
        c.bench_function("BLS12381 signature verification", move |b| {
            b.iter(|| blst_public.verify(msg, &blst_sig))
        });
        c.bench_function("Secp256k1 signature verification", move |b| {
            b.iter(|| secp256k1_public.verify(msg, &secp256k1_sig))
        });
    }

    fn verify_batch_signatures<M: measurement::Measurement>(c: &mut BenchmarkGroup<M>) {
        static BATCH_SIZES: [usize; 10] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];

        let mut csprng: ThreadRng = thread_rng();

        for size in BATCH_SIZES.iter() {
            let ed_keypairs: Vec<_> = (0..*size)
                .map(|_| Ed25519KeyPair::generate(&mut csprng))
                .collect();
            let blst_keypairs: Vec<_> = (0..*size)
                .map(|_| BLS12381KeyPair::generate(&mut csprng))
                .collect();

            let msg: Vec<u8> = fastcrypto::hash::Hashable::digest::<Blake2b<U32>>(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
            )
            .to_vec();

            let ed_signatures: Vec<_> = ed_keypairs.iter().map(|key| key.sign(&msg)).collect();
            let ed_public_keys: Vec<_> =
                ed_keypairs.iter().map(|key| key.public().clone()).collect();
            let blst_signatures: Vec<_> = blst_keypairs.iter().map(|key| key.sign(&msg)).collect();
            let blst_public_keys: Vec<_> = blst_keypairs
                .iter()
                .map(|key| key.public().clone())
                .collect();
            let blst_aggregate_signature =
                BLS12381AggregateSignature::aggregate(&blst_signatures).unwrap();

            c.bench_with_input(
                BenchmarkId::new("Ed25519 batch verification", *size),
                &(msg.clone(), ed_public_keys, ed_signatures),
                |b, i| {
                    b.iter(|| VerifyingKey::verify_batch_empty_fail(&i.0, &i.1[..], &i.2[..]));
                },
            );
            c.bench_with_input(
                BenchmarkId::new("BLS12381 batch verification", *size),
                &(
                    msg.clone(),
                    blst_public_keys.clone(),
                    blst_signatures.clone(),
                ),
                |b, i| {
                    b.iter(|| VerifyingKey::verify_batch_empty_fail(&i.0, &i.1[..], &i.2[..]));
                },
            );
            c.bench_with_input(
                BenchmarkId::new("BLS12381 aggregate verification", *size),
                &(msg, blst_public_keys, blst_aggregate_signature),
                |b, (msg, pk, sig)| {
                    b.iter(|| sig.verify(pk, msg));
                },
            );
        }
    }

    fn aggregate_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 10] = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];

        let mut csprng: ThreadRng = thread_rng();

        for size in BATCH_SIZES.iter() {
            let blst_keypairs: Vec<_> = (0..*size)
                .map(|_| BLS12381KeyPair::generate(&mut csprng))
                .collect();

            let msg: Vec<u8> = fastcrypto::hash::Hashable::digest::<Blake2b<U32>>(
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

        c.bench_function("Ed25519 keypair generation", move |b| {
            b.iter(|| Ed25519KeyPair::generate(&mut csprng))
        });

        c.bench_function("BLS12381 keypair generation", move |b| {
            b.iter(|| BLS12381KeyPair::generate(&mut csprng2))
        });
        c.bench_function("Secp256k1 keypair generation", move |b| {
            b.iter(|| Secp256k1KeyPair::generate(&mut csprng3))
        });
    }

    criterion_group! {
        name = signature_benches;
        config = Criterion::default();
        targets =
           sign,
           verify,
           verification_comparison,
           aggregate_signatures,
           key_generation
    }

    fn verification_comparison(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("verification_comparison");
        group.sampling_mode(SamplingMode::Flat);

        verify_batch_signatures(&mut group);
        group.finish();
    }
}

criterion_main!(signature_benches::signature_benches,);
