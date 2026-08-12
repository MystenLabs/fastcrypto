// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;
extern crate rand;

mod mldsa65_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::hash::{Blake2b256, HashFunction};
    use fastcrypto::traits::{KeyPair, Signer, ToFromBytes, VerifyingKey};
    use fastcrypto_pq::mldsa65::{
        MLDSA65KeyPair, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA65Signature,
    };
    use rand::{prelude::ThreadRng, thread_rng};

    fn sign(c: &mut Criterion) {
        // Sign a 32-byte digest: Sui signs the Blake2b intent digest, not the transaction.
        let msg = Blake2b256::digest(b"Hello, world!").to_vec();
        let mut csprng: ThreadRng = thread_rng();
        let keypair = MLDSA65KeyPair::generate(&mut csprng);

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Sign");
        group.bench_function("MLDSA65", move |b| b.iter(|| keypair.sign(&msg)));
    }

    fn verify(c: &mut Criterion) {
        let msg = Blake2b256::digest(b"Hello, world!").to_vec();
        let mut csprng: ThreadRng = thread_rng();
        let keypair = MLDSA65KeyPair::generate(&mut csprng);
        let public_key = keypair.public().clone();
        let signature = keypair.sign(&msg);

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Verify");
        group.bench_function("MLDSA65", move |b| {
            b.iter(|| public_key.verify(&msg, &signature))
        });
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Key generation");
        group.bench_function("MLDSA65", move |b| {
            b.iter(|| MLDSA65KeyPair::generate(&mut csprng))
        });

        // Parsing a private key (i.e. the seed) costs a key generation: the wire format is the 32-byte
        // seed, so from_bytes re-runs the FIPS 204 key expansion.
        let mut csprng2: ThreadRng = thread_rng();
        let seed = MLDSA65KeyPair::generate(&mut csprng2).as_ref().to_vec();
        group.bench_function("MLDSA65 private key from bytes", move |b| {
            b.iter(|| MLDSA65PrivateKey::from_bytes(&seed).unwrap())
        });
    }

    fn serde(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair = MLDSA65KeyPair::generate(&mut csprng);
        let msg = Blake2b256::digest(b"Hello, world!").to_vec();
        let signature = keypair.sign(&msg);
        let public = keypair.public().clone();

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Serde");
        let pk_bytes = bincode::serialize(&public).unwrap();
        let sig_bytes = bincode::serialize(&signature).unwrap();
        let kp_bytes = bincode::serialize(&keypair).unwrap();
        group.bench_function("MLDSA65 public key serialize", |b| {
            b.iter(|| bincode::serialize(&public).unwrap())
        });
        group.bench_function("MLDSA65 public key deserialize", |b| {
            b.iter(|| bincode::deserialize::<MLDSA65PublicKey>(&pk_bytes).unwrap())
        });
        group.bench_function("MLDSA65 signature serialize", |b| {
            b.iter(|| bincode::serialize(&signature).unwrap())
        });
        group.bench_function("MLDSA65 signature deserialize", |b| {
            b.iter(|| bincode::deserialize::<MLDSA65Signature>(&sig_bytes).unwrap())
        });
        // Deserializing a key pair is a seed expansion, so this one is not free.
        group.bench_function("MLDSA65 keypair deserialize", |b| {
            b.iter(|| bincode::deserialize::<MLDSA65KeyPair>(&kp_bytes).unwrap())
        });
        group.finish();
    }

    criterion_group! {
        name = mldsa65_benches;
        config = Criterion::default().sample_size(20);
        targets =
            sign,
            verify,
            key_generation,
            serde,
    }
}

criterion_main!(mldsa65_benches::mldsa65_benches,);
