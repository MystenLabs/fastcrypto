// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
#[macro_use]
extern crate criterion;
extern crate ed25519_consensus;
extern crate rand;

mod serialization_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::secp256k1::Secp256k1KeyPair;
    use fastcrypto::secp256r1::Secp256r1KeyPair;
    use fastcrypto::traits::Signer;
    use fastcrypto::{bls12381, ed25519::*, traits::KeyPair};
    use rand::{prelude::ThreadRng, thread_rng};

    fn serialize_signature_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg: &[u8] = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        let signature = keypair.sign(msg);
        c.bench_function(name.to_string(), move |b| {
            b.iter(|| bincode::serialize(&signature))
        });
    }

    fn serialize_public_key_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        c.bench_function(name.to_string(), move |b| {
            b.iter(|| bincode::serialize(&keypair.public()))
        });
    }

    fn serialize_signature(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Serialize signature");
        serialize_signature_single::<Ed25519KeyPair, _>("Ed25519", &mut group);
        serialize_signature_single::<bls12381::min_sig::BLS12381KeyPair, _>(
            "BLS12381MinSig",
            &mut group,
        );
        serialize_signature_single::<bls12381::min_pk::BLS12381KeyPair, _>(
            "BLS12381MinPk",
            &mut group,
        );
        serialize_signature_single::<Secp256k1KeyPair, _>("Secp256k1", &mut group);
        serialize_signature_single::<Secp256r1KeyPair, _>("Secp256r1", &mut group);
    }

    fn serialize_public_key(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Serialize public key");
        serialize_public_key_single::<Ed25519KeyPair, _>("Ed25519", &mut group);
        serialize_public_key_single::<bls12381::min_sig::BLS12381KeyPair, _>(
            "BLS12381MinSig",
            &mut group,
        );
        serialize_public_key_single::<bls12381::min_pk::BLS12381KeyPair, _>(
            "BLS12381MinPk",
            &mut group,
        );
        serialize_public_key_single::<Secp256k1KeyPair, _>("Secp256k1", &mut group);
        serialize_public_key_single::<Secp256r1KeyPair, _>("Secp256r1", &mut group);
    }

    fn deserialize_signature_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg: &[u8] = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        let signature = keypair.sign(msg);
        let serialized = bincode::serialize(&signature).unwrap();
        c.bench_function(name.to_string(), move |b| {
            b.iter(|| bincode::deserialize::<KP::Sig>(&serialized))
        });
    }

    fn deserialize_public_key_single<KP: KeyPair, M: measurement::Measurement>(
        name: &str,
        c: &mut BenchmarkGroup<M>,
    ) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair = KP::generate(&mut csprng);
        let serialized = bincode::serialize(&keypair.public()).unwrap();
        c.bench_function(name.to_string(), move |b| {
            b.iter(|| bincode::deserialize::<KP::PubKey>(&serialized))
        });
    }

    fn deserialize_signature(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Deserialize signature");
        deserialize_signature_single::<Ed25519KeyPair, _>("Ed25519", &mut group);
        deserialize_signature_single::<bls12381::min_sig::BLS12381KeyPair, _>(
            "BLS12381MinSig",
            &mut group,
        );
        deserialize_signature_single::<bls12381::min_pk::BLS12381KeyPair, _>(
            "BLS12381MinPk",
            &mut group,
        );
        deserialize_signature_single::<Secp256k1KeyPair, _>("Secp256k1", &mut group);
        deserialize_signature_single::<Secp256r1KeyPair, _>("Secp256r1", &mut group);
        deserialize_bls_signature_non_compact(&mut group);
    }

    fn deserialize_public_key(c: &mut Criterion) {
        let mut group: BenchmarkGroup<_> = c.benchmark_group("Deserialize public key");
        deserialize_public_key_single::<Ed25519KeyPair, _>("Ed25519", &mut group);
        deserialize_public_key_single::<bls12381::min_sig::BLS12381KeyPair, _>(
            "BLS12381MinSig",
            &mut group,
        );
        deserialize_public_key_single::<bls12381::min_pk::BLS12381KeyPair, _>(
            "BLS12381MinPk",
            &mut group,
        );
        deserialize_public_key_single::<Secp256k1KeyPair, _>("Secp256k1", &mut group);
        deserialize_public_key_single::<Secp256r1KeyPair, _>("Secp256r1", &mut group);
    }

    fn deserialize_bls_signature_non_compact<M: measurement::Measurement>(
        c: &mut BenchmarkGroup<M>,
    ) {
        let msg: &[u8] = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = bls12381::min_pk::BLS12381KeyPair::generate(&mut csprng);
        let signature = keypair.sign(msg);
        let serialized = signature.sig.serialize();
        c.bench_function("BLS12381MinPk non-compact", move |b| {
            b.iter(|| bincode::deserialize::<bls12381::min_pk::BLS12381Signature>(&serialized))
        });

        let msg: &[u8] = b"";
        let mut csprng: ThreadRng = thread_rng();
        let keypair = bls12381::min_sig::BLS12381KeyPair::generate(&mut csprng);
        let signature = keypair.sign(msg);
        let serialized = signature.sig.serialize();
        c.bench_function("BLS12381MinSig non-compact", move |b| {
            b.iter(|| bincode::deserialize::<bls12381::min_sig::BLS12381Signature>(&serialized))
        });
    }

    criterion_group! {
        name = serialization_benches;
        config = Criterion::default().sample_size(100);
        targets =
           deserialize_signature,
           deserialize_public_key,
           serialize_signature,
           serialize_public_key,
    }
}

criterion_main!(serialization_benches::serialization_benches);
