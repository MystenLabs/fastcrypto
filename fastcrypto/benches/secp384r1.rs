// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Benchmarks comparing fastcrypto's optimized secp384r1 (NIST P-384) ECDSA implementation with
//! the RustCrypto p384 crate on identical inputs.

#[macro_use]
extern crate criterion;

mod secp384r1_benches {
    use super::*;
    use criterion::*;
    use fastcrypto::secp384r1::Secp384r1KeyPair;
    use fastcrypto::traits::{KeyPair, Signer, VerifyingKey};
    use p384::ecdsa::signature::{Signer as ExternalSigner, Verifier as ExternalVerifier};
    use rand::thread_rng;

    const MSG: &[u8] = b"Hello, world!";

    /// Generate a fastcrypto key pair and an identical RustCrypto p384 signing key.
    fn keys() -> (Secp384r1KeyPair, p384::ecdsa::SigningKey) {
        let kp = Secp384r1KeyPair::generate(&mut thread_rng());
        let external_sk = p384::ecdsa::SigningKey::from_slice(kp.as_ref()).unwrap();
        (kp, external_sk)
    }

    fn sign(c: &mut Criterion) {
        let (kp, external_sk) = keys();

        // Sanity check: the two implementations produce identical signatures.
        let external_sig: p384::ecdsa::Signature = external_sk.sign(MSG);
        assert_eq!(kp.sign(MSG).as_ref(), external_sig.to_bytes().as_slice());

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Secp384r1 sign");
        group.bench_function("fastcrypto", |b| b.iter(|| kp.sign(MSG)));
        group.bench_function("rust_crypto_p384", |b| {
            b.iter(|| {
                let _: p384::ecdsa::Signature = external_sk.sign(MSG);
            })
        });
    }

    fn verify(c: &mut Criterion) {
        let (kp, external_sk) = keys();
        let signature = kp.sign(MSG);
        let external_vk = p384::ecdsa::VerifyingKey::from(&external_sk);
        let external_sig = p384::ecdsa::Signature::from_slice(signature.as_ref()).unwrap();

        // Sanity check: both implementations accept the signature.
        assert!(kp.public().verify(MSG, &signature).is_ok());
        assert!(external_vk.verify(MSG, &external_sig).is_ok());

        let mut group: BenchmarkGroup<_> = c.benchmark_group("Secp384r1 verify");
        group.bench_function("fastcrypto", |b| {
            b.iter(|| kp.public().verify(MSG, &signature))
        });
        group.bench_function("rust_crypto_p384", |b| {
            b.iter(|| external_vk.verify(MSG, &external_sig))
        });
    }

    criterion_group! {
        name = secp384r1_benches;
        config = Criterion::default().sample_size(100);
        targets = sign, verify,
    }
}

criterion_main!(secp384r1_benches::secp384r1_benches);
