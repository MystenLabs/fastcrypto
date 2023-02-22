// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bls12381::mskr::Randomize;
use crate::bls12381::{min_pk, min_sig};
use crate::traits::Signer;
use crate::traits::{AggregateAuthenticator, KeyPair, VerifyingKey};
use rand::thread_rng;

#[test]
fn verify_randomized_signature_bls12381_min_pk() {
    let kp = min_pk::BLS12381KeyPair::generate(&mut thread_rng());

    let pks = (0..4)
        .map(|_| {
            let kp = min_pk::BLS12381KeyPair::generate(&mut thread_rng());
            kp.public().clone()
        })
        .collect::<Vec<_>>();

    let msg = b"Hello world";

    let randomized_kp = kp.randomize(kp.public(), &pks);
    let sig = kp.sign(msg);

    assert!(kp.public().verify(msg, &sig).is_ok());

    assert!(randomized_kp.public().verify(msg, &sig).is_err());

    let randomized_sig = randomized_kp.sign(msg);
    assert!(randomized_kp.public().verify(msg, &randomized_sig).is_ok());

    assert!(randomized_kp
        .public()
        .verify(msg, &sig.randomize(kp.public(), &pks))
        .is_ok());
}

#[test]
fn verify_aggregate_all_bls12381_min_pk() {
    let kps = (0..4)
        .map(|_| min_pk::BLS12381KeyPair::generate(&mut thread_rng()))
        .collect::<Vec<_>>();

    let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

    let msg: &[u8] = b"Hello, world!";
    let sigs = kps
        .iter()
        .map(|kp| kp.randomize(kp.public(), &pks).sign(msg))
        .collect::<Vec<_>>();

    let randomized_pks = pks
        .iter()
        .map(|pk| pk.randomize(pk, &pks))
        .collect::<Vec<_>>();

    let aggregate_sig = min_pk::BLS12381AggregateSignature::aggregate(&sigs).unwrap();

    assert!(aggregate_sig.verify(&randomized_pks, msg).is_ok())
}

#[test]
fn verify_aggregate_subset_bls12381_min_pk() {
    let kps = (0..4)
        .map(|_| min_pk::BLS12381KeyPair::generate(&mut thread_rng()))
        .collect::<Vec<_>>();

    let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

    let msg: &[u8] = b"Hello, world!";
    let sigs = kps
        .iter()
        .skip(1)
        .map(|kp| kp.randomize(kp.public(), &pks).sign(msg))
        .collect::<Vec<_>>();

    let randomized_pks = pks
        .iter()
        .skip(1)
        .map(|pk| pk.randomize(pk, &pks))
        .collect::<Vec<_>>();
    let aggregate_sig = min_pk::BLS12381AggregateSignature::aggregate(&sigs).unwrap();

    assert!(aggregate_sig.verify(&randomized_pks, msg).is_ok())
}

#[test]
fn verify_randomized_signature_bls12381_min_sig() {
    let kp = min_sig::BLS12381KeyPair::generate(&mut thread_rng());

    let pks = (0..4)
        .map(|_| {
            let kp = min_sig::BLS12381KeyPair::generate(&mut thread_rng());
            kp.public().clone()
        })
        .collect::<Vec<_>>();

    let msg = b"Hello world";

    let randomized_kp = kp.randomize(kp.public(), &pks);
    let sig = kp.sign(msg);

    assert!(kp.public().verify(msg, &sig).is_ok());

    assert!(randomized_kp.public().verify(msg, &sig).is_err());

    let randomized_sig = randomized_kp.sign(msg);
    assert!(randomized_kp.public().verify(msg, &randomized_sig).is_ok());

    assert!(randomized_kp
        .public()
        .verify(msg, &sig.randomize(kp.public(), &pks))
        .is_ok());
}

#[test]
fn verify_aggregate_all_bls12381_min_sig() {
    let kps = (0..4)
        .map(|_| min_sig::BLS12381KeyPair::generate(&mut thread_rng()))
        .collect::<Vec<_>>();

    let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

    let msg: &[u8] = b"Hello, world!";
    let sigs = kps
        .iter()
        .map(|kp| kp.randomize(kp.public(), &pks).sign(msg))
        .collect::<Vec<_>>();

    let randomized_pks = pks
        .iter()
        .map(|pk| pk.randomize(pk, &pks))
        .collect::<Vec<_>>();

    let aggregate_sig = min_sig::BLS12381AggregateSignature::aggregate(&sigs).unwrap();

    assert!(aggregate_sig.verify(&randomized_pks, msg).is_ok())
}

#[test]
fn verify_aggregate_subset_bls12381_min_sig() {
    let kps = (0..4)
        .map(|_| min_sig::BLS12381KeyPair::generate(&mut thread_rng()))
        .collect::<Vec<_>>();

    let pks = kps.iter().map(|kp| kp.public().clone()).collect::<Vec<_>>();

    let msg: &[u8] = b"Hello, world!";
    let sigs = kps
        .iter()
        .skip(1)
        .map(|kp| kp.randomize(kp.public(), &pks).sign(msg))
        .collect::<Vec<_>>();

    let randomized_pks = pks
        .iter()
        .skip(1)
        .map(|pk| pk.randomize(pk, &pks))
        .collect::<Vec<_>>();
    let aggregate_sig = min_sig::BLS12381AggregateSignature::aggregate(&sigs).unwrap();

    assert!(aggregate_sig.verify(&randomized_pks, msg).is_ok())
}
