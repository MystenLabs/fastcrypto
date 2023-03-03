// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use ark_bls12_377::{Bls12_377, Fr as Bls377Fr};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_bn254::{Bn254, Fr as Bn254Fr};

use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_std::rand::thread_rng;
use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion, SamplingMode,
};
use fastcrypto_zkp::dummy_circuits::DummyCircuit;
use std::ops::Mul;

#[path = "./conversions.rs"]
mod conversions;

fn bench_prove<F: PrimeField, E: Pairing<ScalarField = F>, M: Measurement>(
    grp: &mut BenchmarkGroup<M>,
) {
    static CONSTRAINTS: [usize; 5] = [8, 9, 10, 11, 12];

    for size in CONSTRAINTS.iter() {
        let rng = &mut thread_rng();
        let c = DummyCircuit::<F> {
            a: Some(<F>::rand(rng)),
            b: Some(<F>::rand(rng)),
            num_variables: 12,
            num_constraints: (1 << *size),
        };

        let (pk, _) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();

        grp.bench_with_input(
            BenchmarkId::new("Groth16 prove", *size),
            &(pk, c),
            |b, (pk, c)| {
                b.iter(|| Groth16::<E>::prove(pk, *c, rng).unwrap());
            },
        );
    }
}

fn bench_verify<F: PrimeField, E: Pairing<ScalarField = F>, M: Measurement>(
    grp: &mut BenchmarkGroup<M>,
) {
    static CONSTRAINTS: [usize; 5] = [8, 9, 10, 11, 12];

    for size in CONSTRAINTS.iter() {
        let rng = &mut thread_rng();
        let c = DummyCircuit::<F> {
            a: Some(<F>::rand(rng)),
            b: Some(<F>::rand(rng)),
            num_variables: 12,
            num_constraints: (1 << *size),
        };

        let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
        let proof = Groth16::<E>::prove(&pk, c, rng).unwrap();
        let v = c.a.unwrap().mul(c.b.unwrap());

        grp.bench_with_input(
            BenchmarkId::new("Groth16 process verifying key", *size),
            &vk,
            |b, vk| {
                b.iter(|| Groth16::<E>::process_vk(vk).unwrap());
            },
        );
        let pvk = Groth16::<E>::process_vk(&vk).unwrap();

        grp.bench_with_input(
            BenchmarkId::new("Groth16 verify with processed vk", *size),
            &(pvk, v),
            |b, (pvk, v)| {
                b.iter(|| Groth16::<E>::verify_with_processed_vk(pvk, &[*v], &proof).unwrap());
            },
        );

        grp.bench_with_input(
            BenchmarkId::new("Groth16 end-to-end verify", *size),
            &(vk, v),
            |b, (vk, v)| {
                b.iter(|| Groth16::<E>::verify(vk, &[*v], &proof).unwrap());
            },
        );
    }
}

fn bench_our_verify<M: Measurement>(grp: &mut BenchmarkGroup<M>) {
    static CONSTRAINTS: [usize; 5] = [8, 9, 10, 11, 12];

    for size in CONSTRAINTS.iter() {
        let rng = &mut thread_rng();
        let c = DummyCircuit::<BlsFr> {
            a: Some(<BlsFr>::rand(rng)),
            b: Some(<BlsFr>::rand(rng)),
            num_variables: 12,
            num_constraints: (1 << *size),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
        let proof = Groth16::<Bls12_381>::prove(&pk, c, rng).unwrap();
        let v = c.a.unwrap().mul(c.b.unwrap());

        grp.bench_with_input(
            BenchmarkId::new("BLST-based Groth16 process verifying key", *size),
            &vk,
            |b, vk| {
                b.iter(|| fastcrypto_zkp::verifier::process_vk_special(vk));
            },
        );
        let pvk = fastcrypto_zkp::verifier::process_vk_special(&vk);

        grp.bench_with_input(
            BenchmarkId::new("BLST-based Groth16 verify with processed vk", *size),
            &(pvk, v),
            |b, (pvk, v)| {
                b.iter(|| {
                    fastcrypto_zkp::verifier::verify_with_processed_vk(pvk, &[*v], &proof).unwrap()
                });
            },
        );
    }
}

fn prove(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-381 Proving");
    group.sampling_mode(SamplingMode::Flat); // This can take a *while*
    group.sample_size(10);
    bench_prove::<BlsFr, Bls12_381, _>(&mut group);
    group.finish();

    // Add fields and pairing engines here
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BN254 Proving");
    group.sampling_mode(SamplingMode::Flat); // This can take a *while*
    group.sample_size(10);
    bench_prove::<Bn254Fr, Bn254, _>(&mut group);
    group.finish();

    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-377 Proving");
    group.sampling_mode(SamplingMode::Flat); // This can take a *while*
    group.sample_size(10);
    bench_prove::<Bls377Fr, Bls12_377, _>(&mut group);
    group.finish();
}

fn verify(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-381 Verification");
    // Add fields and pairing engines here
    bench_verify::<BlsFr, Bls12_381, _>(&mut group);
    bench_our_verify(&mut group);
    group.finish();

    // Add fields and pairing engines here
    let mut group: BenchmarkGroup<_> = c.benchmark_group("BN254 Verification");
    bench_verify::<Bn254Fr, Bn254, _>(&mut group);
    group.finish();

    let mut group: BenchmarkGroup<_> = c.benchmark_group("BLS12-377 Verification");
    bench_verify::<Bls377Fr, Bls12_377, _>(&mut group);
    group.finish();
}

criterion_group! {
    name = proving_benches;
    config = Criterion::default();
    targets =
       verify,
       prove,
}

criterion_main!(conversions::conversion_benches, proving_benches,);
