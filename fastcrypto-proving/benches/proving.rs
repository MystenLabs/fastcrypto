// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_crypto_primitives::SNARK;
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, BenchmarkId,
    Criterion, SamplingMode,
};

#[derive(Copy, Clone)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

fn bench_prove<F: PrimeField, E: PairingEngine<Fr = F>, M: Measurement>(
    grp: &mut BenchmarkGroup<M>,
) {
    static VARIABLES: [usize; 5] = [16, 32, 64, 128, 256];

    for size in VARIABLES.iter() {
        let rng = &mut ark_std::test_rng();
        let c = DummyCircuit::<F> {
            a: Some(<F>::rand(rng)),
            b: Some(<F>::rand(rng)),
            num_variables: *size,
            num_constraints: 65536,
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

fn bench_verify<F: PrimeField, E: PairingEngine<Fr = F>, M: Measurement>(
    grp: &mut BenchmarkGroup<M>,
) {
    static VARIABLES: [usize; 5] = [16, 32, 64, 128, 256];

    for size in VARIABLES.iter() {
        let rng = &mut ark_std::test_rng();
        let c = DummyCircuit::<F> {
            a: Some(<F>::rand(rng)),
            b: Some(<F>::rand(rng)),
            num_variables: *size,
            num_constraints: 65536,
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
            BenchmarkId::new("Groth16 verify", *size),
            &(vk, v),
            |b, (vk, v)| {
                b.iter(|| Groth16::<E>::verify(vk, &[*v], &proof).unwrap());
            },
        );
    }
}

fn prove(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Proving");
    // This can take a *while*
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(10);

    // Add fields and pairing engines here
    bench_prove::<BlsFr, Bls12_381, _>(&mut group);

    group.finish();
}

fn verify(c: &mut Criterion) {
    let mut group: BenchmarkGroup<_> = c.benchmark_group("Proving");
    // Add fields and pairing engines here
    bench_verify::<BlsFr, Bls12_381, _>(&mut group);

    group.finish();
}

criterion_group! {
    name = proving_benches;
    config = Criterion::default();
    targets =
       verify,
       prove,
}

criterion_main!(proving_benches,);
