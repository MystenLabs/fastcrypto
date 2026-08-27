// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bulletproofs++ prover and verifier against the Bulletproofs baseline on
//! the same configurations. Source of the tables in
//! `src/bulletproofspp/README.md`.
//!
//! The baseline drives the dalek `bulletproofs` crate directly with its
//! generators built once per configuration; `fastcrypto::bulletproofs`
//! rebuilds them on every call, which would dominate its timings.

use std::time::Duration;

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof as BpRangeProof};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::scalar::Scalar;
use fastcrypto::bulletproofspp::{Range, RangeProof};
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use merlin::Transcript;
use rand::{Rng, RngCore};

const DST: &[u8] = b"bench";

/// (range, batch size) configurations; batch sizes are powers of two so the
/// Bulletproofs aggregation applies to all of them.
const CONFIGS: [(Range, usize); 8] = [
    (Range::Bits16, 1),
    (Range::Bits32, 1),
    (Range::Bits64, 1),
    (Range::Bits16, 4),
    (Range::Bits16, 8),
    (Range::Bits32, 8),
    (Range::Bits64, 16),
    (Range::Bits64, 32),
];

fn values(range: &Range, m: usize, rng: &mut rand::rngs::ThreadRng) -> Vec<u64> {
    (0..m)
        .map(|_| rng.gen::<u64>() & range.max_value())
        .collect()
}

fn label(range: &Range, m: usize) -> BenchmarkId {
    BenchmarkId::new(format!("{}-bit", range.bits()), m)
}

fn bp_benchmarks(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let pc_gens = PedersenGens::default();
    let blindings = |m: usize, rng: &mut rand::rngs::ThreadRng| -> Vec<Scalar> {
        (0..m)
            .map(|_| {
                let mut bytes = [0u8; 64];
                rng.fill_bytes(&mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            })
            .collect()
    };

    let mut grp = c.benchmark_group("BP prove");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let n = range.bits();
        let bp_gens = BulletproofGens::new(n, *m);
        let values = values(range, *m, &mut rng);
        let blindings = blindings(*m, &mut rng);
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| {
                BpRangeProof::prove_multiple_with_rng(
                    &bp_gens,
                    &pc_gens,
                    &mut Transcript::new(DST),
                    &values,
                    &blindings,
                    n,
                    &mut rng,
                )
                .unwrap()
            })
        });
    }
    grp.finish();

    let mut grp = c.benchmark_group("BP verify");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let n = range.bits();
        let bp_gens = BulletproofGens::new(n, *m);
        let values = values(range, *m, &mut rng);
        let blindings = blindings(*m, &mut rng);
        let (proof, commitments) = BpRangeProof::prove_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut Transcript::new(DST),
            &values,
            &blindings,
            n,
            &mut rng,
        )
        .unwrap();
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| {
                proof
                    .verify_multiple_with_rng(
                        &bp_gens,
                        &pc_gens,
                        &mut Transcript::new(DST),
                        &commitments,
                        n,
                        &mut rng,
                    )
                    .unwrap()
            })
        });
    }
    grp.finish();
}

fn bppp_benchmarks(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let commit = |values: &[u64],
                  rng: &mut rand::rngs::ThreadRng|
     -> (Vec<PedersenCommitment>, Vec<Blinding>) {
        values
            .iter()
            .map(|&v| PedersenCommitment::commit_u64(v, rng))
            .unzip()
    };

    let mut grp = c.benchmark_group("BPPP prove");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let values = values(range, *m, &mut rng);
        let (_, blindings) = commit(&values, &mut rng);
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| RangeProof::prove_batch(&values, &blindings, range, DST, &mut rng).unwrap())
        });
    }
    grp.finish();

    let mut grp = c.benchmark_group("BPPP verify");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let values = values(range, *m, &mut rng);
        let (commitments, blindings) = commit(&values, &mut rng);
        let proof = RangeProof::prove_batch(&values, &blindings, range, DST, &mut rng).unwrap();
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| proof.verify_batch(&commitments, range, DST).unwrap())
        });
    }
    grp.finish();
}

criterion_group!(benches, bp_benchmarks, bppp_benchmarks);
criterion_main!(benches);
