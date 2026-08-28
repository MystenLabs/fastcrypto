// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Bulletproofs++ prover and verifier against the Bulletproofs baseline on
//! the same configurations. Source of the tables in
//! `src/bulletproofspp/README.md`.

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fastcrypto::bulletproofs::{Range as BpRange, RangeProof as BpRangeProof};
use fastcrypto::bulletproofspp::{Range, RangeProof};
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use rand::Rng;

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

fn commit(
    values: &[u64],
    rng: &mut rand::rngs::ThreadRng,
) -> (Vec<PedersenCommitment>, Vec<Blinding>) {
    values
        .iter()
        .map(|&v| PedersenCommitment::commit_u64(v, rng))
        .unzip()
}

fn label(range: &Range, m: usize) -> BenchmarkId {
    BenchmarkId::new(format!("{}-bit", range.bits()), m)
}

fn bp_range(range: &Range) -> BpRange {
    match range {
        Range::Bits8 => BpRange::Bits8,
        Range::Bits16 => BpRange::Bits16,
        Range::Bits32 => BpRange::Bits32,
        Range::Bits64 => BpRange::Bits64,
    }
}

fn bp_benchmarks(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let mut grp = c.benchmark_group("BP prove");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let bp_range = bp_range(range);
        let values = values(range, *m, &mut rng);
        let (_, blindings) = commit(&values, &mut rng);
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| {
                BpRangeProof::prove_batch(&values, &blindings, &bp_range, DST, &mut rng).unwrap()
            })
        });
    }
    grp.finish();

    let mut grp = c.benchmark_group("BP verify");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let bp_range = bp_range(range);
        let values = values(range, *m, &mut rng);
        let (commitments, blindings) = commit(&values, &mut rng);
        let proof =
            BpRangeProof::prove_batch(&values, &blindings, &bp_range, DST, &mut rng).unwrap();
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| {
                proof
                    .verify_batch(&commitments, &bp_range, DST, &mut rng)
                    .unwrap()
            })
        });
    }
    grp.finish();
}

fn bppp_benchmarks(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

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
