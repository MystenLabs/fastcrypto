// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use fastcrypto_zkp::bppp::{Range, RangeProof};
use rand::Rng;

const DST: &[u8] = b"bench";

/// (range, batch size) configurations matching bulletproofpp's
/// benches/BENCHMARKS.md, for direct comparison.
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

fn setup(
    range: &Range,
    m: usize,
    rng: &mut rand::rngs::ThreadRng,
) -> (Vec<u64>, Vec<PedersenCommitment>, Vec<Blinding>) {
    let mask = match range {
        Range::Bits8 => 0xff,
        Range::Bits16 => 0xffff,
        Range::Bits32 => 0xffff_ffff,
        Range::Bits64 => u64::MAX,
    };
    let values: Vec<u64> = (0..m).map(|_| rng.gen::<u64>() & mask).collect();
    let (commitments, blindings) = values
        .iter()
        .map(|&v| PedersenCommitment::commit_u64(v, rng))
        .unzip();
    (values, commitments, blindings)
}

fn label(range: &Range, m: usize) -> BenchmarkId {
    let bits = match range {
        Range::Bits8 => 8,
        Range::Bits16 => 16,
        Range::Bits32 => 32,
        Range::Bits64 => 64,
    };
    BenchmarkId::new(format!("{bits}-bit"), m)
}

fn bench_bppp(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let mut grp = c.benchmark_group("BPPP prove");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let (values, _, blindings) = setup(range, *m, &mut rng);
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| RangeProof::prove_batch(&values, &blindings, range, DST, &mut rng).unwrap())
        });
    }
    grp.finish();

    let mut grp = c.benchmark_group("BPPP verify");
    grp.warm_up_time(Duration::from_secs(1));
    grp.measurement_time(Duration::from_secs(3));
    for (range, m) in &CONFIGS {
        let (values, commitments, blindings) = setup(range, *m, &mut rng);
        let proof = RangeProof::prove_batch(&values, &blindings, range, DST, &mut rng).unwrap();
        grp.bench_function(label(range, *m), |b| {
            b.iter(|| proof.verify_batch(&commitments, range, DST).unwrap())
        });
    }
    grp.finish();
}

criterion_group!(benches, bench_bppp);
criterion_main!(benches);
