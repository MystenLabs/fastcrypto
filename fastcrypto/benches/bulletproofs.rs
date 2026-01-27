// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use std::iter;
use criterion::*;
use fastcrypto::bulletproofs::{Range, RangeProof};
use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::pedersen::{Blinding, PedersenCommitment};
use rand::{thread_rng, Rng};

fn verification(c: &mut Criterion) {
    static INPUT_SIZES: [usize; 4] = [1, 2, 4, 8];
    let ranges = vec![Range::Bits8, Range::Bits16, Range::Bits32, Range::Bits64];
    let mut rng = thread_rng();

    for size in INPUT_SIZES {
        for range in &ranges {
            let bits = range_to_bits(range);
            let values = iter::repeat_with(|| rng.gen_range(0..1 << bits)).take(size)
                .collect::<Vec<_>>();
            let (commitments, blindings): (Vec<PedersenCommitment>, Vec<Blinding>) = values
                .iter()
                .map(|&v| PedersenCommitment::commit(&RistrettoScalar::from(v), &mut rng))
                .unzip();
            let proof =
                RangeProof::prove_batch(&values, &blindings, range, &mut thread_rng()).unwrap();
            c.bench_function(
                &format!("bulletproofs/verification/range={}/inputs={}", bits, size),
                |b| {
                    b.iter(|| proof.verify_batch(&commitments, range, &mut thread_rng()));
                },
            );
        }
    }
}

fn range_to_bits(range: &Range) -> u64 {
    match range {
        Range::Bits8 => 8,
        Range::Bits16 => 16,
        Range::Bits32 => 32,
        Range::Bits64 => 64,
    }
}

criterion_group! {
    name = bulletproofs;
    config = Criterion::default();
    targets = verification,
}

criterion_main!(bulletproofs);
