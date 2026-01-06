// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::ristretto255;
use fastcrypto_tbls::ecies_v1;
use fastcrypto_tbls::nodes::{Node, Nodes, PartyId};
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use itertools::iproduct;
use rand::thread_rng;

type EG = ristretto255::RistrettoPoint;

fn generate_ecies_keys(
    n: u16,
) -> Vec<(PartyId, ecies_v1::PrivateKey<EG>, ecies_v1::PublicKey<EG>)> {
    (0..n)
        .map(|id| {
            let sk = ecies_v1::PrivateKey::<EG>::new(&mut thread_rng());
            let pk = ecies_v1::PublicKey::<EG>::from_private_key(&sk);
            (id, sk, pk)
        })
        .collect()
}

pub fn setup_receiver(
    id: PartyId,
    threshold: u16,
    weight: u16, // Per node
    keys: &[(PartyId, ecies_v1::PrivateKey<EG>, ecies_v1::PublicKey<EG>)],
) -> batch_avss::Receiver {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight,
        })
        .collect();
    batch_avss::Receiver::new(
        Nodes::new(nodes).unwrap(),
        id,
        threshold,
        b"avss".to_vec(),
        keys.get(id as usize).unwrap().1.clone(),
    )
}

pub fn setup_dealer(
    threshold: u16,
    f: u16,
    weight: u16, // Per node
    keys: &[(PartyId, ecies_v1::PrivateKey<EG>, ecies_v1::PublicKey<EG>)],
) -> batch_avss::Dealer {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight,
        })
        .collect();
    batch_avss::Dealer::new(Nodes::new(nodes).unwrap(), threshold, f, b"avss".to_vec()).unwrap()
}

mod batch_avss_benches {
    use super::*;
    use fastcrypto_tbls::threshold_schnorr::batch_avss::Dealer;
    use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
    use itertools::Itertools;

    fn all_batch_avss(c: &mut Criterion) {
        //batch_avss::<350>(c);
        //batch_avss::<500>(c);
        batch_avss::<1000>(c);
    }

    fn batch_avss<const BATCH_SIZE: usize>(c: &mut Criterion) {
        const SIZES: [u16; 1] = [100];
        const TOTAL_WEIGHTS: [u16; 3] = [500, 1000, 1500];

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (BATCH_SIZE = {BATCH_SIZE}) create_message"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(t, t - 1, w, &keys);
                create.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| d0.create_message::<BATCH_SIZE>(&mut thread_rng())),
                );
            }
        }

        {
            let mut process: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (BATCH_SIZE = {BATCH_SIZE}) process_message"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(t, t - 1, w, &keys);
                let r1 = setup_receiver(1, t, w, &keys);
                let message = d0.create_message::<BATCH_SIZE>(&mut thread_rng()).unwrap();

                process.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| r1.process_message(&message).unwrap()),
                );
            }
        }
        {
            let mut complete: BenchmarkGroup<_> =
                c.benchmark_group(format!("BATCH_AVSS (BATCH_SIZE = {BATCH_SIZE}) presigning"));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let keys = generate_ecies_keys(*n);
                let dealers: Vec<Dealer> = (0..total_w)
                    .map(|_| setup_dealer(t, t - 1, w, &keys))
                    .collect();
                let r1 = setup_receiver(1, t, w, &keys);
                let outputs = dealers
                    .iter()
                    .map(|d| {
                        let message = d.create_message::<BATCH_SIZE>(&mut thread_rng()).unwrap();
                        assert_valid_batch(r1.process_message(&message).unwrap())
                    })
                    .collect_vec();

                complete.bench_function(
                    format!("create/n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| {
                        b.iter(|| {
                            Presignatures::<BATCH_SIZE>::new(outputs.clone(), t as usize - 1)
                                .unwrap()
                        })
                    },
                );

                let mut presignatures =
                    Presignatures::<BATCH_SIZE>::new(outputs.clone(), t as usize - 1).unwrap();

                complete.bench_function(
                    format!("next/n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| presignatures.next().unwrap()),
                );
            }
        }
    }

    criterion_group! {
        name = batch_avss_benches;
        config = Criterion::default().sample_size(10);
        targets = all_batch_avss,
    }
}

criterion_main!(batch_avss_benches::batch_avss_benches);

fn assert_valid_batch<const N: usize>(
    processed_message: batch_avss::ProcessedMessage<N>,
) -> batch_avss::ReceiverOutput<N> {
    if let batch_avss::ProcessedMessage::Valid(output) = processed_message {
        output
    } else {
        panic!("Expected valid message");
    }
}
