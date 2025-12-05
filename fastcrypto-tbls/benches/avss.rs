// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::ristretto255;
use fastcrypto_tbls::ecies_v1;
use fastcrypto_tbls::nodes::{Node, Nodes, PartyId};
use fastcrypto_tbls::threshold_schnorr::avss;
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
) -> avss::Receiver {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight,
        })
        .collect();
    avss::Receiver::new(
        Nodes::new(nodes).unwrap(),
        id,
        threshold,
        b"avss".to_vec(),
        None,
        keys.get(id as usize).unwrap().1.clone(),
    )
}

pub fn setup_dealer(
    threshold: u16,
    f: u16,
    weight: u16, // Per node
    keys: &[(PartyId, ecies_v1::PrivateKey<EG>, ecies_v1::PublicKey<EG>)],
) -> avss::Dealer {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight,
        })
        .collect();
    avss::Dealer::new(
        None,
        Nodes::new(nodes).unwrap(),
        threshold,
        f,
        b"avss".to_vec(),
    )
    .unwrap()
}

mod avss_benches {
    use super::*;
    use fastcrypto_tbls::threshold_schnorr::avss::ProcessedMessage::Valid;
    use fastcrypto_tbls::threshold_schnorr::avss::{PartialOutput, ReceiverOutput};
    use fastcrypto_tbls::types::{IndexedValue, ShareIndex};
    use itertools::Itertools;
    use std::collections::HashMap;

    fn dkg(c: &mut Criterion) {
        const SIZES: [u16; 1] = [100];
        const TOTAL_WEIGHTS: [u16; 3] = [500, 1000, 1500];

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group("AVSS create_message");
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(t, t - 1, w, &keys);
                create.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| d0.create_message(&mut thread_rng())),
                );
            }
        }

        {
            let mut verify: BenchmarkGroup<_> = c.benchmark_group("AVSS process_message");
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(t, t - 1, w, &keys);
                let r1 = setup_receiver(1, t, w, &keys);
                let message = d0.create_message(&mut thread_rng()).unwrap();

                verify.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| r1.process_message(&message).unwrap()),
                );
            }
        }

        {
            let mut verify: BenchmarkGroup<_> = c.benchmark_group("AVSS complete");
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let keys = generate_ecies_keys(*n);
                let nodes = Nodes::new(
                    keys.iter()
                        .map(|(id, _sk, pk)| Node::<EG> {
                            id: *id,
                            pk: pk.clone(),
                            weight: w,
                        })
                        .collect(),
                )
                .unwrap();
                let dealers = (0..*n)
                    .map(|_| setup_dealer(t, t - 1, w, &keys))
                    .collect_vec();
                let r1 = setup_receiver(1, t, w, &keys);
                let messages: HashMap<PartyId, avss::Message> = dealers
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        (
                            PartyId::from(i as u16),
                            d.create_message(&mut thread_rng()).unwrap(),
                        )
                    })
                    .collect();

                let outputs: HashMap<PartyId, PartialOutput> = messages
                    .iter()
                    .map(|(i, m)| {
                        let output = r1.process_message(m).unwrap();
                        if let Valid(o) = output {
                            return (*i, o);
                        }
                        panic!()
                    })
                    .collect();

                verify.bench_function(
                    format!("DKG n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| {
                        b.iter(|| ReceiverOutput::complete_dkg(t, &nodes, outputs.clone()).unwrap())
                    },
                );

                let dealers = (0..total_w)
                    .map(|_| setup_dealer(t, t - 1, w, &keys))
                    .collect_vec();
                let r1 = setup_receiver(1, t, w, &keys);
                let messages: HashMap<PartyId, avss::Message> = dealers
                    .iter()
                    .enumerate()
                    .map(|(i, d)| {
                        (
                            PartyId::from(i as u16),
                            d.create_message(&mut thread_rng()).unwrap(),
                        )
                    })
                    .collect();

                let outputs: HashMap<PartyId, PartialOutput> = messages
                    .iter()
                    .map(|(i, m)| {
                        let output = r1.process_message(m).unwrap();
                        if let Valid(o) = output {
                            return (*i, o);
                        }
                        panic!()
                    })
                    .collect();

                let outputs: Vec<IndexedValue<PartialOutput>> = outputs
                    .iter()
                    .map(|(i, o)| {
                        IndexedValue {
                            index: ShareIndex::new(*i + 1).unwrap(),
                            value: o.clone(),
                        }
                        .clone()
                    })
                    .take(t as usize)
                    .collect_vec();

                verify.bench_function(
                    format!(
                        "Key Rotation n={}, total_weight={}, t={}, w={}",
                        n, total_w, t, w
                    )
                    .as_str(),
                    |b| {
                        b.iter(|| {
                            ReceiverOutput::complete_key_rotation(t, 1, &nodes, &outputs).unwrap()
                        })
                    },
                );
            }
        }
    }

    criterion_group! {
        name = avss_benches;
        config = Criterion::default().sample_size(10);
        targets = dkg,
    }
}

criterion_main!(avss_benches::avss_benches);
