// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::{bls12381, ristretto255};
use fastcrypto_tbls::dkg::Party;
use fastcrypto_tbls::ecies;
use fastcrypto_tbls::nodes::{Node, Nodes, PartyId};
use fastcrypto_tbls::random_oracle::RandomOracle;
use itertools::iproduct;
use rand::thread_rng;

type G = bls12381::G2Element;
type EG = ristretto255::RistrettoPoint;

fn gen_ecies_keys(n: u16) -> Vec<(PartyId, ecies::PrivateKey<EG>, ecies::PublicKey<EG>)> {
    (0..n)
        .map(|id| {
            let sk = ecies::PrivateKey::<EG>::new(&mut thread_rng());
            let pk = ecies::PublicKey::<EG>::from_private_key(&sk);
            (id, sk, pk)
        })
        .collect()
}

pub fn setup_party(
    id: PartyId,
    threshold: u32,
    weight: u16,
    keys: &[(PartyId, ecies::PrivateKey<EG>, ecies::PublicKey<EG>)],
) -> Party<G, EG> {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight,
        })
        .collect();
    Party::<G, EG>::new(
        keys.get(id as usize).unwrap().1.clone(),
        Nodes::new(nodes).unwrap(),
        threshold,
        RandomOracle::new("dkg"),
        &mut thread_rng(),
    )
    .unwrap()
}

mod dkg_benches {
    use super::*;

    fn dkg(c: &mut Criterion) {
        const SIZES: [u16; 1] = [100];
        const TOTAL_WEIGHTS: [u16; 4] = [2000, 2500, 3333, 5000];

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group("DKG create");
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let t = (total_w / 3) as u32;
                let keys = gen_ecies_keys(*n);
                let d0 = setup_party(0, t, w, &keys);

                create.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| d0.create_message(&mut thread_rng())),
                );

                let message = d0.create_message(&mut thread_rng());
                println!(
                    "Message size for n={}, t={}: {}",
                    n,
                    t,
                    bcs::to_bytes(&message).unwrap().len(),
                );
            }
        }

        {
            let mut verify: BenchmarkGroup<_> = c.benchmark_group("DKG message processing");
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let t = (total_w / 3) as u32;
                let keys = gen_ecies_keys(*n);
                let d0 = setup_party(0, t, w, &keys);
                let d1 = setup_party(1, t, w, &keys);
                let message = d0.create_message(&mut thread_rng());

                verify.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| {
                        b.iter(|| {
                            d1.process_message(message.clone(), &mut thread_rng())
                                .unwrap()
                        })
                    },
                );
            }
        }
    }

    criterion_group! {
        name = dkg_benches;
        config = Criterion::default();
        targets = dkg,
    }
}

criterion_main!(dkg_benches::dkg_benches);
