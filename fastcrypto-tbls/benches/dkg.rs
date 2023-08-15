// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::{bls12381, ristretto255};
use fastcrypto_tbls::dkg::Party;
use fastcrypto_tbls::ecies;
use fastcrypto_tbls::nodes::{Node, PartyId};
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
        nodes,
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
        const WEIGHTS: [u16; 2] = [20, 33];

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group("DKG create");
            for (n, w) in iproduct!(SIZES.iter(), WEIGHTS.iter()) {
                let t = (n * w / 2) as u32;
                let keys = gen_ecies_keys(*n);
                let d0 = setup_party(0, t, *w, &keys);

                create.bench_function(format!("n={}, w={}, t={}", n, w, t).as_str(), |b| {
                    b.iter(|| d0.create_message(&mut thread_rng()))
                });
            }
        }

        {
            let mut verify: BenchmarkGroup<_> = c.benchmark_group("DKG message processing");
            for (n, w) in iproduct!(SIZES.iter(), WEIGHTS.iter()) {
                let t = (n * w / 2) as u32;
                let keys = gen_ecies_keys(*n);
                let d0 = setup_party(0, t, *w, &keys);
                let d1 = setup_party(1, t, *w, &keys);
                let message = d0.create_message(&mut thread_rng());

                println!("Message size: {}", bcs::to_bytes(&message).unwrap().len());

                verify.bench_function(format!("n={}, w={}, t={}", n, w, t).as_str(), |b| {
                    b.iter(|| d1.process_message(&message, &mut thread_rng()).unwrap())
                });
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
