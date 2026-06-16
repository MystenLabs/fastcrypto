// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use fastcrypto::groups::ristretto255;
use fastcrypto_tbls::ecies_v1;
use fastcrypto_tbls::nodes::{Node, Nodes, PartyId};
use fastcrypto_tbls::threshold_schnorr::batch_avss as batch_avss_orig;
use fastcrypto_tbls::threshold_schnorr::batch_avss_avid as batch_avss;
use itertools::iproduct;
use rand::thread_rng;

type EG = ristretto255::RistrettoPoint;

pub fn generate_ecies_keys(
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

#[allow(clippy::too_many_arguments)]
pub fn setup_receiver(
    id: PartyId,
    dealer_id: PartyId,
    f: u16,
    threshold: u16,
    weight: u16, // Per node
    keys: &[(PartyId, ecies_v1::PrivateKey<EG>, ecies_v1::PublicKey<EG>)],
    batch_size_per_weight: u16,
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
        dealer_id,
        batch_avss::Parameters { t: threshold, f },
        b"avss".to_vec(),
        keys.get(id as usize).unwrap().1.clone(),
        batch_size_per_weight,
    )
    .unwrap()
}

pub fn setup_dealer(
    dealer_id: u16,
    f: u16,
    threshold: u16,
    weight: u16, // Per node
    keys: &[(PartyId, ecies_v1::PrivateKey<EG>, ecies_v1::PublicKey<EG>)],
    batch_size_per_weight: u16,
) -> batch_avss::Dealer {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight,
        })
        .collect();
    batch_avss::Dealer::new(
        Nodes::new(nodes).unwrap(),
        dealer_id,
        batch_avss::Parameters { t: threshold, f },
        b"avss".to_vec(),
        batch_size_per_weight,
    )
    .unwrap()
}

mod batch_avss_benches {
    use super::*;
    use fastcrypto::traits::AllowedRng;
    use fastcrypto_tbls::threshold_schnorr::batch_avss_avid::{
        self as batch_avss, AvidDispersal, AvssCommonMessage, Dealer, UnsignedAvssCert,
    };
    use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
    use itertools::Itertools;
    use std::collections::{BTreeMap, BTreeSet};

    /// The single straggler / pending recipient in [pessimistic_with_one_straggler]. The benches
    /// reconstruct this receiver's ciphertext, so it must be the one whose shares are dispersed.
    const STRAGGLER: PartyId = 1;

    /// Run a "one straggler" pessimistic round: every receiver but [STRAGGLER] is treated as
    /// having confirmed in the optimistic phase; [STRAGGLER] is the straggler. Returns `v`, the
    /// per-recipient [AvidDispersal]s, and the [UnsignedAvssCert] (all parties except the
    /// straggler) the receivers need to call [batch_avss::Receiver::prepare_avid_echo_messages].
    fn pessimistic_with_one_straggler(
        dealer: &Dealer,
        rng: &mut impl AllowedRng,
    ) -> (
        AvssCommonMessage,
        BTreeMap<PartyId, AvidDispersal>,
        UnsignedAvssCert,
    ) {
        let (state, _) = dealer.create_avss_messages(rng).unwrap();
        let common = state.common.clone();
        let pending: BTreeSet<PartyId> = std::iter::once(STRAGGLER).collect();
        let messages = dealer.create_avid_dispersals(&state, pending).unwrap();
        let n = messages.len() as u16;
        let cert = UnsignedAvssCert {
            voters: (0..n).filter(|&i| i != STRAGGLER).collect(),
            common_message_hash: common.hash(),
        };
        (common, messages, cert)
    }

    fn all_batch_avss(c: &mut Criterion) {
        batch_avss(c, 1);
        batch_avss(c, 10);
        batch_avss(c, 25);
    }

    fn batch_avss(c: &mut Criterion, batch_size_per_weight: u16) {
        const SIZES: [u16; 1] = [100];
        const TOTAL_WEIGHTS: [u16; 3] = [500, 1000, 1500];

        {
            let mut create: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (batch_size_per_weight = {batch_size_per_weight}) create_avss_messages"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let f = t.saturating_sub(1);
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(0, f, t, w, &keys, batch_size_per_weight);
                create.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| d0.create_avss_messages(&mut thread_rng())),
                );
            }
        }

        {
            let mut verify_common: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (batch_size_per_weight = {batch_size_per_weight}) verify_common_message"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let f = t.saturating_sub(1);
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(0, f, t, w, &keys, batch_size_per_weight);
                let r1 = setup_receiver(1, 0, f, t, w, &keys, batch_size_per_weight);
                let (common, _, _) = pessimistic_with_one_straggler(&d0, &mut thread_rng());
                verify_common.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| r1.verify_common_message(common.clone()).unwrap()),
                );
            }
        }

        {
            let mut echo: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (batch_size_per_weight = {batch_size_per_weight}) echo"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let f = t.saturating_sub(1);
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(0, f, t, w, &keys, batch_size_per_weight);
                let r1 = setup_receiver(1, 0, f, t, w, &keys, batch_size_per_weight);
                let (common, messages, cert) =
                    pessimistic_with_one_straggler(&d0, &mut thread_rng());
                let vcm = r1.verify_common_message(common).unwrap();
                let message = &messages[&1];
                echo.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| {
                        b.iter(|| {
                            r1.prepare_avid_echo_messages_and_vote(message.clone(), &vcm, &cert)
                                .unwrap()
                        })
                    },
                );
            }
        }

        {
            let mut verify_echo: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (batch_size_per_weight = {batch_size_per_weight}) verify_echo"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let f = t.saturating_sub(1);
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(0, f, t, w, &keys, batch_size_per_weight);
                let r0 = setup_receiver(0, 0, f, t, w, &keys, batch_size_per_weight);
                let r1 = setup_receiver(1, 0, f, t, w, &keys, batch_size_per_weight);
                let (common, messages, cert) =
                    pessimistic_with_one_straggler(&d0, &mut thread_rng());
                let vcm0 = r0.verify_common_message(common.clone()).unwrap();
                let vcm1 = r1.verify_common_message(common).unwrap();
                let (builder0, _) = r0
                    .prepare_avid_echo_messages_and_vote(messages[&0].clone(), &vcm0, &cert)
                    .unwrap();
                let echo_for_r1 = builder0.create_echo(1).unwrap();
                let (_, vote1) = r1
                    .prepare_avid_echo_messages_and_vote(messages[&r1.id].clone(), &vcm1, &cert)
                    .unwrap();
                let top_root = vote1.top_root;
                verify_echo.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| {
                        b.iter(|| {
                            r1.verify_avid_echo_message(
                                echo_for_r1.clone(),
                                r0.id,
                                &top_root,
                                &cert,
                            )
                            .unwrap()
                        })
                    },
                );
            }
        }

        {
            let mut process: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (batch_size_per_weight = {batch_size_per_weight}) process_message"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let f = t.saturating_sub(1);
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(0, f, t, w, &keys, batch_size_per_weight);
                let receivers: Vec<batch_avss::Receiver> = (0..*n)
                    .map(|id| setup_receiver(id, 0, f, t, w, &keys, batch_size_per_weight))
                    .collect();
                let (common, messages, cert) =
                    pessimistic_with_one_straggler(&d0, &mut thread_rng());
                let mut top_root = None;
                let echoes: Vec<BTreeMap<PartyId, batch_avss::Echo>> = receivers
                    .iter()
                    .map(|r| {
                        let vcm = r.verify_common_message(common.clone()).unwrap();
                        let (builder, vote) = r
                            .prepare_avid_echo_messages_and_vote(
                                messages[&r.id].clone(),
                                &vcm,
                                &cert,
                            )
                            .unwrap();
                        if r.id == 1 {
                            top_root = Some(vote.top_root);
                        }
                        builder
                            .recipients()
                            .iter()
                            .map(|&rcpt| (rcpt, builder.create_echo(rcpt).unwrap()))
                            .collect()
                    })
                    .collect();
                let top_root = top_root.unwrap();
                let vcm1 = receivers[1].verify_common_message(common).unwrap();
                let echoes_for_party_1: Vec<batch_avss::VerifiedEcho> = echoes
                    .iter()
                    .enumerate()
                    .map(|(sender, em)| {
                        receivers[1]
                            .verify_avid_echo_message(
                                em[&1u16].clone(),
                                sender as PartyId,
                                &top_root,
                                &cert,
                            )
                            .unwrap()
                    })
                    .collect();
                let r1 = &receivers[1];

                process.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| r1.decode_ciphertext(&echoes_for_party_1, &vcm1).unwrap()),
                );
            }
        }

        {
            let mut verify_decrypt: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (batch_size_per_weight = {batch_size_per_weight}) verify_and_decrypt"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let f = t.saturating_sub(1);
                let keys = generate_ecies_keys(*n);
                let d0 = setup_dealer(0, f, t, w, &keys, batch_size_per_weight);
                let receivers: Vec<batch_avss::Receiver> = (0..*n)
                    .map(|id| setup_receiver(id, 0, f, t, w, &keys, batch_size_per_weight))
                    .collect();
                let (common, messages, cert) =
                    pessimistic_with_one_straggler(&d0, &mut thread_rng());
                let mut top_root = None;
                let echoes: Vec<BTreeMap<PartyId, batch_avss::Echo>> = receivers
                    .iter()
                    .map(|r| {
                        let vcm = r.verify_common_message(common.clone()).unwrap();
                        let (builder, vote) = r
                            .prepare_avid_echo_messages_and_vote(
                                messages[&r.id].clone(),
                                &vcm,
                                &cert,
                            )
                            .unwrap();
                        if r.id == 1 {
                            top_root = Some(vote.top_root);
                        }
                        builder
                            .recipients()
                            .iter()
                            .map(|&rcpt| (rcpt, builder.create_echo(rcpt).unwrap()))
                            .collect()
                    })
                    .collect();
                let top_root = top_root.unwrap();
                let vcm1 = receivers[1].verify_common_message(common).unwrap();
                let echoes_for_party_1: Vec<batch_avss::VerifiedEcho> = echoes
                    .iter()
                    .enumerate()
                    .map(|(sender, em)| {
                        receivers[1]
                            .verify_avid_echo_message(
                                em[&1u16].clone(),
                                sender as PartyId,
                                &top_root,
                                &cert,
                            )
                            .unwrap()
                    })
                    .collect();
                let r1 = &receivers[1];
                let ciphertext = match r1.decode_ciphertext(&echoes_for_party_1, &vcm1).unwrap() {
                    batch_avss::DecodeOutcome::Decoded(c) => c,
                    _ => panic!("expected Decoded outcome"),
                };

                verify_decrypt.bench_function(
                    format!("n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| b.iter(|| r1.decrypt_and_verify(&ciphertext, &vcm1).unwrap()),
                );
            }
        }
        {
            let mut complete: BenchmarkGroup<_> = c.benchmark_group(format!(
                "BATCH_AVSS (batch_size_per_weight = {batch_size_per_weight}) presigning"
            ));
            for (n, total_w) in iproduct!(SIZES.iter(), TOTAL_WEIGHTS.iter()) {
                let w = total_w / n;
                let total_w = w * n;
                let t = total_w / 3 - 1;
                let f = t.saturating_sub(1);
                let keys = generate_ecies_keys(*n);
                let quorum = (2 * n / 3 + 1) as usize;
                let dealers: Vec<Dealer> = (0..quorum)
                    .map(|id| setup_dealer(id as u16, f, t, w, &keys, batch_size_per_weight))
                    .collect();
                let outputs = dealers
                    .iter()
                    .enumerate()
                    .map(|(dealer_id, d)| {
                        let (common, messages, cert) =
                            pessimistic_with_one_straggler(d, &mut thread_rng());
                        let receivers: Vec<batch_avss::Receiver> = (0..*n)
                            .map(|id| {
                                setup_receiver(
                                    id,
                                    dealer_id as u16,
                                    f,
                                    t,
                                    w,
                                    &keys,
                                    batch_size_per_weight,
                                )
                            })
                            .collect();
                        let mut top_root = None;
                        let echoes: Vec<BTreeMap<PartyId, batch_avss::Echo>> = receivers
                            .iter()
                            .map(|r| {
                                let vcm = r.verify_common_message(common.clone()).unwrap();
                                let (builder, vote) = r
                                    .prepare_avid_echo_messages_and_vote(
                                        messages[&r.id].clone(),
                                        &vcm,
                                        &cert,
                                    )
                                    .unwrap();
                                if r.id == 1 {
                                    top_root = Some(vote.top_root);
                                }
                                builder
                                    .recipients()
                                    .iter()
                                    .map(|&rcpt| (rcpt, builder.create_echo(rcpt).unwrap()))
                                    .collect()
                            })
                            .collect();
                        let top_root = top_root.unwrap();
                        let vcm1 = receivers[1].verify_common_message(common).unwrap();
                        let echoes_for_party_1: Vec<batch_avss::VerifiedEcho> = echoes
                            .iter()
                            .enumerate()
                            .map(|(sender, em)| {
                                receivers[1]
                                    .verify_avid_echo_message(
                                        em[&1u16].clone(),
                                        sender as PartyId,
                                        &top_root,
                                        &cert,
                                    )
                                    .unwrap()
                            })
                            .collect();
                        let ciphertext = match receivers[1]
                            .decode_ciphertext(&echoes_for_party_1, &vcm1)
                            .unwrap()
                        {
                            batch_avss::DecodeOutcome::Decoded(c) => c,
                            _ => panic!("expected Decoded outcome"),
                        };
                        let output = assert_valid_batch(
                            receivers[1].decrypt_and_verify(&ciphertext, &vcm1).unwrap(),
                        );
                        // presigning consumes the legacy `batch_avss` output types; convert here
                        // while `receivers[1]` is still in scope to derive the share indices.
                        output.into_legacy(&receivers[1].my_indices())
                    })
                    .collect_vec();

                let outputs: Vec<batch_avss_orig::ReceiverOutput> = outputs;

                complete.bench_function(
                    format!("create/n={}, total_weight={}, t={}, w={}", n, total_w, t, w).as_str(),
                    |b| {
                        b.iter(|| {
                            Presignatures::new(
                                outputs.clone(),
                                batch_size_per_weight,
                                t as usize - 1,
                            )
                            .unwrap()
                        })
                    },
                );

                // Ensure that we have enough presignatures.
                let presignatures = (0..1000)
                    .map(|_| {
                        Presignatures::new(outputs.clone(), batch_size_per_weight, t as usize - 1)
                            .unwrap()
                    })
                    .collect_vec();

                let mut presigs = presignatures.into_iter().flatten();

                complete
                    .bench_function(
                        format!("next/n={}, total_weight={}, t={}, w={}", n, total_w, t, w)
                            .as_str(),
                        |b| b.iter(|| presigs.next().unwrap()),
                    )
                    .sample_size(10);
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

fn assert_valid_batch(outcome: batch_avss::DecryptionOutcome) -> batch_avss::ReceiverOutput {
    match outcome {
        batch_avss::DecryptionOutcome::Valid(output) => output,
        _ => panic!("Expected valid outcome"),
    }
}
