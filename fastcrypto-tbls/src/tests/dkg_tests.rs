// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::dkg::Party;
use crate::ecies;
use crate::nodes::{Node, Nodes, PartyId};
use crate::random_oracle::RandomOracle;
use crate::tbls::ThresholdBls;
use crate::types::ThresholdBls12381MinSig;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::G2Element;
use rand::thread_rng;
use tracing_test::traced_test;

const MSG: [u8; 4] = [1, 2, 3, 4];

type G = G2Element;
type S = ThresholdBls12381MinSig;
type EG = G2Element;

fn gen_ecies_keys(n: usize) -> Vec<(PartyId, ecies::PrivateKey<EG>, ecies::PublicKey<EG>)> {
    (0..n)
        .map(|id| {
            let sk = ecies::PrivateKey::<EG>::new(&mut thread_rng());
            let pk = ecies::PublicKey::<EG>::from_private_key(&sk);
            (id as u16, sk, pk)
        })
        .collect()
}

fn setup_party(
    id: u16,
    keys: &[(PartyId, ecies::PrivateKey<EG>, ecies::PublicKey<EG>)],
) -> Party<G, EG> {
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight: 2,
        })
        .collect();
    Party::<G, EG>::new(
        keys.get(id as usize).unwrap().1.clone(),
        Nodes::new(nodes).unwrap(),
        3,
        RandomOracle::new("dkg"),
        &mut thread_rng(),
    )
    .unwrap()
}

// TODO: add more tests.

#[traced_test]
#[test]
fn test_dkg_e2e_4_parties_threshold_2() {
    let keys = gen_ecies_keys(4);

    let d0 = setup_party(0, &keys);
    let d1 = setup_party(1, &keys);
    // The third party is ignored (emulating a byzantine party).
    let _d2 = setup_party(2, &keys);
    let d3 = setup_party(3, &keys);

    // Only the first message of d0 will pass all tests and be used in the final key.
    let msg0 = d0.create_message(&mut thread_rng());
    println!("msg size: {}", bcs::to_bytes(&msg0).unwrap().len());
    // Modify d1's message to make it invalid (emulating a cheating party). Other parties should
    // detect that and send a complaint.
    let mut msg1 = d1.create_message(&mut thread_rng());
    // Switch the encrypted shares of two receivers.
    msg1.encrypted_shares.swap_for_testing(0, 1);
    // Don't send the message of d3 to d0 (emulating a slow party).
    let _msg3 = d3.create_message(&mut thread_rng());

    assert_eq!(
        d0.merge(&[d0.process_message(msg0.clone(), &mut thread_rng()).unwrap()])
            .err(),
        Some(FastCryptoError::NotEnoughInputs)
    );

    let r1_all = vec![msg0, msg1];

    let proc_msg0 = &r1_all
        .iter()
        .map(|m| d0.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf0, used_msgs0) = d0.merge(proc_msg0).unwrap();

    let proc_msg1 = &r1_all
        .iter()
        .map(|m| d1.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf1, used_msgs1) = d1.merge(proc_msg1).unwrap();

    // Note that d3's first round message is not included but it should still be able to receive
    // shares and post complaints.
    let proc_msg3 = &r1_all
        .iter()
        .map(|m| d3.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf3, used_msgs3) = d3.merge(proc_msg3).unwrap();

    // There should be some complaints on the first messages of d1.
    assert!(
        !conf0.complaints.is_empty()
            || !conf1.complaints.is_empty()
            || !conf3.complaints.is_empty()
    );
    // But also no complaints from one of the parties.
    assert!(
        conf0.complaints.is_empty() || conf1.complaints.is_empty() || conf3.complaints.is_empty()
    );

    let r2_all = vec![conf0, conf1, conf3];
    let ver_msg0 = d1
        .process_confirmations(&used_msgs0, &r2_all, 3, &mut thread_rng())
        .unwrap();
    let ver_msg1 = d1
        .process_confirmations(&used_msgs1, &r2_all, 3, &mut thread_rng())
        .unwrap();
    let ver_msg3 = d3
        .process_confirmations(&used_msgs3, &r2_all, 3, &mut thread_rng())
        .unwrap();

    let o0 = d0.aggregate(&ver_msg0);
    let _o1 = d1.aggregate(&ver_msg1);
    let o3 = d3.aggregate(&ver_msg3);

    // Use the shares from 01 and o4 to sign a message.
    let sig00 = S::partial_sign(&o0.shares.as_ref().unwrap()[0], &MSG);
    let sig30 = S::partial_sign(&o3.shares.as_ref().unwrap()[0], &MSG);
    let sig31 = S::partial_sign(&o3.shares.as_ref().unwrap()[1], &MSG);

    S::partial_verify(&o0.vss_pk, &MSG, &sig00).unwrap();
    S::partial_verify(&o3.vss_pk, &MSG, &sig30).unwrap();
    S::partial_verify(&o3.vss_pk, &MSG, &sig31).unwrap();

    let sigs = vec![sig00, sig30, sig31];
    let sig = S::aggregate(d0.t(), &sigs).unwrap();
    S::verify(o0.vss_pk.c0(), &MSG, &sig).unwrap();
}
