// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::dkg::{Message, Party, ProcessedMessage};
use crate::ecies;
use crate::ecies::{MultiRecipientEncryption, PublicKey};
use crate::nodes::{Node, Nodes, PartyId};
use crate::random_oracle::RandomOracle;
use crate::tbls::ThresholdBls;
use crate::types::ThresholdBls12381MinSig;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::groups::GroupElement;
use rand::thread_rng;

const MSG: [u8; 4] = [1, 2, 3, 4];

type G = G2Element;
type S = ThresholdBls12381MinSig;
type EG = G2Element;

type KeyNodePair<EG> = (PartyId, ecies::PrivateKey<EG>, ecies::PublicKey<EG>);

fn gen_keys_and_nodes(n: usize) -> (Vec<KeyNodePair<EG>>, Nodes<EG>) {
    let keys = (0..n)
        .map(|id| {
            let sk = ecies::PrivateKey::<EG>::new(&mut thread_rng());
            let pk = ecies::PublicKey::<EG>::from_private_key(&sk);
            (id as u16, sk, pk)
        })
        .collect::<Vec<_>>();
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight: 2 + id,
        })
        .collect();
    let nodes = Nodes::new(nodes).unwrap();
    (keys, nodes)
}

// Enable if logs are needed
// #[traced_test]
#[test]
fn test_dkg_e2e_5_parties_min_weight_2_threshold_4() {
    let ro = RandomOracle::new("dkg");
    let t = 3;
    let (keys, nodes) = gen_keys_and_nodes(6);

    // Create the parties
    let d0 = Party::<G, EG>::new(
        keys.get(0_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    assert_eq!(d0.t(), t);
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    // The third party (d2) is ignored (emulating a byzantine party).
    let d3 = Party::<G, EG>::new(
        keys.get(3_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let d4 = Party::<G, EG>::new(
        keys.get(4_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let d5 = Party::<G, EG>::new(
        keys.get(5_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();

    // Only the first messages of d0, d4, d5 will pass all tests. d4's messages will be excluded
    // later because of an invalid complaint
    let msg4 = d4.create_message(&mut thread_rng());
    let msg5 = d5.create_message(&mut thread_rng());
    // d5 will receive invalid shares from d0, but its complaint will not be processed on time.
    let mut msg0 = d0.create_message(&mut thread_rng());
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg0);
    pk_and_msgs[5] = pk_and_msgs[0].clone();
    msg0.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 0"), &mut thread_rng());
    // We will modify d1's message to make it invalid (emulating a cheating party). d0 and d1
    // should detect that and send complaints.
    let mut msg1 = d1.create_message(&mut thread_rng());
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg1);
    pk_and_msgs.swap(0, 1);
    msg1.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 1"), &mut thread_rng());
    // d2 and d3 are ignored here (emulating slow parties).

    let all_messages = vec![msg0.clone(), msg1, msg0.clone(), msg4.clone(), msg5.clone()]; // duplicates should be ignored

    // expect failure - merge() requires t messages (even if some are duplicated)
    let proc0 = d0.process_message(msg0.clone(), &mut thread_rng()).unwrap();
    assert_eq!(
        d0.merge(&[proc0.clone()]).err(),
        Some(FastCryptoError::NotEnoughInputs)
    );
    assert_eq!(
        d0.merge(&[proc0.clone(), proc0.clone()]).err(),
        Some(FastCryptoError::NotEnoughInputs)
    );

    // merge() should succeed and ignore duplicates and include 1 complaint
    let proc_msg0 = &all_messages
        .iter()
        .map(|m| d0.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf0, used_msgs0) = d0.merge(proc_msg0).unwrap();
    assert_eq!(conf0.complaints.len(), 1);
    assert_eq!(used_msgs0.0.len(), 4);
    assert_eq!(proc0.message, msg0);

    let proc_msg1 = &all_messages
        .iter()
        .map(|m| d1.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf1, used_msgs1) = d1.merge(proc_msg1).unwrap();

    // Note that d3's first round message is not included but it should still be able to receive
    // shares and post complaints.
    let proc_msg3 = &all_messages
        .iter()
        .map(|m| d3.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf3, used_msgs3) = d3.merge(proc_msg3).unwrap();

    let proc_msg5 = &all_messages
        .iter()
        .map(|m| d5.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf5, used_msgs5) = d5.merge(proc_msg5).unwrap();
    assert_eq!(conf5.complaints.len(), 1);

    // There should be some complaints on the first messages of d1.
    assert!(
        !conf0.complaints.is_empty()
            || !conf1.complaints.is_empty()
            || !conf3.complaints.is_empty()
    );
    // But also no complaints from one of the parties (since we switched only 2 encryptions)
    assert!(
        conf0.complaints.is_empty() || conf1.complaints.is_empty() || conf3.complaints.is_empty()
    );

    // create a simple invalid complaint from d4.
    let mut conf4 = conf1.clone();
    conf4.sender = 4;

    let all_confirmations = vec![conf0.clone(), conf1.clone(), conf3, conf1.clone(), conf4]; // duplicates should be ignored

    // expect failure - process_confirmations() should receive valid minimal_threshold
    assert_eq!(
        d1.process_confirmations(&used_msgs0, &all_confirmations, 0, &mut thread_rng())
            .err(),
        Some(FastCryptoError::InvalidInput)
    );
    assert_eq!(
        d1.process_confirmations(&used_msgs0, &all_confirmations, 1, &mut thread_rng())
            .err(),
        Some(FastCryptoError::InvalidInput)
    );
    // expect failure - process_confirmations() should receive enough messages (non duplicated).
    assert_eq!(
        d1.process_confirmations(
            &used_msgs0,
            &[conf0.clone(), conf0.clone(), conf0.clone()],
            3,
            &mut thread_rng()
        )
        .err(),
        Some(FastCryptoError::NotEnoughInputs)
    );

    // back to the happy case
    let ver_msg0 = d1
        .process_confirmations(&used_msgs0, &all_confirmations, 3, &mut thread_rng())
        .unwrap();
    let ver_msg1 = d1
        .process_confirmations(&used_msgs1, &all_confirmations, 3, &mut thread_rng())
        .unwrap();
    let ver_msg3 = d3
        .process_confirmations(&used_msgs3, &all_confirmations, 3, &mut thread_rng())
        .unwrap();
    let ver_msg5 = d5
        .process_confirmations(&used_msgs5, &all_confirmations, 3, &mut thread_rng())
        .unwrap();
    assert_eq!(ver_msg0.0.len(), 2); // only msg0, msg5 were valid and didn't send invalid complaints
    assert_eq!(ver_msg1.0.len(), 2);
    assert_eq!(ver_msg3.0.len(), 2);
    assert_eq!(ver_msg5.0.len(), 2);

    let o0 = d0.aggregate(&ver_msg0);
    let _o1 = d1.aggregate(&ver_msg1);
    let o3 = d3.aggregate(&ver_msg3);
    let o5 = d5.aggregate(&ver_msg5);
    assert!(o0.shares.is_some());
    assert!(o3.shares.is_some());
    assert!(o5.shares.is_none()); // recall that it didn't receive valid share from msg0

    // check the resulting vss pk
    let mut poly = msg0.vss_pk.clone();
    poly.add(&msg5.vss_pk);
    assert_eq!(poly, o0.vss_pk);

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

fn decrypt_and_prepare_for_reenc(
    keys: &[KeyNodePair<EG>],
    nodes: &Nodes<EG>,
    msg0: &Message<G, EG>,
) -> Vec<(PublicKey<EG>, Vec<u8>)> {
    nodes
        .iter()
        .map(|n| {
            let key = keys[n.id as usize].1.clone();
            (
                n.pk.clone(),
                key.decrypt(&msg0.encrypted_shares.get_encryption(n.id as usize).unwrap()),
            )
        })
        .collect::<Vec<_>>()
}

#[test]
fn test_party_new_errors() {
    let ro = RandomOracle::new("dkg");
    let (keys, nodes) = gen_keys_and_nodes(4);

    // t is zero
    assert!(Party::<G, EG>::new(
        keys.get(0_usize).unwrap().1.clone(),
        nodes.clone(),
        0,
        ro.clone(),
        &mut thread_rng(),
    )
    .is_err());
    // t is too large
    assert!(Party::<G, EG>::new(
        keys.get(0_usize).unwrap().1.clone(),
        nodes.clone(),
        100,
        ro.clone(),
        &mut thread_rng(),
    )
    .is_err());
    // Invalid pk
    assert!(Party::<G, EG>::new(
        ecies::PrivateKey::<EG>::new(&mut thread_rng()),
        nodes.clone(),
        3,
        ro.clone(),
        &mut thread_rng(),
    )
    .is_err());
}

#[test]
fn test_process_message_failures() {
    let ro = RandomOracle::new("dkg");
    let t = 3;
    let (keys, nodes) = gen_keys_and_nodes(4);

    let d0 = Party::<G, EG>::new(
        keys.get(0_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();

    // invalid sender
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let mut invalid_msg = d1.create_message(&mut thread_rng());
    invalid_msg.sender = 50;
    assert!(d0.process_message(invalid_msg, &mut thread_rng()).is_err());

    // invalid degree
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t - 1,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let invalid_msg = d1.create_message(&mut thread_rng());
    assert!(d0.process_message(invalid_msg, &mut thread_rng()).is_err());

    // invalid c0
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let mut invalid_msg = d1.create_message(&mut thread_rng());
    let mut poly: Vec<G> = invalid_msg.vss_pk.as_vec().clone();
    poly[0] = G::zero();
    invalid_msg.vss_pk = poly.into();
    assert!(d0.process_message(invalid_msg, &mut thread_rng()).is_err());

    // invalid number of encrypted shares
    let mut msg1 = d1.create_message(&mut thread_rng());
    // Switch the encrypted shares of two receivers.
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg1);
    pk_and_msgs.swap(0, 1);
    msg1.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 1"), &mut thread_rng());
    let ProcessedMessage {
        message: _,
        shares,
        complaint,
    } = d0.process_message(msg1, &mut thread_rng()).unwrap();
    if !shares.is_empty() || complaint.is_none() {
        panic!("expected complaint");
    };

    // invalid encryption's proof
    let mut msg1 = d1.create_message(&mut thread_rng());
    // Switch the encrypted shares of two receivers.
    msg1.encrypted_shares.swap_for_testing(0, 1);
    assert!(d0.process_message(msg1, &mut thread_rng()).is_err());

    // invalid share
    // use another d1 with a different vss_sk to create an encryption with "invalid" shares
    let another_d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let msg1_from_another_d1 = another_d1.create_message(&mut thread_rng());
    let mut msg1 = d1.create_message(&mut thread_rng());
    msg1.encrypted_shares = msg1_from_another_d1.encrypted_shares;
    let ProcessedMessage {
        message: _,
        shares,
        complaint,
    } = d0.process_message(msg1, &mut thread_rng()).unwrap();
    if !shares.is_empty() || complaint.is_none() {
        panic!("expected complaint");
    };
}

#[test]
fn test_test_process_confirmations() {
    let ro = RandomOracle::new("dkg");
    let t = 3;
    let (keys, nodes) = gen_keys_and_nodes(6);

    let d0 = Party::<G, EG>::new(
        keys.get(0_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let d2 = Party::<G, EG>::new(
        keys.get(2_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let d3 = Party::<G, EG>::new(
        keys.get(3_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();

    let msg0 = d0.create_message(&mut thread_rng());
    let msg1 = d1.create_message(&mut thread_rng());
    let msg2 = d2.create_message(&mut thread_rng());
    let mut msg3 = d3.create_message(&mut thread_rng());
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg3);
    pk_and_msgs.swap(0, 1);
    msg3.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 3"), &mut thread_rng());

    let all_messages = vec![msg0, msg1, msg2, msg3];

    let proc_msg0 = &all_messages
        .iter()
        .map(|m| d0.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf0, used_msgs0) = d0.merge(proc_msg0).unwrap();

    let proc_msg1 = &all_messages
        .iter()
        .map(|m| d1.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf1, _used_msgs1) = d1.merge(proc_msg1).unwrap();

    let proc_msg2 = &all_messages
        .iter()
        .map(|m| d2.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf2, _used_msgs2) = d2.merge(proc_msg2).unwrap();

    let proc_msg3 = &all_messages
        .iter()
        .map(|m| d3.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf3, _used_msgs3) = d3.merge(proc_msg3).unwrap();

    // sanity check that with the current confirmations, all messages are in
    let ver_msg = d1
        .process_confirmations(
            &used_msgs0,
            &[conf0.clone(), conf1.clone(), conf2.clone(), conf3.clone()],
            3,
            &mut thread_rng(),
        )
        .unwrap();
    // d3 is ignored because it sent an invalid message
    assert_eq!(
        ver_msg
            .0
            .iter()
            .map(|m| m.message.sender)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );

    // invalid senders should be ignored
    let mut conf7 = conf3.clone();
    conf7.sender = 7; // Should be ignored since it's an invalid sender
    let ver_msg = d1
        .process_confirmations(
            &used_msgs0,
            &[conf2.clone(), conf3.clone(), conf7],
            3,
            &mut thread_rng(),
        )
        .unwrap();
    // d3 is not ignored since conf7 is ignored
    assert_eq!(
        ver_msg
            .0
            .iter()
            .map(|m| m.message.sender)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );

    // create an invalid complaint from d4 (invalid recovery package)
    assert!(conf2.complaints.is_empty()); // since only d0, d1 received invalid shares
    let mut conf2 = conf1.clone();
    conf2.sender = 2;
    let ver_msg = d1
        .process_confirmations(
            &used_msgs0,
            &[conf0.clone(), conf1.clone(), conf2.clone(), conf3.clone()],
            3,
            &mut thread_rng(),
        )
        .unwrap();
    // now also d2 is ignored because it sent an invalid complaint
    assert_eq!(
        ver_msg
            .0
            .iter()
            .map(|m| m.message.sender)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
}

#[test]
fn create_message_generates_valid_message() {
    let (keys, nodes) = gen_keys_and_nodes(4);
    let d = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        3,
        RandomOracle::new("dkg"),
        &mut thread_rng(),
    )
    .unwrap();
    let msg = d.create_message(&mut thread_rng());

    assert_eq!(msg.sender, 1);
    assert_eq!(msg.encrypted_shares.len(), 4);
    assert_eq!(msg.vss_pk.degree(), 2);
}
