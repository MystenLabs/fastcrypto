// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::dkg_v0::{create_fake_complaint, Confirmation, Party, DKG_MESSAGES_MAX_SIZE};
use crate::dkg_v1::{Message, ProcessedMessage};
use crate::ecies_v0::{PrivateKey, PublicKey};
use crate::ecies_v1::MultiRecipientEncryption;
use crate::nodes::{Node, Nodes, PartyId};
use crate::polynomial::Poly;
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

type KeyNodePair<EG> = (PartyId, PrivateKey<EG>, PublicKey<EG>);

fn gen_keys_and_nodes(n: usize) -> (Vec<KeyNodePair<EG>>, Nodes<EG>) {
    let keys = (0..n)
        .map(|id| {
            let sk = PrivateKey::<EG>::new(&mut thread_rng());
            let pk = PublicKey::<EG>::from_private_key(&sk);
            (id as u16, sk, pk)
        })
        .collect::<Vec<_>>();
    let nodes = keys
        .iter()
        .map(|(id, _sk, pk)| Node::<EG> {
            id: *id,
            pk: pk.clone(),
            weight: if *id == 2 { 0 } else { 2 + id },
        })
        .collect();
    let nodes = Nodes::new(nodes).unwrap();
    (keys, nodes)
}

// Enable if logs are needed
// #[traced_test]
#[test]
fn test_dkg_e2e_5_parties_min_weight_2_threshold_3() {
    let ro = RandomOracle::new("dkg");
    let t = 3;
    let (keys, nodes) = gen_keys_and_nodes(6);

    // Create the parties
    let d0 = Party::<G, EG>::new(
        keys.first().unwrap().1.clone(),
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
    // Party with weight 0
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
    let msg4 = d4.create_message_v1(&mut thread_rng()).unwrap();
    let msg5 = d5.create_message_v1(&mut thread_rng()).unwrap();
    // zero weight
    assert_eq!(
        d2.create_message_v1(&mut thread_rng()).err(),
        Some(FastCryptoError::IgnoredMessage)
    );
    // d5 will receive invalid shares from d0, but its complaint will not be processed on time.
    let mut msg0 = d0.create_message_v1(&mut thread_rng()).unwrap();
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg0, &ro);
    pk_and_msgs[5] = pk_and_msgs[0].clone();
    msg0.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 0"), &mut thread_rng());

    // We will modify d1's message to make it invalid (emulating a cheating party). d0 and d1
    // should detect that and send complaints.
    let mut msg1 = d1.create_message_v1(&mut thread_rng()).unwrap();
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg1, &ro);
    pk_and_msgs.swap(0, 1);
    msg1.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 1"), &mut thread_rng());
    // d2 and d3 are ignored here (emulating slow parties).

    let all_messages = vec![msg0.clone(), msg1, msg0.clone(), msg4.clone(), msg5.clone()]; // duplicates should be ignored

    // expect failure - merge() requires t messages (even if some are duplicated)
    let proc0 = d0
        .process_message_v1(msg0.clone(), &mut thread_rng())
        .unwrap();
    assert_eq!(
        d0.merge_v1(&[proc0.clone()]).err(),
        Some(FastCryptoError::NotEnoughInputs)
    );
    assert_eq!(
        d0.merge_v1(&[proc0.clone(), proc0.clone()]).err(),
        Some(FastCryptoError::NotEnoughInputs)
    );

    // merge() should succeed and ignore duplicates and include 1 complaint
    let proc_msg0 = &all_messages
        .iter()
        .map(|m| d0.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf0, used_msgs0) = d0.merge_v1(proc_msg0).unwrap();
    assert_eq!(conf0.complaints.len(), 1);
    assert_eq!(used_msgs0.0.len(), 4);
    assert_eq!(proc0.message, msg0);

    let proc_msg1 = &all_messages
        .iter()
        .map(|m| d1.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf1, used_msgs1) = d1.merge_v1(proc_msg1).unwrap();

    let proc_msg2 = &all_messages
        .iter()
        .map(|m| d2.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf2, used_msgs2) = d2.merge_v1(proc_msg2).unwrap();
    assert!(conf2.complaints.is_empty());

    // Note that d3's first round message is not included but it should still be able to receive
    // shares and post complaints.
    let proc_msg3 = &all_messages
        .iter()
        .map(|m| d3.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf3, used_msgs3) = d3.merge_v1(proc_msg3).unwrap();

    let proc_msg5 = &all_messages
        .iter()
        .map(|m| d5.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf5, used_msgs5) = d5.merge_v1(proc_msg5).unwrap();
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

    let all_confirmations = vec![
        conf0.clone(),
        conf2.clone(),
        conf1.clone(),
        conf3,
        conf1.clone(),
        conf4,
    ]; // duplicates and zero weights should be ignored

    // expect failure - process_confirmations() should receive enough messages (non duplicated).
    assert_eq!(
        d1.process_confirmations_v1(
            &used_msgs0,
            &[conf0.clone(), conf0.clone(), conf0.clone()],
            &mut thread_rng(),
        )
        .err(),
        Some(FastCryptoError::NotEnoughInputs)
    );

    // back to the happy case
    let ver_msg0 = d1
        .process_confirmations_v1(&used_msgs0, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg1 = d1
        .process_confirmations_v1(&used_msgs1, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg2 = d2
        .process_confirmations_v1(&used_msgs2, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg3 = d3
        .process_confirmations_v1(&used_msgs3, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg5 = d5
        .process_confirmations_v1(&used_msgs5, &all_confirmations, &mut thread_rng())
        .unwrap();
    assert_eq!(ver_msg0.len(), 2); // only msg0, msg5 were valid and didn't send invalid complaints
    assert_eq!(ver_msg1.len(), 2);
    assert_eq!(ver_msg2.len(), 2);
    assert_eq!(ver_msg3.len(), 2);
    assert_eq!(ver_msg5.len(), 2);

    let o0 = d0.aggregate_v1(&ver_msg0);
    let _o1 = d1.aggregate_v1(&ver_msg1);
    let o2 = d2.aggregate_v1(&ver_msg2);
    let o3 = d3.aggregate_v1(&ver_msg3);
    let o5 = d5.aggregate_v1(&ver_msg5);
    assert!(o0.shares.is_some());
    assert!(o2.shares.is_none());
    assert!(o3.shares.is_some());
    assert!(o5.shares.is_none()); // recall that it didn't receive valid share from msg0
    assert_eq!(o0.vss_pk, o2.vss_pk);
    assert_eq!(o0.vss_pk, o3.vss_pk);
    assert_eq!(o0.vss_pk, o5.vss_pk);

    // check the resulting vss pk
    let mut poly = msg0.vss_pk.clone();
    poly.add(&msg5.vss_pk);
    assert_eq!(poly, o0.vss_pk);

    // Use the shares to sign the message.
    let sig00 = S::partial_sign(&o0.shares.as_ref().unwrap()[0], &MSG);
    let sig30 = S::partial_sign(&o3.shares.as_ref().unwrap()[0], &MSG);
    let sig31 = S::partial_sign(&o3.shares.as_ref().unwrap()[1], &MSG);

    S::partial_verify(&o0.vss_pk, &MSG, &sig00).unwrap();
    S::partial_verify(&o3.vss_pk, &MSG, &sig30).unwrap();
    S::partial_verify(&o3.vss_pk, &MSG, &sig31).unwrap();

    let sigs = vec![sig00, sig30, sig31];
    let sig = S::aggregate(d0.t(), sigs.iter()).unwrap();
    S::verify(o0.vss_pk.c0(), &MSG, &sig).unwrap();
}

fn decrypt_and_prepare_for_reenc(
    keys: &[KeyNodePair<EG>],
    nodes: &Nodes<EG>,
    msg0: &Message<G, EG>,
    ro: &RandomOracle,
) -> Vec<(PublicKey<EG>, Vec<u8>)> {
    nodes
        .iter()
        .map(|n| {
            let key = keys[n.id as usize].1.clone();
            (
                n.pk.clone(),
                msg0.encrypted_shares.decrypt(
                    &key,
                    &ro.extend(&format!("encs {}", msg0.sender)),
                    n.id as usize,
                ),
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
        keys.first().unwrap().1.clone(),
        nodes.clone(),
        0,
        ro.clone(),
        &mut thread_rng(),
    )
    .is_err());
    // t is too large
    assert!(Party::<G, EG>::new(
        keys.first().unwrap().1.clone(),
        nodes.clone(),
        6,
        ro.clone(),
        &mut thread_rng(),
    )
    .is_err());
    // Invalid pk
    assert!(Party::<G, EG>::new(
        PrivateKey::<EG>::new(&mut thread_rng()),
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
        keys.first().unwrap().1.clone(),
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
    let mut invalid_msg = d1.create_message_v1(&mut thread_rng()).unwrap();
    invalid_msg.sender = 50;
    assert!(d0
        .process_message_v1(invalid_msg, &mut thread_rng())
        .is_err());

    // zero weight
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let mut fake_msg_from_d2 = d1.create_message_v1(&mut thread_rng()).unwrap();
    fake_msg_from_d2.sender = 2;
    assert!(d0
        .process_message_v1(fake_msg_from_d2, &mut thread_rng())
        .is_err());

    // invalid degree
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t - 1,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let invalid_msg = d1.create_message_v1(&mut thread_rng()).unwrap();
    assert!(d0
        .process_message_v1(invalid_msg, &mut thread_rng())
        .is_err());

    // invalid c0
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let mut invalid_msg = d1.create_message_v1(&mut thread_rng()).unwrap();
    let mut poly: Vec<G> = invalid_msg.vss_pk.as_vec().clone();
    poly[0] = G::zero();
    invalid_msg.vss_pk = poly.into();
    assert!(d0
        .process_message_v1(invalid_msg, &mut thread_rng())
        .is_err());

    // invalid total number of encrypted shares
    let mut msg1 = d1.create_message_v1(&mut thread_rng()).unwrap();
    // Switch the encrypted shares of two receivers.
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg1, &ro);
    pk_and_msgs.pop();
    msg1.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 1"), &mut thread_rng());
    assert!(d0.process_message_v1(msg1, &mut thread_rng()).is_err());

    // invalid encryption's proof
    let mut msg1 = d1.create_message_v1(&mut thread_rng()).unwrap();
    // Switch the encrypted shares of two receivers.
    msg1.encrypted_shares
        .modify_c_hat_for_testing(msg1.encrypted_shares.ephemeral_key().clone());
    assert!(d0.process_message_v1(msg1, &mut thread_rng()).is_err());

    // invalid number of encrypted shares for specific receiver
    let mut msg1 = d1.create_message_v1(&mut thread_rng()).unwrap();
    // Switch the encrypted shares of two receivers.
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg1, &ro);
    pk_and_msgs.swap(0, 1);
    msg1.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 1"), &mut thread_rng());
    let ProcessedMessage {
        message: _,
        shares,
        complaint,
    } = d0.process_message_v1(msg1, &mut thread_rng()).unwrap();
    if !shares.is_empty() || complaint.is_none() {
        panic!("expected complaint");
    };

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
    let msg1_from_another_d1 = another_d1.create_message_v1(&mut thread_rng()).unwrap();
    let mut msg1 = d1.create_message_v1(&mut thread_rng()).unwrap();
    msg1.encrypted_shares = msg1_from_another_d1.encrypted_shares;
    let ProcessedMessage {
        message: _,
        shares,
        complaint,
    } = d0.process_message_v1(msg1, &mut thread_rng()).unwrap();
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
        keys.first().unwrap().1.clone(),
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

    let msg0 = d0.create_message_v1(&mut thread_rng()).unwrap();
    let msg1 = d1.create_message_v1(&mut thread_rng()).unwrap();
    // zero weight
    assert_eq!(
        d2.create_message_v1(&mut thread_rng()).err(),
        Some(FastCryptoError::IgnoredMessage)
    );
    let mut msg3 = d3.create_message_v1(&mut thread_rng()).unwrap();
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg3, &ro);
    pk_and_msgs.swap(0, 1);
    msg3.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 3"), &mut thread_rng());

    let all_messages = vec![msg0, msg1, msg3];

    let proc_msg0 = &all_messages
        .iter()
        .map(|m| d0.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf0, used_msgs0) = d0.merge_v1(proc_msg0).unwrap();

    let proc_msg1 = &all_messages
        .iter()
        .map(|m| d1.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf1, _used_msgs1) = d1.merge_v1(proc_msg1).unwrap();

    let proc_msg2 = &all_messages
        .iter()
        .map(|m| d2.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf2, _used_msgs2) = d2.merge_v1(proc_msg2).unwrap();

    let proc_msg3 = &all_messages
        .iter()
        .map(|m| d3.process_message_v1(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf3, _used_msgs3) = d3.merge_v1(proc_msg3).unwrap();

    // sanity check that with the current confirmations, all messages are in
    let ver_msg = d1
        .process_confirmations_v1(
            &used_msgs0,
            &[conf0.clone(), conf1.clone(), conf2.clone(), conf3.clone()],
            &mut thread_rng(),
        )
        .unwrap();
    // d3 is ignored because it sent an invalid message, d2 is ignored because it's weight is 0
    assert_eq!(
        ver_msg
            .data()
            .iter()
            .map(|m| m.message.sender)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );

    // invalid senders should be ignored
    let mut conf7 = conf3.clone();
    conf7.sender = 7; // Should be ignored since it's an invalid sender
    let ver_msg = d1
        .process_confirmations_v1(
            &used_msgs0,
            &[conf2.clone(), conf3.clone(), conf7],
            &mut thread_rng(),
        )
        .unwrap();

    // d3 is not ignored since conf7 is ignored, d2 is ignored because it's weight is 0
    assert_eq!(
        ver_msg
            .data()
            .iter()
            .map(|m| m.message.sender)
            .collect::<Vec<_>>(),
        vec![0, 1, 3]
    );

    // create an invalid complaint from d4 (invalid recovery package)
    assert!(conf2.complaints.is_empty()); // since only d0, d1 received invalid shares
    let mut conf2 = conf1.clone();
    conf2.sender = 2;
    let ver_msg = d1
        .process_confirmations_v1(
            &used_msgs0,
            &[conf0.clone(), conf1.clone(), conf2.clone(), conf3.clone()],
            &mut thread_rng(),
        )
        .unwrap();
    // now also d2 is ignored because it sent an invalid complaint
    assert_eq!(
        ver_msg
            .data()
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
    let msg = d.create_message_v1(&mut thread_rng()).unwrap();

    assert_eq!(msg.sender, 1);
    assert_eq!(msg.encrypted_shares.len(), 4);
    assert_eq!(msg.vss_pk.degree(), 2);
}

#[test]
fn test_size_limits() {
    // Confirm that messages sizes are within the limit for the extreme expected parameters.
    let n = 3333;
    let t = n / 3;
    let k = 400;

    let p = Poly::<<G2Element as GroupElement>::ScalarType>::rand(t as u16, &mut thread_rng());
    let ro = RandomOracle::new("test");
    let keys_and_msg = (0..k)
        .map(|i| {
            let sk = PrivateKey::<EG>::new(&mut thread_rng());
            let pk = PublicKey::<EG>::from_private_key(&sk);
            (sk, pk, format!("test {}", i))
        })
        .collect::<Vec<_>>();
    let encrypted_shares = MultiRecipientEncryption::encrypt(
        &keys_and_msg
            .iter()
            .map(|(_, pk, msg)| (pk.clone(), msg.as_bytes().to_vec()))
            .collect::<Vec<_>>(),
        &ro,
        &mut thread_rng(),
    );
    let msg = Message {
        sender: 0,
        vss_pk: p.commit::<EG>(),
        encrypted_shares,
    };
    assert!(bcs::to_bytes(&msg).unwrap().len() <= DKG_MESSAGES_MAX_SIZE);

    let complaints = (0..k)
        .map(|_| create_fake_complaint::<EG>())
        .collect::<Vec<_>>();
    let conf = Confirmation {
        sender: 0,
        complaints,
    };
    assert!(bcs::to_bytes(&conf).unwrap().len() <= DKG_MESSAGES_MAX_SIZE);
}
