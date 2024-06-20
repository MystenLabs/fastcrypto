// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::groups::GroupElement;

use crate::dkg::{Output, Party, DKG_MESSAGES_MAX_SIZE};
use crate::dkg_v0::{create_fake_complaint, Confirmation, Message, ProcessedMessage};
use crate::ecies::{PrivateKey, PublicKey};
use crate::ecies_v0::MultiRecipientEncryption;
use crate::mocked_dkg::generate_mocked_output;
use crate::nodes::{Node, Nodes, PartyId};
use crate::polynomial::Poly;
use crate::random_oracle::RandomOracle;
use crate::tbls::ThresholdBls;
use crate::types::ThresholdBls12381MinSig;
use fastcrypto::traits::AllowedRng;
use rand::rngs::StdRng;
use rand::{thread_rng, SeedableRng};

const MSG: [u8; 4] = [1, 2, 3, 4];

type G = G2Element;
type S = ThresholdBls12381MinSig;
type EG = G2Element;

type KeyNodePair<EG> = (PartyId, PrivateKey<EG>, PublicKey<EG>);

fn gen_keys_and_nodes(n: usize) -> (Vec<KeyNodePair<EG>>, Nodes<EG>) {
    gen_keys_and_nodes_rng(n, &mut thread_rng())
}

fn gen_keys_and_nodes_rng<R: AllowedRng>(
    n: usize,
    rng: &mut R,
) -> (Vec<KeyNodePair<EG>>, Nodes<EG>) {
    let keys = (0..n)
        .map(|id| {
            let sk = PrivateKey::<EG>::new(rng);
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
    let msg4 = d4.create_message(&mut thread_rng()).unwrap();
    let msg5 = d5.create_message(&mut thread_rng()).unwrap();
    // zero weight
    assert_eq!(
        d2.create_message(&mut thread_rng()).err(),
        Some(FastCryptoError::IgnoredMessage)
    );
    // d5 will receive invalid shares from d0, but its complaint will not be processed on time.
    let mut msg0 = d0.create_message(&mut thread_rng()).unwrap();
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg0);
    pk_and_msgs[5] = pk_and_msgs[0].clone();
    msg0.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 0"), &mut thread_rng());
    // We will modify d1's message to make it invalid (emulating a cheating party). d0 and d1
    // should detect that and send complaints.
    let mut msg1 = d1.create_message(&mut thread_rng()).unwrap();
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

    let proc_msg2 = &all_messages
        .iter()
        .map(|m| d2.process_message(m.clone(), &mut thread_rng()).unwrap())
        .collect::<Vec<_>>();
    let (conf2, used_msgs2) = d2.merge(proc_msg2).unwrap();
    assert!(conf2.complaints.is_empty());

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
        d1.process_confirmations(
            &used_msgs0,
            &[conf0.clone(), conf0.clone(), conf0.clone()],
            &mut thread_rng(),
        )
        .err(),
        Some(FastCryptoError::NotEnoughInputs)
    );

    // back to the happy case
    let ver_msg0 = d1
        .process_confirmations(&used_msgs0, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg1 = d1
        .process_confirmations(&used_msgs1, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg2 = d2
        .process_confirmations(&used_msgs2, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg3 = d3
        .process_confirmations(&used_msgs3, &all_confirmations, &mut thread_rng())
        .unwrap();
    let ver_msg5 = d5
        .process_confirmations(&used_msgs5, &all_confirmations, &mut thread_rng())
        .unwrap();
    assert_eq!(ver_msg0.len(), 2); // only msg0, msg5 were valid and didn't send invalid complaints
    assert_eq!(ver_msg1.len(), 2);
    assert_eq!(ver_msg2.len(), 2);
    assert_eq!(ver_msg3.len(), 2);
    assert_eq!(ver_msg5.len(), 2);

    let o0 = d0.aggregate(&ver_msg0);
    let _o1 = d1.aggregate(&ver_msg1);
    let o2 = d2.aggregate(&ver_msg2);
    let o3 = d3.aggregate(&ver_msg3);
    let o5 = d5.aggregate(&ver_msg5);
    assert!(o0.shares.is_some());
    assert!(o2.shares.is_none());
    assert!(o3.shares.is_some());
    assert!(o5.shares.is_none()); // recall that it didn't receive valid share from msg0
    assert_eq!(o0.vss_pk, o2.vss_pk);
    assert_eq!(o0.vss_pk, o3.vss_pk);
    assert_eq!(o0.vss_pk, o5.vss_pk);

    // check the resulting vss pk
    let mut poly = msg0.vss_pk.clone();
    poly += &msg5.vss_pk;
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
    let mut invalid_msg = d1.create_message(&mut thread_rng()).unwrap();
    invalid_msg.sender = 50;
    assert!(d0.process_message(invalid_msg, &mut thread_rng()).is_err());

    // zero weight
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut thread_rng(),
    )
    .unwrap();
    let mut fake_msg_from_d2 = d1.create_message(&mut thread_rng()).unwrap();
    fake_msg_from_d2.sender = 2;
    assert!(d0
        .process_message(fake_msg_from_d2, &mut thread_rng())
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
    let invalid_msg = d1.create_message(&mut thread_rng()).unwrap();
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
    let mut invalid_msg = d1.create_message(&mut thread_rng()).unwrap();
    let mut poly: Vec<G> = invalid_msg.vss_pk.as_vec().clone();
    poly[0] = G::zero();
    invalid_msg.vss_pk = poly.into();
    assert!(d0.process_message(invalid_msg, &mut thread_rng()).is_err());

    // invalid total number of encrypted shares
    let mut msg1 = d1.create_message(&mut thread_rng()).unwrap();
    // Switch the encrypted shares of two receivers.
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg1);
    pk_and_msgs.pop();
    msg1.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 1"), &mut thread_rng());
    assert!(d0.process_message(msg1, &mut thread_rng()).is_err());

    // invalid encryption's proof
    let mut msg1 = d1.create_message(&mut thread_rng()).unwrap();
    // Switch the encrypted shares of two receivers.
    msg1.encrypted_shares.swap_for_testing(0, 1);
    assert!(d0.process_message(msg1, &mut thread_rng()).is_err());

    // invalid number of encrypted shares for specific receiver
    let mut msg1 = d1.create_message(&mut thread_rng()).unwrap();
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
    let msg1_from_another_d1 = another_d1.create_message(&mut thread_rng()).unwrap();
    let mut msg1 = d1.create_message(&mut thread_rng()).unwrap();
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

    let msg0 = d0.create_message(&mut thread_rng()).unwrap();
    let msg1 = d1.create_message(&mut thread_rng()).unwrap();
    // zero weight
    assert_eq!(
        d2.create_message(&mut thread_rng()).err(),
        Some(FastCryptoError::IgnoredMessage)
    );
    let mut msg3 = d3.create_message(&mut thread_rng()).unwrap();
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg3);
    pk_and_msgs.swap(0, 1);
    msg3.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 3"), &mut thread_rng());

    let all_messages = vec![msg0, msg1, msg3];

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
        .process_confirmations(
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
        .process_confirmations(
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
    let msg = d.create_message(&mut thread_rng()).unwrap();

    assert_eq!(msg.sender, 1);
    assert_eq!(msg.encrypted_shares.len(), 4);
    assert_eq!(msg.vss_pk.degree(), 2);
}

#[test]
fn test_mock() {
    let (_, nodes) = gen_keys_and_nodes(4);
    let sk = 321;
    let t: u16 = 6;
    let p0: Output<G, EG> = generate_mocked_output(nodes.clone(), 5, sk, 0);
    let p1: Output<G, EG> = generate_mocked_output(nodes.clone(), 5, sk, 1);
    let p2: Output<G, EG> = generate_mocked_output(nodes.clone(), 5, sk, 2);
    let p3: Output<G, EG> = generate_mocked_output(nodes.clone(), 5, sk, 3);

    assert_eq!(p0.vss_pk, p1.vss_pk);
    assert_eq!(p0.vss_pk, p2.vss_pk);
    assert_eq!(p0.vss_pk, p3.vss_pk);

    let shares = p0
        .shares
        .unwrap()
        .iter()
        .chain(p1.shares.unwrap().iter())
        .chain(p2.shares.unwrap().iter())
        .chain(p3.shares.unwrap().iter())
        .cloned()
        .collect::<Vec<_>>();

    let shares = shares.iter().take(t as usize);

    let recovered_sk = Poly::<
        <fastcrypto::groups::bls12381::G2Element as fastcrypto::groups::GroupElement>::ScalarType,
    >::recover_c0(t, shares.into_iter())
    .unwrap();
    assert_eq!(recovered_sk, sk.into());
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

#[test]
fn test_serialized_message_regression() {
    let ro = RandomOracle::new("dkg");
    let t = 3;
    let mut rng = StdRng::from_seed([1; 32]);
    let (keys, nodes) = gen_keys_and_nodes_rng(6, &mut rng);

    let d0 = Party::<G, EG>::new(
        keys.first().unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();
    let d1 = Party::<G, EG>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();
    let _d2 = Party::<G, EG>::new(
        keys.get(2_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();
    let d3 = Party::<G, EG>::new(
        keys.get(3_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();

    let msg0 = d0.create_message(&mut rng).unwrap();
    let msg1 = d1.create_message(&mut rng).unwrap();
    let mut msg3 = d3.create_message(&mut rng).unwrap();
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg3);
    pk_and_msgs.swap(0, 1);
    msg3.encrypted_shares =
        MultiRecipientEncryption::encrypt(&pk_and_msgs, &ro.extend("encs 3"), &mut rng);

    let all_messages = vec![msg0.clone(), msg1, msg3];

    let proc_msg0 = &all_messages
        .iter()
        .map(|m| d0.process_message(m.clone(), &mut rng).unwrap())
        .collect::<Vec<_>>();
    let (conf0, _used_msgs0) = d0.merge(proc_msg0).unwrap();

    // fixed values below were generated using the next code:
    // println!("hex msg0: {:?}", hex::encode(bcs::to_bytes(&msg0).unwrap()));
    // println!(
    //     "hex conf0: {:?}",
    //     hex::encode(bcs::to_bytes(&conf0).unwrap())
    // );

    let expected_msg0 = "000003acee6249d2cf89903c516b3a29410e25da2c7aea52d59e3c12397198397ce35c6a8fd64bda4963d2daac6adf2cf94d22061c663f859dbdc19af4aebb6657e5c8f565ec6f56464a6610d547d59147f06390922fd0b8a7e1aa1a89ac9b2370d90196cfd197b6a5af7bc932c4831541be2dc896e40b47592f4be223bcee68227c4cd19ef1083f2bdc89401f7afd68a46bed17ac2669c5a246737bcc4fde95fb44eee18b2c0175ce4f7bea9300e6f3d66d388c7df4919ffe8f95a919b3436b4938a2b1b5539bebf257db7185189bc0cdc98cbb3fd163a96b1d180bb5fa34d12693d18e07c2d5723d5c65ca3b25e75817fdbb0837d5985ef1c9af57492b74f7fd6f45f30bf6c176fba2e9df61e07114505984a4189b8c6eb585fcce4da3518b509893b6b2ae04078eb54aa79efff5358d4a6aac16bb15c1389eb863e40847703094ad79621e3992031409dab281803419b16b0ae98c8cc1e1fc58a8c78a3d4397b83914109c5e3a49d5e54c730cd81c2626abd0bde41f8c2b3cff521855361e5f4dcd06413499012e5c16571ed52ef0375fd0bd2f02b90869ed0e125af2e70079fca0f1abc7aa6e8a44d6ac1af8ec880c81b2a971b6f256d2c2ad2ae0e5814de06df06d374061db72abcb6193e1d9289a7905f358f64303b341ac4b286028394fcb5c9c940e1954792d785f51b5b0e481da37cef068d3e9a060cc3c12025a06445a3b9b5d3cb70c140521385cd8579521f75c555d35293f77c6c2fe2e54e0354dd325f0b937df08018da10176edd1c91b09f0a59029b0e5012d5f5547cfe242901e13bb7ff0be17007c551d31ad0fc4d0d2ece0cea5de46a5f80ea01a33997ee24b65450a7a349da4946e2df0e3612f8646d6d61ec428dfb8e1d35dafe9a319d53d34beaad61b9b0d62c166e00e0b2625f4016e8bfd60732062b319926ce6cc795625111259d5db3410ee37954b1592517804ac72afd2a751216e5f70d10d95a5456e6bdafc08cf606f876221c101b92ed3fd2d69a4200cbe7474ccab154dcbc52a8c5ba672d335a3d7b2d82fb440d2a7cd391a2bd8e8739935311e1a9705c2ae4e1df88886b66e9664d6aaab96af6b2b8c97764da11996995895a553d0f705fa7995f74074b1261c44499783bafe0c252176a00767d246fc06d44cfaa5c64c07f225ad2b137fc602456d5d0eb2f537675a8d29e78055db77280d56c77dff35411a868392ec04e628766a9977d86bc87c04f8174e5fda4b178f9e12969841fabeb3e01c25669a2c30fbc5027411ed05e101c5ee1aea5f56bb0f0bc78d89a8a96a1f7cbee4d8daaeb31b2cdd1842ca3e79e25622ebedb1cb61d3b43f82ed68e2e1f40f0664cb3e9fd5bbc8ca996d325541f50cd45810e76919d00732a2923736296e6d4cd03b8135a4489a04b710344eee35b0ef033eb425ec4a2a139a215a034c0773ae5fcab31a502df03af43dac9902aeb37bd242dcf45597c1f6590b8903187097afe45143fe1fbee1e658cb71429e5e098e47ead204129aa79e512a9f5a7fcac4f32b91d02712a9421cc01c866a26f76954e4618822d8ae56d9ffe8c52a38e2af3f9bf6704d996c26c18b064d3530d7c7b3cca4530f925fd4a871314266a0839db3dfb9beecc7bd8c46ae9a3a2cb1c0cfcd8e9b5044b6ef40857bc11296ebc50617966249a1e8ebf8bd44e31892806f0dc1d55b9d9e7cb56f54b7dd5e537b5d197fddb3cff267000cf72dc556b3e957de414581fa3de87957e3c526f0e45c19bb95bf1871246d2a4094bf1af6f8726993";
    let expected_conf0 = "00000103009242c26a0ef926f97ff4eb739a6ee2fed88efbacb79392cff978cad2b66a07c0b9e20333aad7a2fc1567a2b27b1b777e0fd52d8525ef903b43c828a5894d8f110479f0422ddd69a893fc4abce54dda795532de21303d072b164d601bac0d111b98db3bd4924d5ca3cf5c031f790ace67834ad4aa592cd93060b092e2db540e01e436182aad5d6ad21e458d0ee217970018a28cb7c0c7174e2d0667fd4093ad214c94169a53bd0a159c8cd62657efce03e215d31daec89a67ef79b34cfab0dca1a141e9fe2fd6d9b627c2bb8df63f4738e2a810b27bf6514162c89c641a7bee56358ff9624f087940b01ae54aaa06999016237bb392d54891e564925324dc4da99cd9f1145d50ba447c4b36eac8ff60caac14c94d5b595c6a830746b12fa34c9c307b6c491a3ae88febd0085159e165faa7f23d663876ad679837e24b33be9a5e";
    assert_eq!(hex::encode(bcs::to_bytes(&msg0).unwrap()), expected_msg0);
    assert_eq!(hex::encode(bcs::to_bytes(&conf0).unwrap()), expected_conf0);
}
