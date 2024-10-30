// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::dkg::{Confirmation, Output, Party, DKG_MESSAGES_MAX_SIZE};
use crate::dkg_v0::create_fake_complaint;
use crate::dkg_v1::{Message, ProcessedMessage};
use crate::ecies::{PrivateKey, PublicKey};
use crate::ecies_v1::MultiRecipientEncryption;
use crate::nodes::{Node, Nodes, PartyId};
use crate::polynomial::Poly;
use crate::random_oracle::RandomOracle;
use crate::tbls::ThresholdBls;
use crate::types::ThresholdBls12381MinSig;
use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::groups::secp256k1::ProjectivePoint;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement, HashToGroupElement, MultiScalarMul};
use fastcrypto::traits::AllowedRng;
use itertools::Itertools;
use paste::paste;
use rand::prelude::StdRng;
use rand::rngs::ThreadRng;
use rand::{thread_rng, SeedableRng};
use serde::de::DeserializeOwned;
use serde::Serialize;
use zeroize::Zeroize;

const MSG: [u8; 4] = [1, 2, 3, 4];

type S = ThresholdBls12381MinSig;

type KeyNodePair<EG> = (PartyId, PrivateKey<EG>, PublicKey<EG>);

macro_rules! generate_tests {
    ($test_fn:ident, $( ($type1:ty, $type2:ty, $alias:ident) ),* $(,)? ) => {
        $(
            paste! {
                #[test]
                fn [<test_ $test_fn _ $alias>]() {
                    $test_fn::<$type1, $type2>();
                }
            }
        )*
    }
}

fn gen_keys_and_nodes<EG>(n: usize) -> (Vec<KeyNodePair<EG>>, Nodes<EG>)
where
    EG: GroupElement + Serialize + DeserializeOwned,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
    gen_keys_and_nodes_rng::<EG, ThreadRng>(n, &mut thread_rng())
}

fn gen_keys_and_nodes_rng<EG, R: AllowedRng>(
    n: usize,
    rng: &mut R,
) -> (Vec<KeyNodePair<EG>>, Nodes<EG>)
where
    EG: GroupElement + Serialize + DeserializeOwned,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
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

fn dkg_e2e_5_parties_min_weight_2_threshold_3<G, EG>() -> (u16, Vec<Option<Output<G, EG>>>)
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
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
    let o1 = d1.aggregate_v1(&ver_msg1);
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
    poly += &msg5.vss_pk;
    assert_eq!(poly, o0.vss_pk);

    (
        t,
        vec![Some(o0), Some(o1), Some(o2), Some(o3), None, Some(o5)],
    )
}

fn sign_with_shares(threshold: u16, outputs: Vec<Option<Output<G2Element, G2Element>>>) {
    let o0 = outputs[0].clone().unwrap();
    let o3 = outputs[3].clone().unwrap();

    // Use the shares to sign the message.
    let sig00 = S::partial_sign(&o0.shares.as_ref().unwrap()[0], &MSG);
    let sig30 = S::partial_sign(&o3.shares.as_ref().unwrap()[0], &MSG);
    let sig31 = S::partial_sign(&o3.shares.as_ref().unwrap()[1], &MSG);

    S::partial_verify(&o0.vss_pk, &MSG, &sig00).unwrap();
    S::partial_verify(&o3.vss_pk, &MSG, &sig30).unwrap();
    S::partial_verify(&o3.vss_pk, &MSG, &sig31).unwrap();

    let sigs = vec![sig00, sig30, sig31];
    let sig = S::aggregate(threshold, sigs.iter()).unwrap();
    S::verify(o0.vss_pk.c0(), &MSG, &sig).unwrap();
}

fn decrypt_and_prepare_for_reenc<G, EG>(
    keys: &[KeyNodePair<EG>],
    nodes: &Nodes<EG>,
    msg0: &Message<G, EG>,
    ro: &RandomOracle,
) -> Vec<(PublicKey<EG>, Vec<u8>)>
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
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

// Enable if logs are needed
// #[traced_test]
#[test]
fn test_dkg_e2e_5_parties_min_weight_2_threshold_3() {
    dkg_e2e_5_parties_min_weight_2_threshold_3::<ProjectivePoint, ProjectivePoint>();
    let (threshold, outputs) = dkg_e2e_5_parties_min_weight_2_threshold_3::<G2Element, G2Element>();
    sign_with_shares(threshold, outputs);
}

fn party_new_errors<G, EG>()
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
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

generate_tests!(
    party_new_errors,
    (ProjectivePoint, ProjectivePoint, secp256k1),
    (G2Element, G2Element, bls12381),
);

fn process_message_failures<G, EG>()
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
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
        .modify_c_hat_for_testing(*msg1.encrypted_shares.ephemeral_key());
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

generate_tests!(
    process_message_failures,
    (ProjectivePoint, ProjectivePoint, secp256k1),
    (G2Element, G2Element, bls12381),
);

fn process_confirmations<G, EG>()
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
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

generate_tests!(
    process_confirmations,
    (ProjectivePoint, ProjectivePoint, secp256k1),
    (G2Element, G2Element, bls12381),
);

fn create_message_generates_valid_message<G, EG>()
where
    G: GroupElement + MultiScalarMul + Serialize + DeserializeOwned,
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
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

generate_tests!(
    create_message_generates_valid_message,
    (ProjectivePoint, ProjectivePoint, secp256k1),
    (G2Element, G2Element, bls12381),
);

fn size_limits<G, EG>()
where
    G: GroupElement,
    EG: GroupElement + Serialize + DeserializeOwned + HashToGroupElement,
    EG::ScalarType: FiatShamirChallenge + Zeroize,
{
    // Confirm that messages sizes are within the limit for the extreme expected parameters.
    let n = 3333;
    let t = n / 3;
    let k = 400;

    // an approximation of the weights
    let w = n / k;
    let shares = (0..w).map(G::ScalarType::from).collect_vec();

    let p = Poly::<EG::ScalarType>::rand(t as u16, &mut thread_rng());
    let ro = RandomOracle::new("test");
    let keys_and_msg = (0..k)
        .map(|_| {
            let sk = PrivateKey::<EG>::new(&mut thread_rng());
            let pk = PublicKey::<EG>::from_private_key(&sk);
            (sk, pk, bcs::to_bytes(&shares).unwrap())
        })
        .collect::<Vec<_>>();
    let encrypted_shares = MultiRecipientEncryption::encrypt(
        &keys_and_msg
            .iter()
            .map(|(_, pk, msg)| (pk.clone(), msg.clone()))
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

generate_tests!(
    size_limits,
    (ProjectivePoint, ProjectivePoint, secp256k1),
    (G2Element, G2Element, bls12381),
);

#[test]
fn test_serialized_message_regression() {
    let ro = RandomOracle::new("dkg");
    let t = 3;
    let mut rng = StdRng::from_seed([1; 32]);
    let (keys, nodes) = gen_keys_and_nodes_rng(6, &mut rng);

    let d0 = Party::<G2Element, G2Element>::new(
        keys.first().unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();
    let d1 = Party::<G2Element, G2Element>::new(
        keys.get(1_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();
    let _d2 = Party::<G2Element, G2Element>::new(
        keys.get(2_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();
    let d3 = Party::<G2Element, G2Element>::new(
        keys.get(3_usize).unwrap().1.clone(),
        nodes.clone(),
        t,
        ro.clone(),
        &mut rng,
    )
    .unwrap();

    let msg0 = d0.create_message_v1(&mut rng).unwrap();
    let msg1 = d1.create_message_v1(&mut rng).unwrap();
    let mut msg3 = d3.create_message_v1(&mut rng).unwrap();
    let mut pk_and_msgs = decrypt_and_prepare_for_reenc(&keys, &nodes, &msg3, &ro);
    pk_and_msgs.swap(0, 1);
    msg3.encrypted_shares = crate::ecies_v1::MultiRecipientEncryption::encrypt(
        &pk_and_msgs,
        &ro.extend("encs 3"),
        &mut rng,
    );

    let all_messages = vec![msg0.clone(), msg1, msg3];

    let proc_msg0 = &all_messages
        .iter()
        .map(|m| d0.process_message_v1(m.clone(), &mut rng).unwrap())
        .collect::<Vec<_>>();
    let (conf0, _used_msgs0) = d0.merge_v1(proc_msg0).unwrap();

    // fixed values below were generated using the next code:
    // println!("hex msg0: {:?}", hex::encode(bcs::to_bytes(&msg0).unwrap()));
    // println!(
    //     "hex conf0: {:?}",
    //     hex::encode(bcs::to_bytes(&conf0).unwrap())
    // );

    let expected_msg0 = "000003acee6249d2cf89903c516b3a29410e25da2c7aea52d59e3c12397198397ce35c6a8fd64bda4963d2daac6adf2cf94d22061c663f859dbdc19af4aebb6657e5c8f565ec6f56464a6610d547d59147f06390922fd0b8a7e1aa1a89ac9b2370d90196cfd197b6a5af7bc932c4831541be2dc896e40b47592f4be223bcee68227c4cd19ef1083f2bdc89401f7afd68a46bed17ac2669c5a246737bcc4fde95fb44eee18b2c0175ce4f7bea9300e6f3d66d388c7df4919ffe8f95a919b3436b4938a2b1b5539bebf257db7185189bc0cdc98cbb3fd163a96b1d180bb5fa34d12693d18e07c2d5723d5c65ca3b25e75817fdbb0837d5985ef1c9af57492b74f7fd6f45f30bf6c176fba2e9df61e07114505984a4189b8c6eb585fcce4da3518b509893b6b2ae04078eb54aa79efff5358d4a6aac16bb15c1389eb863e40847703094ad79621e3992031409dab281803419b16b0ae98c8cc1e1fc58a8c78a3d4397b83914109c5e3a49d5e54c730cd81c2626abd0bde41f8c2b3cff521855361e5f4dcd8831787968259a34d70c6179eab5eb85abdc054ecc45c3fb8a5367de2f4c701d19466fcfbeab2180741e04969fa3600714728ae5c0cc03b027b85df69b2412f1dc61e165250de6e1bce717af1f2b55e070e4bc0317652d23f7ced9ac03b8260806419b3811e60da868a4a9937dff11b4936babda4114ecce78aa903f36fc937fde0ed6776175f38d8cc1d4f3e8284f6d723f6b02423a946c5021a520067a9e8b3698ca61e6c7d761435b0b3cbfd1d1edb19239aff4f39c4c5b5a89cae37073683d731d1e19b2252d569b1f09768aa406bd3fb05bba04f0d0062d607938a3b4be2ce35e9da880f69666fe99e5ed23afe7730f123578b417a8823f025bbfa89afbf9d78667c60195a1014848562feae33283b542f4515e3a8860afd7534278dd6d2a7db30d56754d98f13d9fd6c447060fc62cdf610a8ef2934a2baf2310c4a5918160c7e4499bbd56f081319cc62591ea5e12ee13b74b3bf23211523b0539d5b1f674203bdf34e5cba5fd18961edddf17a73c31f9b61eb7f781ccddf24f83a692414f0f587d2403e0a06efc86f8e27061bdcb4b959ab71524e1bfe3b85607a314734b992370ecad71b320c101525249fd661eb67b243b232d3caebc20cddf24a00fdf3ed45cadfe438b0846dc26765d10427d8334569a6f9226c3c80ad6f773401ab2bc1e4ff0883eed0a071d33255a0c30c6a0e69a3abc4a8719d6c18956c31cbcf8694b10969a36a308137d9dc2b7dede7272fe901f0445d476741050fe9ecb190204b2f427c8b19914e2c32a03554ea689c24cc839fb91ada2af6bfc0b740537005bdcd47b0708d79b3f4552b55823c170b35a99e75a2804a6d78f507cdae72d515e523501cd43ee13222e7ce1014c76eaae067b4f5c3147b3604e5c9b2ce83e7cb89960433f909631574986481426ccfd007a75a00a3cd0fcb0ca447cd4ec9799a244dfd4c21836776fd480183d4ec43d31af47d8761764855209d5c1bc1c8e2b26aa297370214a34d553e8abbb4bacde684237756a9b0118a34e190cc1dff7e447150187c4b0aa85cb1e3b2602520b29e5abef4dfaa238ad548059aeb0802c89943409c74c45b790c8edb88ef4ff0fff58866e1432ab2fdd8c18708d1af798fba0698b3a983a7ea381ecfa6ccc48cfb3b38f613117f75f1701ec92b3dfaa9ecad82301b84adb61be835c90011ef0b3cca4530f925fd4a871314266a0839db3dfb9beecc7bd8c46ae9a3a2cb1c0cfcd8e9b5044b6ef40857bc11296ebc50617966249a1e8ebf8bd44e31892806f0dc1d55b9d9e7cb56f54b7dd5e537b5d197fddb3cff267000cf72dc556b3e957de96f856c6c7cd926c00698fae41ed7c12541d7656cf15352fe249616205ed2fdb0fd12ba1ef04e13ef338f4bd379b4c5f0d2f2b6b7848f768b040a54fc1c846edd9456164e282e50bee9d3fc40907be6840139c476bd7cdb2441cd15ae7ac3d0e150d1ca5e8116373fe9d5c3e4d5596643d7aa497c2550be3007f16779719593e";
    let expected_conf0 = "00000103009242c26a0ef926f97ff4eb739a6ee2fed88efbacb79392cff978cad2b66a07c0b9e20333aad7a2fc1567a2b27b1b777e0fd52d8525ef903b43c828a5894d8f110479f0422ddd69a893fc4abce54dda795532de21303d072b164d601bac0d111b98db3bd4924d5ca3cf5c031f790ace67834ad4aa592cd93060b092e2db540e01e436182aad5d6ad21e458d0ee217970018a28cb7c0c7174e2d0667fd4093ad214c94169a53bd0a159c8cd62657efce03e215d31daec89a67ef79b34cfab0dca1a141e9fe2fd6d9b627c2bb8df63f4738e2a810b27bf6514162c89c641a7bee56358ff9624f087940b01ae54aaa06999016237bb392d54891e564925324dc4da99cd9f1145d50ba447c4b36eac8ff60caac14c94d5b595c6a830746b12fa34c9c026d4688a438c233e2bd93c124405f03ce1ce7de4b18a1caa5a6d6c5b386309b";
    assert_eq!(hex::encode(bcs::to_bytes(&msg0).unwrap()), expected_msg0);
    assert_eq!(hex::encode(bcs::to_bytes(&conf0).unwrap()), expected_conf0);
}
