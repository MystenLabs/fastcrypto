// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ecies;
use crate::nodes::{Node, Nodes};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::groups::{FiatShamirChallenge, GroupElement};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::num::NonZeroU32;

fn get_nodes<G>(n: u16) -> Vec<Node<G>>
where
    G: GroupElement + Serialize + DeserializeOwned,
    G::ScalarType: FiatShamirChallenge,
{
    let sk = ecies::PrivateKey::<G>::new(&mut thread_rng());
    let pk = ecies::PublicKey::<G>::from_private_key(&sk);
    (0..n)
        .map(|i| Node {
            id: i,
            pk: pk.clone(),
            weight: 1 + i,
        })
        .collect()
}

#[test]
fn test_new_failures() {
    // missing id
    let mut nodes_vec = get_nodes::<G2Element>(20);
    nodes_vec.remove(7);
    assert!(Nodes::new(nodes_vec).is_err());
    // start id is not 0
    let mut nodes_vec = get_nodes::<G2Element>(20);
    nodes_vec.remove(0);
    assert!(Nodes::new(nodes_vec).is_err());
    // duplicate id
    let mut nodes_vec = get_nodes::<G2Element>(20);
    nodes_vec[19].id = 1;
    assert!(Nodes::new(nodes_vec).is_err());
    // too many nodes
    let nodes_vec = get_nodes::<G2Element>(20000);
    assert!(Nodes::new(nodes_vec).is_err());
    // too little
    let nodes_vec: Vec<Node<G2Element>> = Vec::new();
    assert!(Nodes::new(nodes_vec).is_err());
}

#[test]
fn test_new_order() {
    // order should not matter
    let mut nodes_vec = get_nodes::<G2Element>(100);
    nodes_vec.shuffle(&mut thread_rng());
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    nodes_vec.shuffle(&mut thread_rng());
    let nodes2 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(nodes1, nodes2);
    assert_eq!(nodes1.hash(), nodes2.hash());
}

#[test]
fn test_zero_weight() {
    // The basic case
    let nodes_vec = get_nodes::<G2Element>(10);
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU32::new(1).unwrap())
            .unwrap()
            .id,
        0
    );
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU32::new(2).unwrap())
            .unwrap()
            .id,
        1
    );
    assert_eq!(nodes1.share_ids_of(0), vec![NonZeroU32::new(1).unwrap()]);

    // first node's weight is 0
    let mut nodes_vec = get_nodes::<G2Element>(10);
    nodes_vec[0].weight = 0;
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU32::new(1).unwrap())
            .unwrap()
            .id,
        1
    );
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU32::new(2).unwrap())
            .unwrap()
            .id,
        1
    );
    assert_eq!(nodes1.share_ids_of(0), vec![]);

    // last node's weight is 0
    let mut nodes_vec = get_nodes::<G2Element>(10);
    nodes_vec[9].weight = 0;
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU32::new(nodes1.total_weight()).unwrap())
            .unwrap()
            .id,
        8
    );
    assert_eq!(nodes1.share_ids_of(9), vec![]);

    // third node's weight is 0
    let mut nodes_vec = get_nodes::<G2Element>(10);
    nodes_vec[2].weight = 0;
    let nodes1 = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(
        nodes1
            .share_id_to_node(&NonZeroU32::new(4).unwrap())
            .unwrap()
            .id,
        3
    );
    assert_eq!(nodes1.share_ids_of(2), vec![]);
}

#[test]
fn test_interfaces() {
    let nodes_vec = get_nodes::<G2Element>(100);
    let nodes = Nodes::new(nodes_vec.clone()).unwrap();
    assert_eq!(nodes.total_weight(), 5050);
    assert_eq!(nodes.num_nodes(), 100);
    assert!(nodes
        .share_ids_iter()
        .zip(1u32..=5050)
        .all(|(a, b)| a.get() == b));

    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU32::new(1).unwrap())
            .unwrap(),
        &nodes_vec[0]
    );
    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU32::new(3).unwrap())
            .unwrap(),
        &nodes_vec[1]
    );
    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU32::new(4).unwrap())
            .unwrap(),
        &nodes_vec[2]
    );
    assert_eq!(
        nodes
            .share_id_to_node(&NonZeroU32::new(5050).unwrap())
            .unwrap(),
        &nodes_vec[99]
    );
    assert!(nodes
        .share_id_to_node(&NonZeroU32::new(5051).unwrap())
        .is_err());
    assert!(nodes
        .share_id_to_node(&NonZeroU32::new(15051).unwrap())
        .is_err());

    assert_eq!(nodes.node_id_to_node(1).unwrap(), &nodes_vec[1]);

    assert_eq!(
        nodes.share_ids_of(1),
        vec![NonZeroU32::new(2).unwrap(), NonZeroU32::new(3).unwrap()]
    );
}

#[test]
fn test_reduce() {
    for number_of_nodes in [10, 50, 100, 150, 200, 250, 300, 350, 400] {
        let node_vec = get_nodes::<RistrettoPoint>(number_of_nodes);
        let nodes = Nodes::new(node_vec).unwrap();
        let t = (nodes.total_weight() / 3) as u16;

        // No extra gap, should return the inputs
        let (new_nodes, new_t) = nodes.reduce(t, 1);
        assert_eq!(nodes, new_nodes);
        assert_eq!(t, new_t);

        // 10% gap
        let (new_nodes, _new_t) = nodes.reduce(t, (nodes.total_weight() / 10) as u16);
        // Estimate the real factor d
        let d = nodes.iter().last().unwrap().weight / new_nodes.iter().last().unwrap().weight;
        // The loss per node is on average (d - 1) / 2
        // We use 9 instead of 10 to compensate wrong value of d
        assert!((d - 1) / 2 * number_of_nodes < ((nodes.total_weight() / 9) as u16));
    }
}
